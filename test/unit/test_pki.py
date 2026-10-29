import pytest

from core.rsa_keygen import generate_keypair
from pki.ca import CertificateAuthority
from pki.certificate import DAY, Certificate, now
from pki.chain_verify import verify_chain
from pki.revocation import CRL
from pki.timestamp import TimestampAuthority, TimestampToken, verify_token

BITS = 768


@pytest.fixture(scope="module")
def world():
    start = now() - 30 * DAY
    root = CertificateAuthority.create("Root CA", BITS)
    root.self_signed_root(not_before=start)
    inter = root.create_intermediate("Intermediate CA", BITS, not_before=start)
    alice_keys = generate_keypair(BITS)
    alice = inter.issue("Alice", alice_keys[0], not_before=start)
    return root, inter, alice, alice_keys


def test_valid_chain(world):
    root, inter, alice, _ = world
    res = verify_chain(alice, [inter.certificate], [root.certificate])
    assert res.valid and "Alice → Intermediate CA → Root CA" in res.reason


def test_certificate_dict_roundtrip(world):
    _, _, alice, _ = world
    assert Certificate.from_dict(alice.to_dict()) == alice
    assert "Alice" in alice.describe()


def test_missing_intermediate(world):
    root, _, alice, _ = world
    assert not verify_chain(alice, [], [root.certificate]).valid


def test_expired(world):
    root, inter, alice, _ = world
    res = verify_chain(alice, [inter.certificate], [root.certificate], at_time=now() + 400 * DAY)
    assert not res.valid and "hết hạn" in res.reason


def test_revoked_with_time(world):
    root, inter, alice, _ = world
    t_r = now() - 10
    inter.revoke(alice.serial, at=t_r)
    crl = inter.publish_crl()
    try:
        assert not verify_chain(alice, [inter.certificate], [root.certificate], crl).valid
        assert verify_chain(alice, [inter.certificate], [root.certificate], crl, at_time=t_r - 1).valid
        tampered = CRL.from_dict({**crl.to_dict(), "revoked": {}})
        res = verify_chain(alice, [inter.certificate], [root.certificate], tampered)
        assert not res.valid and "CRL" in res.reason
    finally:
        inter.revoked.clear()


def test_tampered_ca_signature(world):
    root, inter, alice, _ = world
    d = alice.to_dict()
    d["subject"] = "Mallory"
    res = verify_chain(Certificate.from_dict(d), [inter.certificate], [root.certificate])
    assert not res.valid and "không hợp lệ" in res.reason
    sig = bytearray(bytes.fromhex(alice.signature_hex))
    sig[-1] ^= 1
    assert not verify_chain(Certificate.from_dict({**alice.to_dict(), "signature_hex": sig.hex()}),
                            [inter.certificate], [root.certificate]).valid


def test_untrusted_root_and_non_ca_issuer(world):
    root, inter, alice, alice_keys = world
    evil = CertificateAuthority.create("Root CA", BITS)
    evil.self_signed_root()
    fake = evil.issue("Alice", alice.public_key)
    assert not verify_chain(fake, [evil.certificate], [root.certificate]).valid
    leaf_pub, _ = generate_keypair(BITS)
    not_ca = CertificateAuthority("Alice", alice_keys, alice)    # chứng chỉ Alice không có is_ca
    child = not_ca.issue("Bob", leaf_pub)
    res = verify_chain(child, [alice, inter.certificate], [root.certificate])
    assert not res.valid and "không phải CA" in res.reason


def test_timestamp_token():
    tsa = TimestampAuthority.create("TSA", BITS)
    sig = b"\x01" * 96
    token = tsa.stamp(sig, at=1_700_000_000)
    assert verify_token(token, sig, tsa.public_key)
    assert verify_token(TimestampToken.from_dict(token.to_dict()), sig, tsa.public_key)
    assert not verify_token(token, sig[:-1] + b"\x02", tsa.public_key)
    assert not verify_token(TimestampToken.from_dict({**token.to_dict(), "time": 1_600_000_000}), sig, tsa.public_key)
