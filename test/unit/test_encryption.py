"""Đối chiếu OAEP với cryptography và kiểm tra gói ký rồi mã hoá."""
import copy

import pytest

from core.encryption import MAX_MESSAGE_BYTES, decrypt_oaep, encrypt_oaep, seal, unseal
from core.signature import SignatureBundle, sign, verify


def bundle_for(message, priv, scheme="pkcs1v15"):
    from core.hash.sha256 import sha256
    return SignatureBundle(scheme, "message.bin", sha256(message).hex(), sign(message, priv, scheme).hex())


@pytest.mark.parametrize("message", [b"", b"abc", bytes(range(190))])
def test_oaep_cross_library(keypair, message):
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    pub, priv = keypair
    ref = rsa.RSAPrivateNumbers(priv.p, priv.q, priv.d, priv.d % (priv.p - 1),
                               priv.d % (priv.q - 1), pow(priv.q, -1, priv.p),
                               rsa.RSAPublicNumbers(pub.e, pub.n)).private_key()
    label = b"test-label"
    pad = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=label)
    assert ref.decrypt(encrypt_oaep(message, pub, label), pad) == message
    assert decrypt_oaep(ref.public_key().encrypt(message, pad), priv, label) == message
    with pytest.raises(ValueError):
        decrypt_oaep(encrypt_oaep(message, pub, label), priv, b"wrong-label")


@pytest.mark.parametrize("scheme", ["pkcs1v15"])
def test_package_binary_roundtrip(keypair, other_keypair, scheme):
    pub, priv = keypair
    receiver_pub, receiver_priv = other_keypair
    message = bytes(range(256)) * 2
    bundle = bundle_for(message, priv, scheme)
    envelope = seal(message, bundle, receiver_pub)
    recovered, signature = unseal(envelope, receiver_priv)
    assert recovered == message
    assert signature.to_dict() == bundle.to_dict()
    assert verify(recovered, signature.signature, pub, scheme)
    assert envelope != seal(message, bundle, receiver_pub)
    with pytest.raises(ValueError):
        unseal(envelope, priv)


@pytest.mark.parametrize("change", ["flip", "reorder", "truncate", "duplicate", "splice", "id"])
def test_modified_package_rejected(keypair, change):
    pub, priv = keypair
    message = b"demo" * 100
    bundle = bundle_for(message, priv)
    envelope = copy.deepcopy(seal(message, bundle, pub))
    if change == "flip":
        block = bytearray.fromhex(envelope["blocks"][0])
        block[-1] ^= 1
        envelope["blocks"][0] = block.hex()
    elif change == "reorder":
        envelope["blocks"].reverse()
    elif change == "truncate":
        envelope["blocks"].pop()
    elif change == "duplicate":
        envelope["blocks"][1] = envelope["blocks"][0]
    elif change == "splice":
        envelope["blocks"][0] = seal(message, bundle, pub)["blocks"][0]
    else:
        envelope["package_id"] = "00" * 16
    with pytest.raises(ValueError):
        unseal(envelope, priv)


def test_limits_and_malformed_input(keypair):
    pub, priv = keypair
    with pytest.raises(ValueError):
        encrypt_oaep(b"x" * 191, pub)
    with pytest.raises(ValueError):
        seal(b"x" * (MAX_MESSAGE_BYTES + 1), bundle_for(b"a", priv), pub)
    for envelope in ({}, None, {"algorithm": "unsupported"}):
        with pytest.raises(ValueError):
            unseal(envelope, priv)
