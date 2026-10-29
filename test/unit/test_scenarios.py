"""Mỗi kịch bản s1 → s6 chạy hết luồng và cho valid == True."""
import pytest

from core.step_logger import StepLogger
from scenarios import REGISTRY, load

BITS = 1024


def _run(name: str):
    log = StepLogger()
    result = load(name).run(log, bits=BITS)
    assert result.valid, log.to_text()
    assert log.steps and log.steps[-1].level == "ok"
    return result


def test_registry_order():
    assert [m for m, _ in REGISTRY] == [
        "s1_authentication", "s2_integrity_tamper", "s3_non_repudiation_contract",
        "s4_key_compromise", "s5_hmac_vs_signature", "s6_sign_then_encrypt"]


def test_s1_authentication():
    r = _run("s1_authentication")
    assert r.details["alice_signature"] and not r.details["mallory_signature"]


def test_s2_integrity_tamper():
    r = _run("s2_integrity_tamper")
    assert not r.details["tampered"] and r.details["hash_bit_diff"] > 64


def test_s3_non_repudiation_contract():
    r = _run("s3_non_repudiation_contract")
    assert not r.details["bob_edits_contract"] and not r.details["backdated_token"]


def test_s4_key_compromise():
    r = _run("s4_key_compromise")
    assert r.details["before_revocation"] and not r.details["after_revocation"]


def test_s5_hmac_vs_signature():
    r = _run("s5_hmac_vs_signature")
    assert r.details["hmac_bob_forgery_accepted"] and not r.details["rsa_bob_forgery_accepted"]


def test_s5_hmac_matches_rfc4231_and_stdlib():
    import hashlib
    import hmac

    from scenarios.s5_hmac_vs_signature import hmac_sha256
    assert hmac_sha256(b"\x0b" * 20, b"Hi There").hex() == \
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    for key in (b"", b"k" * 64, b"k" * 100):
        assert hmac_sha256(key, b"msg") == hmac.new(key, b"msg", hashlib.sha256).digest()


def test_s6_sign_then_encrypt():
    pytest.importorskip("cryptography")
    r = _run("s6_sign_then_encrypt")
    assert r.details["bob_opens"] and not r.details["forward_accepted"]
