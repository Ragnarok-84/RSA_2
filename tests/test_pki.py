# Tệp: tests/test_pki.py   [Báo cáo 5.4 - Bộ kiểm thử; 4.4 - CRL, dấu thời gian]
import os
import sys
import unittest
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.rsa_math import generate_keypair
from pki import cert as pki_cert
from pki.crl import CertificateRevocationList, verify_published_crl
from pki.timestamp import TimestampAuthority, NonceRegistry

REAL = os.environ.get("REAL") == "1"
KEYSIZE = 2048 if REAL else 512


class TestCertificate(unittest.TestCase):
    def test_full_demo(self):
        r = pki_cert.run_demo(keysize=KEYSIZE, verbose=False)
        self.assertTrue(r["root"])
        self.assertTrue(r["alice_valid"])
        self.assertTrue(r["doc_ok"])
        for key in ("doc_tampered", "forged_key", "fake_ca", "expired", "wrong_usage", "revoked"):
            self.assertFalse(r[key], key)

    def test_not_yet_valid(self):
        ca = pki_cert.CertificateAuthority("CA", keysize=KEYSIZE)
        _, pub = generate_keypair(keysize=KEYSIZE)
        c = ca.issue_certificate("Z", pub, days=30, start=datetime.now() + timedelta(days=10))
        ok, msg = pki_cert.verify_certificate(c, ca.certificate, ca.crl)
        self.assertFalse(ok)
        self.assertIn("chưa có hiệu lực", msg)

    def test_tampered_fields(self):
        ca = pki_cert.CertificateAuthority("CA", keysize=KEYSIZE)
        _, pub = generate_keypair(keysize=KEYSIZE)
        c = ca.issue_certificate("Thu Trang", pub)
        for field, value in (("subject", "Mai Phương"), ("not_after", "2099-01-01"), ("key_usage", "encryption")):
            self.assertFalse(pki_cert.verify_certificate(dict(c, **{field: value}), ca.certificate)[0], field)

    def test_bad_usage_value(self):
        ca = pki_cert.CertificateAuthority("CA", keysize=KEYSIZE)
        with self.assertRaises(ValueError):
            ca.issue_certificate("X", ca.public_key, key_usage="moi-thu")


class TestCrl(unittest.TestCase):
    def test_revocation_time_semantics(self):
        crl = CertificateRevocationList("CA")
        t = datetime(2026, 5, 1, 12, 0, 0)
        crl.revoke(7, at=t)
        self.assertIn(7, crl)
        self.assertFalse(crl.is_revoked(7, now=t - timedelta(seconds=1)))   # trước thời điểm thu hồi
        self.assertTrue(crl.is_revoked(7, now=t))
        self.assertFalse(crl.is_revoked(8, now=t))
        with self.assertRaises(ValueError):
            crl.revoke(9, reason="vi-thich")

    def test_published_crl_signature(self):
        ca = pki_cert.CertificateAuthority("CA", keysize=KEYSIZE)
        ca.revoke(5)
        pub = ca.publish_crl()
        self.assertTrue(verify_published_crl(pub, ca.certificate, pki_cert.verify_data))
        self.assertFalse(verify_published_crl(dict(pub, entries={}), ca.certificate, pki_cert.verify_data))
        other = pki_cert.CertificateAuthority("CA", keysize=KEYSIZE)
        self.assertFalse(verify_published_crl(pub, other.certificate, pki_cert.verify_data))


class TestTimestampAndNonce(unittest.TestCase):
    def test_timestamp_authority(self):
        tsa = TimestampAuthority(keysize=KEYSIZE)
        tok = tsa.issue(123456789)
        self.assertTrue(tsa.verify(tok, 123456789))
        self.assertFalse(tsa.verify(tok, 123456780))                            # chữ ký khác
        self.assertFalse(tsa.verify(dict(tok, time="2000-01-01 00:00:00"), 123456789))   # sửa ngày

    def test_nonce_single_use_owner_expiry(self):
        reg = NonceRegistry(lifetime_seconds=60)
        n = reg.issue("Thu Trang")
        self.assertTrue(reg.consume(n, "Thu Trang")[0])
        self.assertFalse(reg.consume(n, "Thu Trang")[0])                            # dùng lại
        n2 = reg.issue("Thu Trang")
        self.assertFalse(reg.consume(n2, "Mai Phương")[0])                             # sai chủ thể
        n3 = reg.issue("Thu Trang")
        self.assertFalse(reg.consume(n3, "Thu Trang", now=datetime.now() + timedelta(minutes=5))[0])   # hết hạn
        self.assertNotEqual(reg.issue("Thu Trang"), reg.issue("Thu Trang"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
