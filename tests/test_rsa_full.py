import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import rsa_full, rsa_mini
from core.rsa_math import generate_keypair

REAL = os.environ.get("REAL") == "1"
KEYSIZE = 2048 if REAL else 512
OAEP_KEYSIZE = max(KEYSIZE, 1024)          # OAEP-SHA256 cần N >= 66 byte + dữ liệu
SIGN_KEYSIZE = max(KEYSIZE, 1024)          # PSS với salt 32 byte cần N >= 528 bit


class TestSignVerify(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.priv, cls.pub = generate_keypair(keysize=SIGN_KEYSIZE)

    def test_sign_verify_both_schemes(self):
        for scheme in rsa_full.SCHEMES:
            s = rsa_full.sign_message("hello", self.priv, scheme)
            self.assertTrue(rsa_full.verify_message("hello", s, self.pub, scheme), scheme)
            self.assertFalse(rsa_full.verify_message("hellO", s, self.pub, scheme), scheme)

    def test_scheme_mismatch(self):
        s = rsa_full.sign_message("x", self.priv, "pss")
        self.assertFalse(rsa_full.verify_message("x", s, self.pub, "pkcs1v15"))
        with self.assertRaises(ValueError):
            rsa_full.sign_message("x", self.priv, "khong-ton-tai")

    def test_pkcs1v15_deterministic_pss_randomized(self):
        self.assertEqual(rsa_full.sign_message("x", self.priv), rsa_full.sign_message("x", self.priv))
        self.assertNotEqual(rsa_full.sign_message("x", self.priv, "pss"), rsa_full.sign_message("x", self.priv, "pss"))

    def test_bytes_and_unicode(self):
        s = rsa_full.sign_message("Hợp đồng", self.priv)
        self.assertTrue(rsa_full.verify_message("Hợp đồng".encode(), s, self.pub))

    def test_long_message(self):
        data = os.urandom(100_000)
        s = rsa_full.sign_message(data, self.priv)
        self.assertTrue(rsa_full.verify_message(data, s, self.pub))

    def test_wrong_key(self):
        _, other_pub = generate_keypair(keysize=SIGN_KEYSIZE)
        for scheme in rsa_full.SCHEMES:
            s = rsa_full.sign_message("x", self.priv, scheme)
            self.assertFalse(rsa_full.verify_message("x", s, other_pub, scheme))

    def test_signature_out_of_range(self):
        N = self.pub[1]
        for scheme in rsa_full.SCHEMES:
            s = rsa_full.sign_message("x", self.priv, scheme)
            for bad in (s + N, 0, -s, N):
                self.assertFalse(rsa_full.verify_message("x", bad, self.pub, scheme))

    def test_explain_sign(self):
        r = rsa_full.explain_sign("x", self.priv, self.pub)
        self.assertTrue(r["valid"])
        self.assertEqual(r["em"], r["em_recovered"])
        self.assertEqual(r["hash"], r["hash_recovered"])

    def test_interop_with_cryptography(self):
        try:
            from cryptography.hazmat.primitives.asymmetric import padding
            from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
            from cryptography.hazmat.primitives import hashes
        except ImportError:
            self.skipTest("chưa cài cryptography")
        e, N = self.pub
        k = (N.bit_length() + 7) // 8
        key = RSAPublicNumbers(e, N).public_key()
        key.verify(rsa_full.sign_message(b"interop", self.priv).to_bytes(k, "big"), b"interop",
                   padding.PKCS1v15(), hashes.SHA256())
        key.verify(rsa_full.sign_message(b"interop", self.priv, "pss").to_bytes(k, "big"), b"interop",
                   padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())


class TestOaepEncryption(unittest.TestCase):
    """Bổ sung - tính bảo mật."""

    @classmethod
    def setUpClass(cls):
        cls.priv, cls.pub = generate_keypair(keysize=OAEP_KEYSIZE)

    def test_roundtrip_and_lengths(self):
        mx = rsa_full.max_message_length(self.pub)
        for m in (b"", b"a", "Tiếng Việt".encode(), os.urandom(mx)):
            self.assertEqual(rsa_full.oaep_decrypt(rsa_full.oaep_encrypt(m, self.pub), self.priv), m)
        with self.assertRaises(ValueError):
            rsa_full.oaep_encrypt(os.urandom(mx + 1), self.pub)

    def test_randomized_vs_textbook(self):
        self.assertNotEqual(rsa_full.oaep_encrypt(b"x", self.pub), rsa_full.oaep_encrypt(b"x", self.pub))
        self.assertEqual(rsa_full.textbook_encrypt(42, self.pub), rsa_full.textbook_encrypt(42, self.pub))
        self.assertEqual(rsa_full.textbook_decrypt(rsa_full.textbook_encrypt(42, self.pub), self.priv), 42)

    def test_wrong_key_label_tamper(self):
        c = rsa_full.oaep_encrypt(b"bi mat", self.pub, label="Thu Thủy".encode())
        other, _ = generate_keypair(keysize=OAEP_KEYSIZE)
        bad = bytearray(c); bad[-1] ^= 1
        for args in ((c, other, "Thu Thủy".encode()), (c, self.priv, "Mai Phương".encode()), (bytes(bad), self.priv, "Thu Thủy".encode()), (c[:-1], self.priv, "Thu Thủy".encode())):
            with self.assertRaises(rsa_full.DecryptionError):
                rsa_full.oaep_decrypt(*args)

    def test_interop_with_cryptography(self):
        try:
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import padding
            from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
        except ImportError:
            self.skipTest("chưa cài cryptography")
        oaep = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        c = RSAPublicNumbers(*self.pub).public_key().encrypt(b"tu thu vien", oaep)
        self.assertEqual(rsa_full.oaep_decrypt(c, self.priv), b"tu thu vien")


class TestRsaMini(unittest.TestCase):
    """Bản thu nhỏ phải tái hiện đúng ví dụ trên lớp (căn cứ chấm tính đúng đắn)."""

    @classmethod
    def setUpClass(cls):
        cls.r = rsa_mini.run_demo(verbose=False)

    def test_class_example_numbers(self):
        r = self.r
        self.assertEqual((r["N"], r["phi"], r["d"], r["C"], r["M2"], r["S"]), (187, 160, 23, 11, 88, 11))
        self.assertTrue(r["verify_ok"])
        self.assertFalse(r["verify_tampered"])

    def test_hash_then_sign(self):
        self.assertTrue(self.r["hash_ok"])
        self.assertFalse(self.r["hash_tampered"])

    def test_confidentiality_numbers(self):
        # Thu Thủy: p=23, q=29, e=3 -> d=411. Thu Trang ký S=11, mã hóa C1=88^3 mod 667, C2=11^3 mod 667
        r = self.r
        self.assertEqual((r["bob_N"], r["bob_d"], r["conf_C1"], r["conf_C2"], r["conf_M"]), (667, 411, 465, 664, 88))
        self.assertTrue(r["conf_sig_ok"])
        self.assertEqual(r["conf_dict_attack"], 88)


if __name__ == "__main__":
    unittest.main(verbosity=2)
