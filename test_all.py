# Tệp: test_all.py
# BỘ TEST HOÀN CHỈNH cho toàn dự án.
#
#   python test_all.py            -> chế độ nhanh (khóa 512 bit, Bleichenbacher 1536 bit)
#   python test_all.py --real     -> chế độ thực tế (khóa 2048 bit)
#   hoặc đặt REAL = True ngay bên dưới / biến môi trường REAL=1
import hashlib
import hmac as std_hmac
import os
import sys
import unittest
from datetime import datetime, timedelta

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

REAL = False   # <--- bật True để chạy bộ test với khóa thực tế (2048 bit)
if "--real" in sys.argv:
    sys.argv.remove("--real")
    REAL = True
if os.environ.get("REAL") == "1":
    REAL = True

KEYSIZE = 2048 if REAL else 512
ATTACK_KEYSIZE = 2048 if REAL else 1536     # Bleichenbacher SHA-256 cần N >= ~1328 bit

import math_utils
import keygen
import rsa_core
import rsa_mini
import hmac_utils
import pki_ca
import test_s4
from sha256 import hash_sha256
from attacks import attacks
from scenarios.s1_authentication import run_scenario_s1
from scenarios.s2_nonrepudiation import run_scenario_s2
from scenarios.s3_revocation import run_scenario_s3
from scenarios.s7_key_substitution import run_scenario_s7


class TestMath(unittest.TestCase):
    def test_gcd_inverse_modexp(self):
        self.assertEqual(math_utils.gcd(48, 18), 6)
        self.assertEqual(math_utils.mod_inverse(7, 160), 23)
        self.assertEqual(math_utils.mod_exp(88, 7, 187), 11)
        for a, b, m in ((123456789, 987654321, 1000000007), (5, 117, 19), (2, 10 ** 20, 10 ** 9 + 9)):
            self.assertEqual(math_utils.mod_exp(a, b, m), pow(a, b, m))

    def test_no_inverse_raises(self):
        with self.assertRaises(ValueError):
            math_utils.mod_inverse(6, 9)

    def test_miller_rabin(self):
        for p in (2, 3, 104729, 2 ** 61 - 1):
            self.assertTrue(math_utils.is_prime(p), p)
        for c in (1, 4, 561, 104730, 2 ** 61 + 1):      # 561 là số Carmichael
            self.assertFalse(math_utils.is_prime(c), c)

    def test_compare_hashes(self):
        self.assertTrue(math_utils.compare_hashes("abc", "abc"))
        self.assertFalse(math_utils.compare_hashes("abc", "abd"))
        self.assertFalse(math_utils.compare_hashes("abc", None))
        self.assertFalse(math_utils.compare_hashes(None, None))


class TestSha256(unittest.TestCase):
    def test_vectors(self):
        self.assertEqual(hash_sha256("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        self.assertEqual(hash_sha256(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

    def test_against_hashlib(self):
        for n in list(range(0, 130)) + [1000, 4096]:
            data = os.urandom(n)
            self.assertEqual(hash_sha256(data), hashlib.sha256(data).hexdigest(), n)
        self.assertEqual(hash_sha256("Tiếng Việt có dấu"), hashlib.sha256("Tiếng Việt có dấu".encode()).hexdigest())


class TestHmac(unittest.TestCase):
    def test_rfc4231(self):
        self.assertEqual(hmac_utils.generate_hmac("Jefe", "what do ya want for nothing?"),
                         "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")

    def test_against_stdlib_all_key_lengths(self):
        for klen in (0, 1, 63, 64, 65, 131):
            k, m = os.urandom(klen), os.urandom(50)
            self.assertEqual(hmac_utils.generate_hmac(k, m), std_hmac.new(k, m, hashlib.sha256).hexdigest(), klen)

    def test_verify(self):
        tag = hmac_utils.generate_hmac("k", "m")
        self.assertTrue(hmac_utils.verify_hmac("k", "m", tag))
        self.assertFalse(hmac_utils.verify_hmac("k", "m2", tag))
        self.assertFalse(hmac_utils.verify_hmac("k2", "m", tag))
        self.assertFalse(hmac_utils.verify_hmac("k", "m", None))


class TestKeygenAndMini(unittest.TestCase):
    def test_hand_example(self):
        priv, pub = keygen.generate_keypair(p=17, q=11, e=7)
        self.assertEqual((priv, pub), ((23, 187), (7, 187)))

    def test_rsa_mini_numbers(self):
        r = rsa_mini.run_demo(verbose=False)
        self.assertEqual((r["N"], r["phi"], r["d"], r["C"], r["M2"], r["S"]), (187, 160, 23, 11, 88, 11))
        self.assertTrue(r["verify_ok"])
        self.assertFalse(r["verify_tampered"])

    def test_random_key_properties(self):
        for _ in range(3):
            (d, N), (e, N2) = keygen.generate_keypair(keysize=KEYSIZE)
            self.assertEqual(N, N2)
            self.assertEqual(N.bit_length(), KEYSIZE)
            m = 0xDEADBEEF
            self.assertEqual(pow(pow(m, e, N), d, N), m)

    def test_bad_params(self):
        with self.assertRaises(ValueError):
            keygen.generate_keypair()
        with self.assertRaises(ValueError):
            keygen.generate_keypair(p=17, q=11, e=10)      # gcd(10, 160) != 1
        with self.assertRaises(ValueError):
            keygen.generate_keypair(p=17, q=17)

    def test_alias(self):
        self.assertIs(keygen.generate_key_pair, keygen.generate_keypair)


class TestRsaCore(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.priv, cls.pub = keygen.generate_keypair(keysize=KEYSIZE)

    def test_sign_verify(self):
        s = rsa_core.sign_message("hello", self.priv)
        self.assertTrue(rsa_core.verify_message("hello", s, self.pub))
        self.assertFalse(rsa_core.verify_message("hellO", s, self.pub))

    def test_bytes_and_unicode(self):
        s = rsa_core.sign_message("Hợp đồng", self.priv)
        self.assertTrue(rsa_core.verify_message("Hợp đồng".encode(), s, self.pub))

    def test_wrong_key(self):
        _, other_pub = keygen.generate_keypair(keysize=KEYSIZE)
        s = rsa_core.sign_message("x", self.priv)
        self.assertFalse(rsa_core.verify_message("x", s, other_pub))

    def test_signature_out_of_range(self):
        N = self.pub[1]
        s = rsa_core.sign_message("x", self.priv)
        self.assertFalse(rsa_core.verify_message("x", s + N, self.pub))     # S + N
        self.assertFalse(rsa_core.verify_message("x", 0, self.pub))
        self.assertFalse(rsa_core.verify_message("x", -s, self.pub))

    def test_padding_structure(self):
        em_len = (self.pub[1].bit_length() + 7) // 8
        em = rsa_core.add_pkcs1_v15_padding(hash_sha256("x"), em_len).to_bytes(em_len, "big")
        self.assertEqual(em[:2], b"\x00\x01")
        self.assertEqual(em[-32:].hex(), hash_sha256("x"))
        self.assertEqual(rsa_core.parse_em_strict(em), hash_sha256("x"))
        self.assertIsNone(rsa_core.parse_em_strict(em + b"\x00"))            # byte thừa
        self.assertIsNone(rsa_core.parse_em_strict(b"\x00\x02" + em[2:]))    # sai block type

    def test_padding_too_short(self):
        with self.assertRaises(ValueError):
            rsa_core.add_pkcs1_v15_padding(hash_sha256("x"), 40)

    def test_interop_with_cryptography(self):
        try:
            from cryptography.hazmat.primitives.asymmetric import padding
            from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
            from cryptography.hazmat.primitives import hashes
        except ImportError:
            self.skipTest("chưa cài cryptography")
        e, N = self.pub
        s = rsa_core.sign_message(b"interop", self.priv)
        RSAPublicNumbers(e, N).public_key().verify(
            s.to_bytes((N.bit_length() + 7) // 8, "big"), b"interop", padding.PKCS1v15(), hashes.SHA256())


class TestPki(unittest.TestCase):
    def test_full_demo(self):
        r = pki_ca.run_demo(keysize=KEYSIZE, verbose=False)
        self.assertTrue(r["root"])
        self.assertTrue(r["alice_valid"])
        self.assertTrue(r["doc_ok"])
        self.assertFalse(r["doc_tampered"])
        self.assertFalse(r["forged_key"])
        self.assertFalse(r["fake_ca"])
        self.assertFalse(r["expired"])
        self.assertFalse(r["revoked"])

    def test_not_yet_valid(self):
        ca = pki_ca.CertificateAuthority("CA", keysize=KEYSIZE)
        _, pub = keygen.generate_keypair(keysize=KEYSIZE)
        cert = ca.issue_certificate("Z", pub, days=30, start=datetime.now() + timedelta(days=10))
        ok, msg = pki_ca.verify_certificate(cert, ca.certificate, ca.crl)
        self.assertFalse(ok)
        self.assertIn("chưa có hiệu lực", msg)

    def test_timestamp_authority(self):
        tsa = pki_ca.TimestampAuthority(keysize=KEYSIZE)
        tok = tsa.issue(123456789)
        self.assertTrue(tsa.verify(tok, 123456789))
        self.assertFalse(tsa.verify(tok, 123456780))
        self.assertFalse(tsa.verify(dict(tok, time="2000-01-01 00:00:00"), 123456789))


class TestScenarios(unittest.TestCase):
    def test_s1(self):
        self.assertTrue(run_scenario_s1(keysize=KEYSIZE, verbose=False))

    def test_s2(self):
        self.assertTrue(run_scenario_s2(keysize=KEYSIZE, verbose=False))

    def test_s3(self):
        self.assertTrue(run_scenario_s3(keysize=KEYSIZE, verbose=False))

    def test_s4(self):
        self.assertTrue(test_s4.test_S4_hmac_repudiation(verbose=False))

    def test_s7(self):
        self.assertTrue(run_scenario_s7(keysize=KEYSIZE, verbose=False))

    def test_s5_s6(self):
        import sa_signature_pki, io, contextlib
        # Chế độ TSA phải khớp kỳ vọng ở mọi test case (mã thoát 0)
        with contextlib.redirect_stdout(io.StringIO()):
            code = sa_signature_pki.main(["--bits", str(KEYSIZE if REAL else 1024)])
        self.assertEqual(code, 0)


class TestFileSigner(unittest.TestCase):
    def test_sign_verify_real_file_and_tamper(self):
        import tempfile, file_signer
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "anh.bin")
            with open(path, "wb") as f:
                f.write(os.urandom(5000))                # dữ liệu nhị phân giả làm ảnh
            r = file_signer.demo_sign_file(path=path, keysize=KEYSIZE, workdir=tmp, verbose=False)
            self.assertTrue(r["valid_original"])
            self.assertFalse(r["valid_tampered"])
            priv = file_signer.load_private_key(os.path.join(tmp, "alice.private.json"))
            pub = file_signer.load_public_key(os.path.join(tmp, "alice.public.json"))
            self.assertEqual(priv[1], pub[1])
            self.assertTrue(file_signer.verify_file(path, pub)[0])


class TestCrossCheck(unittest.TestCase):
    def test_doi_chieu_all_match(self):
        import doi_chieu, io, contextlib
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(doi_chieu.run())


class TestNoForbiddenLibraries(unittest.TestCase):
    """Đề yêu cầu tự cài phần lõi: file lõi không được import thư viện mật mã có sẵn."""
    CORE = ["math_utils.py", "sha256.py", "hmac_utils.py", "keygen.py", "rsa_core.py", "rsa_mini.py",
            "pki_ca.py", "sa_signature_pki.py", "file_signer.py"]
    FORBIDDEN = ("import hashlib", "from hashlib", "import hmac", "from hmac", "cryptography", "Crypto.", "openssl")

    def test_core_files_clean(self):
        import glob
        here = os.path.dirname(os.path.abspath(__file__))
        files = [os.path.join(here, f) for f in self.CORE if os.path.exists(os.path.join(here, f))]
        files += glob.glob(os.path.join(here, "attacks", "*.py")) + glob.glob(os.path.join(here, "scenarios", "*.py"))
        self.assertGreater(len(files), 8)
        for path in files:
            with open(path, encoding="utf-8") as f:
                for n, line in enumerate(f, 1):
                    code = line.split("#")[0]
                    for bad in self.FORBIDDEN:
                        self.assertNotIn(bad, code, f"{os.path.basename(path)}:{n} dùng '{bad}'")


class TestAttacks(unittest.TestCase):
    def test_small_n(self):
        self.assertEqual(attacks.attack_small_n(3233), (53, 61))
        self.assertIsNone(attacks.attack_small_n(104729))        # nguyên tố
        d, p, q = attacks.recover_private_key(17, 3233)
        self.assertEqual(d, 2753)

    def test_small_n_fails_on_big_key(self):
        # Với khóa thực, chia thử không khả thi: chỉ kiểm tra N nhỏ (24-bit) bị phá nhanh
        p, q = 3571, 4093
        self.assertEqual(attacks.attack_small_n(p * q), (p, q))

    def test_no_padding_forgery(self):
        self.assertTrue(attacks.demo_no_padding_forgery(verbose=False))

    def test_no_padding_forgery_blocked_by_padding(self):
        priv, pub = keygen.generate_keypair(keysize=KEYSIZE)
        s1 = rsa_core.sign_message("a", priv)
        s2 = rsa_core.sign_message("b", priv)
        s3 = attacks.attack_no_padding_forgery(pub, s1, s2)
        for m in ("a", "b", "ab"):
            self.assertFalse(rsa_core.verify_message(m, s3, pub))

    def test_cuberoot(self):
        for x in (0, 1, 7, 8, 9, 10 ** 30, 12345678901234567890123456789 ** 3, 12345678901234567890123456789 ** 3 + 1):
            r = attacks.integer_cuberoot_ceil(x)
            self.assertGreaterEqual(r ** 3, x)
            if r > 0:
                self.assertLess((r - 1) ** 3, x)

    def test_bleichenbacher(self):
        lenient, strict = attacks.demo_bleichenbacher(keysize=ATTACK_KEYSIZE, verbose=False)
        self.assertTrue(lenient)       # bên xác thực lỏng lẻo bị lừa
        self.assertFalse(strict)       # rsa_core kiểm tra chặt nên từ chối

    def test_bleichenbacher_requires_e3(self):
        with self.assertRaises(ValueError):
            attacks.attack_bleichenbacher_e3((65537, 1 << 2048), hash_sha256("x"))

    def test_bleichenbacher_small_modulus_rejected(self):
        with self.assertRaises(ValueError):
            attacks.attack_bleichenbacher_e3((3, (1 << 1023) + 1), hash_sha256("x"))


if __name__ == "__main__":
    print(f"=== BỘ TEST HOÀN CHỈNH — REAL = {REAL} (khóa {KEYSIZE} bit) ===")
    unittest.main(verbosity=2)
