# Tệp: tests/test_rsa_math.py   [Báo cáo 5.4 - Bộ kiểm thử; 2.6 - Số học nền tảng]
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import rsa_math as rm

REAL = os.environ.get("REAL") == "1"
KEYSIZE = 2048 if REAL else 512


class TestArithmetic(unittest.TestCase):
    def test_gcd_and_extended_gcd(self):
        self.assertEqual(rm.gcd(48, 18), 6)
        for a, b in ((240, 46), (160, 7), (10 ** 30 + 7, 2 ** 89 - 1)):
            g, x, y = rm.extended_gcd(a, b)
            self.assertEqual(a * x + b * y, g)
            self.assertEqual(g, rm.gcd(a, b))

    def test_mod_inverse_class_example(self):
        self.assertEqual(rm.mod_inverse(7, 160), 23)        # ví dụ trên lớp
        self.assertEqual(rm.mod_inverse(3, 616), 411)       # khóa của Bob trong ví dụ bảo mật
        with self.assertRaises(ValueError):
            rm.mod_inverse(6, 9)

    def test_mod_exp(self):
        self.assertEqual(rm.mod_exp(88, 7, 187), 11)
        for a, b, m in ((123456789, 987654321, 1000000007), (5, 117, 19), (2, 10 ** 20, 10 ** 9 + 9), (7, 0, 13)):
            self.assertEqual(rm.mod_exp(a, b, m), pow(a, b, m))
        self.assertEqual(rm.mod_exp(5, 3, 1), 0)

    def test_square_and_multiply_trace(self):
        trace = []
        rm.mod_exp(88, 23, 187, trace)                      # 23 = 10111b
        self.assertEqual([b for b, _ in trace], list("10111"))
        self.assertEqual([v for _, v in trace], [88, 77, 22, 143, 11])

    def test_miller_rabin(self):
        for p in (2, 3, 104729, 2 ** 61 - 1, 2 ** 127 - 1):
            self.assertTrue(rm.is_prime(p), p)
        for c in (0, 1, 4, 561, 1105, 104730, 2 ** 61 + 1, (2 ** 61 - 1) * (2 ** 31 - 1)):   # 561, 1105: Carmichael
            self.assertFalse(rm.is_prime(c), c)

    def test_generate_prime_bits(self):
        for bits in (16, 64, 128):
            p = rm.generate_prime(bits)
            self.assertEqual(p.bit_length(), bits)
            self.assertTrue(rm.is_prime(p))

    def test_cuberoot(self):
        for x in (0, 1, 7, 8, 9, 10 ** 30, 12345678901234567890123456789 ** 3, 12345678901234567890123456789 ** 3 + 1):
            r = rm.integer_cuberoot_ceil(x)
            self.assertGreaterEqual(r ** 3, x)
            if r > 0:
                self.assertLess((r - 1) ** 3, x)

    def test_compare_hashes_and_i2osp(self):
        self.assertTrue(rm.compare_hashes("abc", "abc"))
        self.assertFalse(rm.compare_hashes("abc", "abd"))
        self.assertFalse(rm.compare_hashes("abc", "abcd"))
        self.assertFalse(rm.compare_hashes("abc", None))
        self.assertEqual(rm.int_to_bytes(258, 3), b"\x00\x01\x02")
        self.assertEqual(rm.bytes_to_int(b"\x00\x01\x02"), 258)
        with self.assertRaises(ValueError):
            rm.int_to_bytes(256, 1)


class TestKeygen(unittest.TestCase):
    def test_hand_example(self):
        self.assertEqual(rm.generate_keypair(p=17, q=11, e=7), ((23, 187), (7, 187)))

    def test_random_key_properties(self):
        for _ in range(3):
            (d, N), (e, N2) = rm.generate_keypair(keysize=KEYSIZE)
            self.assertEqual(N, N2)
            self.assertEqual(N.bit_length(), KEYSIZE)
            self.assertEqual(e, 65537)
            m = 0xDEADBEEF
            self.assertEqual(pow(pow(m, e, N), d, N), m)

    def test_custom_e(self):
        (d, N), (e, _) = rm.generate_keypair(keysize=KEYSIZE, e=3)
        self.assertEqual(e, 3)
        self.assertEqual(pow(pow(42, 3, N), d, N), 42)

    def test_bad_params(self):
        with self.assertRaises(ValueError):
            rm.generate_keypair()
        with self.assertRaises(ValueError):
            rm.generate_keypair(p=17, q=11, e=10)      # gcd(10, 160) != 1
        with self.assertRaises(ValueError):
            rm.generate_keypair(p=17, q=17)
        with self.assertRaises(ValueError):
            rm.generate_keypair(p=15, q=11)            # 15 không nguyên tố

    def test_alias_and_explain(self):
        self.assertIs(rm.generate_key_pair, rm.generate_keypair)
        self.assertIn("=> d = 23", "\n".join(rm.explain_keygen(17, 11, 7)))


if __name__ == "__main__":
    unittest.main(verbosity=2)
