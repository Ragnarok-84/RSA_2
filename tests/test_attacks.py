# Tệp: tests/test_attacks.py   [bổ sung - Báo cáo 3.6, 6.4: tấn công minh họa phải tái hiện được]
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.sha256 import hash_sha256
from attacks import small_n, forgery_no_padding, bleichenbacher_e3, confidentiality

REAL = os.environ.get("REAL") == "1"
KEYSIZE = 2048 if REAL else 512
OAEP_KEYSIZE = max(KEYSIZE, 1024)
ATTACK_KEYSIZE = 2048 if REAL else 1536     # Bleichenbacher SHA-256 cần N >= ~1328 bit


class TestSignatureAttacks(unittest.TestCase):
    def test_small_n(self):
        self.assertEqual(small_n.attack_small_n(3233), (53, 61))
        self.assertEqual(small_n.attack_small_n(3571 * 4093), (3571, 4093))
        self.assertIsNone(small_n.attack_small_n(104729))        # nguyên tố
        self.assertEqual(small_n.recover_private_key(17, 3233)[0], 2753)
        self.assertTrue(small_n.demo_small_n(verbose=False))

    def test_no_padding_forgery(self):
        self.assertTrue(forgery_no_padding.demo_no_padding_forgery(verbose=False))
        self.assertTrue(forgery_no_padding.padding_blocks_forgery(keysize=KEYSIZE))

    def test_bleichenbacher(self):
        lenient, strict = bleichenbacher_e3.demo_bleichenbacher(keysize=ATTACK_KEYSIZE, verbose=False)
        self.assertTrue(lenient)       # bên xác thực lỏng lẻo bị lừa
        self.assertFalse(strict)       # core/padding kiểm tra chặt nên từ chối

    def test_bleichenbacher_preconditions(self):
        with self.assertRaises(ValueError):
            bleichenbacher_e3.attack_bleichenbacher_e3((65537, 1 << 2048), hash_sha256("x"))
        with self.assertRaises(ValueError):
            bleichenbacher_e3.attack_bleichenbacher_e3((3, (1 << 1023) + 1), hash_sha256("x"))


class TestConfidentialityAttacks(unittest.TestCase):
    def test_dictionary_textbook_vs_oaep(self):
        textbook_broken, oaep_safe = confidentiality.demo_dictionary(keysize=OAEP_KEYSIZE, verbose=False)
        self.assertTrue(textbook_broken)
        self.assertTrue(oaep_safe)

    def test_encrypt_and_sign_leak(self):
        self.assertTrue(confidentiality.demo_encrypt_and_sign_leak(keysize=OAEP_KEYSIZE, verbose=False))

    def test_hastad(self):
        broken, oaep_safe = confidentiality.demo_hastad(keysize=1024, verbose=False)
        self.assertTrue(broken)
        self.assertTrue(oaep_safe)

    def test_same_key_sign_decrypt(self):
        self.assertTrue(confidentiality.demo_same_key_sign_decrypt(keysize=KEYSIZE, verbose=False))


if __name__ == "__main__":
    unittest.main(verbosity=2)
