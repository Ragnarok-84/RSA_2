# Tệp: tests/test_padding.py   [Báo cáo 5.4 - Bộ kiểm thử; 3.4 - PKCS#1 v1.5, PSS]
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import padding as pd
from core.sha256 import hash_sha256, sha256_bytes


class TestPkcs1v15(unittest.TestCase):
    def test_structure(self):
        em_len = 128
        em = pd.add_pkcs1_v15_padding(hash_sha256("x"), em_len).to_bytes(em_len, "big")
        self.assertEqual(em[:2], b"\x00\x01")
        ps_end = em.index(b"\x00", 2)
        self.assertTrue(all(b == 0xFF for b in em[2:ps_end]))
        self.assertGreaterEqual(ps_end - 2, 8)
        self.assertEqual(em[ps_end + 1:ps_end + 20], pd.SHA256_DIGEST_INFO)
        self.assertEqual(em[-32:].hex(), hash_sha256("x"))

    def test_strict_parse(self):
        em = pd.pkcs1_v15_encode(sha256_bytes("x"), 128)
        self.assertEqual(pd.parse_em_strict(em), hash_sha256("x"))
        self.assertIsNone(pd.parse_em_strict(em + b"\x00"))                 # byte thừa
        self.assertIsNone(pd.parse_em_strict(b"\x00\x02" + em[2:]))         # sai block type
        bad = bytearray(em); bad[5] = 0xFE
        self.assertIsNone(pd.parse_em_strict(bytes(bad)))                   # PS không toàn FF
        bad = bytearray(em); bad[-40] ^= 1
        self.assertIsNone(pd.parse_em_strict(bytes(bad)))                   # DigestInfo sai

    def test_too_short(self):
        with self.assertRaises(ValueError):
            pd.add_pkcs1_v15_padding(hash_sha256("x"), 40)


class TestPss(unittest.TestCase):
    EM_BITS = 1023

    def test_roundtrip_and_structure(self):
        h = sha256_bytes("tai lieu")
        em = pd.pss_encode(h, self.EM_BITS)
        self.assertEqual(len(em), 128)
        self.assertEqual(em[-1], 0xBC)
        self.assertEqual(em[0] & 0x80, 0)                   # bit cao nhất bị xóa (emBits = 1023)
        self.assertTrue(pd.pss_verify(h, em, self.EM_BITS))

    def test_randomized_salt(self):
        h = sha256_bytes("x")
        self.assertNotEqual(pd.pss_encode(h, self.EM_BITS), pd.pss_encode(h, self.EM_BITS))
        salt = b"s" * 32
        self.assertEqual(pd.pss_encode(h, self.EM_BITS, salt), pd.pss_encode(h, self.EM_BITS, salt))

    def test_reject_tamper(self):
        h = sha256_bytes("x")
        em = pd.pss_encode(h, self.EM_BITS)
        self.assertFalse(pd.pss_verify(sha256_bytes("y"), em, self.EM_BITS))
        for pos in (0, 10, 100, 126, 127):
            bad = bytearray(em); bad[pos] ^= 0x01
            self.assertFalse(pd.pss_verify(h, bytes(bad), self.EM_BITS), pos)
        self.assertFalse(pd.pss_verify(h, em[:-1], self.EM_BITS))


class TestMgf1Oaep(unittest.TestCase):
    def test_mgf1(self):
        self.assertEqual(pd.mgf1(b"", 32), sha256_bytes(b"\x00\x00\x00\x00"))
        self.assertEqual(pd.mgf1(b"seed", 100)[:32], sha256_bytes(b"seed\x00\x00\x00\x00"))
        self.assertEqual(len(pd.mgf1(b"seed", 100)), 100)

    def test_oaep_roundtrip(self):
        k = 128
        for m in (b"", b"a", os.urandom(pd.oaep_max_length(k))):
            self.assertEqual(pd.oaep_decode(pd.oaep_encode(m, k, b"L"), k, b"L"), m)
        with self.assertRaises(ValueError):
            pd.oaep_encode(os.urandom(pd.oaep_max_length(k) + 1), k)

    def test_oaep_reject(self):
        k = 128
        em = pd.oaep_encode(b"bi mat", k, b"Bob")
        with self.assertRaises(pd.DecodingError):
            pd.oaep_decode(em, k, b"Eve")                   # sai nhãn
        bad = bytearray(em); bad[0] = 1
        with self.assertRaises(pd.DecodingError):
            pd.oaep_decode(bytes(bad), k, b"Bob")


if __name__ == "__main__":
    unittest.main(verbosity=2)
