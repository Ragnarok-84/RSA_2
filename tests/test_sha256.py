import hashlib
import hmac as std_hmac          # thư viện chuẩn: CHỈ dùng để đối chiếu
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.sha256 import hash_sha256, sha256_bytes, SHA256, hash_file
from core.hmac_utils import generate_hmac, verify_hmac, pbkdf2_hmac_sha256


class TestSha256(unittest.TestCase):
    def test_nist_vectors(self):
        """Test vector của NIST (FIPS 180-4, ví dụ mẫu)."""
        self.assertEqual(hash_sha256(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        self.assertEqual(hash_sha256("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        self.assertEqual(hash_sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
                         "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")

    def test_against_hashlib_all_padding_boundaries(self):
        """Các độ dài quanh biên đệm 55/56/64 byte và dữ liệu lớn."""
        for n in list(range(0, 130)) + [1000, 4096]:
            data = os.urandom(n)
            self.assertEqual(hash_sha256(data), hashlib.sha256(data).hexdigest(), n)

    def test_unicode(self):
        self.assertEqual(hash_sha256("Tiếng Việt có dấu"), hashlib.sha256("Tiếng Việt có dấu".encode()).hexdigest())

    def test_streaming_equals_one_shot(self):
        data = os.urandom(5000)
        h = SHA256()
        for i in range(0, len(data), 333):          # nạp từng mẩu không chia hết 64
            h.update(data[i:i + 333])
        self.assertEqual(h.hexdigest(), hash_sha256(data))
        self.assertEqual(sha256_bytes(data), hashlib.sha256(data).digest())

    def test_hash_file(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(os.urandom(200_000))
            path = f.name
        try:
            with open(path, "rb") as f:
                self.assertEqual(hash_file(path, chunk_size=7000), hashlib.sha256(f.read()).hexdigest())
        finally:
            os.remove(path)

    def test_one_bit_change(self):
        """Đổi 1 bit thông điệp -> giá trị băm khác (cơ sở của việc ký trên băm)."""
        self.assertNotEqual(hash_sha256(b"\x00"), hash_sha256(b"\x01"))


class TestHmacPbkdf2(unittest.TestCase):
    def test_rfc4231(self):
        self.assertEqual(generate_hmac(b"\x0b" * 20, b"Hi There"),
                         "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
        self.assertEqual(generate_hmac("Jefe", "what do ya want for nothing?"),
                         "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")

    def test_against_stdlib_all_key_lengths(self):
        for klen in (0, 1, 63, 64, 65, 131):
            k, m = os.urandom(klen), os.urandom(50)
            self.assertEqual(generate_hmac(k, m), std_hmac.new(k, m, hashlib.sha256).hexdigest(), klen)

    def test_verify(self):
        tag = generate_hmac("k", "m")
        self.assertTrue(verify_hmac("k", "m", tag))
        self.assertFalse(verify_hmac("k", "m2", tag))
        self.assertFalse(verify_hmac("k2", "m", tag))
        self.assertFalse(verify_hmac("k", "m", None))

    def test_pbkdf2_against_hashlib(self):
        for dklen in (16, 32, 50):
            self.assertEqual(pbkdf2_hmac_sha256("mat khau", b"salt", 100, dklen),
                             hashlib.pbkdf2_hmac("sha256", "mat khau".encode(), b"salt", 100, dklen))


if __name__ == "__main__":
    unittest.main(verbosity=2)
