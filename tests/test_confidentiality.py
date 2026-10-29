# Tệp: tests/test_confidentiality.py   [bổ sung - TÍNH BẢO MẬT: ký rồi mã hóa, tệp thật, bảo vệ khóa riêng]
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.rsa_math import generate_keypair
from core import secure_message as sm
from demo import file_signer

REAL = os.environ.get("REAL") == "1"
KEYSIZE = 2048 if REAL else 512
OAEP_KEYSIZE = max(KEYSIZE, 1024)


class TestSecureMessage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.a_priv, cls.a_pub = generate_keypair(keysize=OAEP_KEYSIZE)
        cls.b_priv, cls.b_pub = generate_keypair(keysize=OAEP_KEYSIZE)
        cls.keys = {"Thu Trang": cls.a_pub}.get

    def test_keystream_is_involution(self):
        k, n, data = os.urandom(32), os.urandom(12), os.urandom(1000)
        ct = sm.keystream_xor(k, n, data)
        self.assertNotEqual(ct, data)
        self.assertEqual(sm.keystream_xor(k, n, ct), data)

    def test_seal_open(self):
        env = sm.seal("Bí mật", "Thu Trang", self.a_priv, "Thu Thủy", self.b_pub)
        self.assertNotIn("Bí mật".encode().hex(), str(env))
        self.assertNotIn("Thu Trang", str(env))                    # danh tính người gửi được giấu
        r = sm.open_sealed(env, "Thu Thủy", self.b_priv, self.keys)
        self.assertEqual((r["message"].decode(), r["sender"]), ("Bí mật", "Thu Trang"))

    def test_tamper_each_field(self):
        env = sm.seal(b"x" * 100, "Thu Trang", self.a_priv, "Thu Thủy", self.b_pub)
        for field in ("ct", "tag", "nonce", "ek"):
            bad = dict(env)
            raw = bytearray(bad[field].encode())
            # '0'/'1' đổi giá trị thật sự cả với hex lẫn base64 (thay 'a' bằng 'A' thì hex không đổi)
            raw[5] = ord("0") if raw[5] != ord("0") else ord("1")
            bad[field] = raw.decode()
            with self.assertRaises(sm.SecureMessageError, msg=field):
                sm.open_sealed(bad, "Thu Thủy", self.b_priv, self.keys)

    def test_wrong_recipient_and_forwarding(self):
        c_priv, c_pub = generate_keypair(keysize=OAEP_KEYSIZE)
        env = sm.seal("cho Thu Thủy".encode(), "Thu Trang", self.a_priv, "Thu Thủy", self.b_pub)
        with self.assertRaises(sm.SecureMessageError):
            sm.open_sealed(env, "Tuyết Linh", c_priv, self.keys)
        fwd = sm.encrypt_for(sm.decrypt_envelope(env, self.b_priv), "Tuyết Linh", c_pub)
        with self.assertRaisesRegex(sm.SecureMessageError, "chuyển tiếp"):
            sm.open_sealed(fwd, "Tuyết Linh", c_priv, self.keys)

    def test_impersonation(self):
        e_priv, _ = generate_keypair(keysize=OAEP_KEYSIZE)
        env = sm.seal(b"gia", "Thu Trang", e_priv, "Thu Thủy", self.b_pub)
        with self.assertRaisesRegex(sm.SecureMessageError, "KHÔNG hợp lệ"):
            sm.open_sealed(env, "Thu Thủy", self.b_priv, self.keys)
        with self.assertRaises(sm.SecureMessageError):          # người gửi không có trong danh bạ tin cậy
            sm.open_sealed(sm.seal(b"x", "Mallory", e_priv, "Thu Thủy", self.b_pub), "Thu Thủy", self.b_priv, self.keys)


class TestRealFiles(unittest.TestCase):
    def test_sign_verify_real_file_and_tamper(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "anh.bin")
            with open(path, "wb") as f:
                f.write(os.urandom(5000))                # dữ liệu nhị phân giả làm ảnh
            r = file_signer.demo_sign_file(path=path, keysize=KEYSIZE, workdir=tmp, verbose=False)
            self.assertTrue(r["valid_original"])
            self.assertFalse(r["valid_tampered"])
            priv = file_signer.load_private_key(os.path.join(tmp, "thutrang.private.json"))
            pub = file_signer.load_public_key(os.path.join(tmp, "thutrang.public.json"))
            self.assertEqual(priv[1], pub[1])
            self.assertTrue(file_signer.verify_file(path, pub, r["sig_path"])[0])

    def test_seal_open_real_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "hop_dong.txt")
            with open(path, "wb") as f:
                f.write("Hợp đồng mua bán\n".encode() * 300 + os.urandom(1000))
            r = file_signer.demo_seal_file(path=path, keysize=OAEP_KEYSIZE, workdir=tmp, verbose=False)
            self.assertTrue(r["restored_equal"])
            self.assertTrue(r["eve_blocked"])
            self.assertEqual(r["sender"], "Thu Trang")

    def test_password_protected_private_key(self):
        priv, pub = generate_keypair(keysize=KEYSIZE)
        with tempfile.TemporaryDirectory() as tmp:
            priv_path, _ = file_signer.save_keypair("k", priv, pub, tmp, password="dung-mat-khau")
            with open(priv_path, encoding="utf-8") as f:
                self.assertNotIn(hex(priv[0]), f.read())            # d không nằm trần trong tệp
            self.assertEqual(file_signer.load_private_key(priv_path, password="dung-mat-khau"), priv)
            with self.assertRaises(ValueError):
                file_signer.load_private_key(priv_path, password="sai")


if __name__ == "__main__":
    unittest.main(verbosity=2)
