"""
attacks/bleichenbacher_e3.py
[Báo cáo 3.6 - Độ an toàn; 6.4 - Tấn công minh họa]
Tấn công kiểu Bleichenbacher 2006 với e = 3 vào bộ kiểm tra đệm PKCS#1 v1.5 LỎNG LẺO.

Bộ kiểm tra lỏng chỉ đọc 00 01 FF.. 00 DigestInfo H rồi bỏ qua phần còn lại. Kẻ tấn công dựng
khối 00 01 FF 00 DigestInfo H || rác, lấy căn bậc ba nguyên s. Vì s^3 < N nên s^3 mod N = s^3:
phần đầu giữ nguyên, chỉ phần "rác" thay đổi -> chữ ký giả được chấp nhận mà không cần khóa riêng.
"""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.rsa_math import generate_keypair, mod_exp, byte_length, int_to_bytes, bytes_to_int, integer_cuberoot_ceil
from core.sha256 import hash_sha256
from core.padding import SHA256_DIGEST_INFO, HASH_LEN
from core.rsa_full import verify_message


def lenient_verify(message, signature, public_key):
    """
    Bộ kiểm tra LỎNG LẺO (có lỗi, như nhiều thư viện trước 2006): chỉ kiểm tra 00 01, bỏ qua các
    byte FF, gặp 00, so DigestInfo rồi lấy 32 byte kế tiếp làm hash — KHÔNG kiểm tra phần còn lại.
    """
    e, n = public_key
    k = byte_length(n)
    em = int_to_bytes(mod_exp(signature, e, n), k)
    if em[:2] != b"\x00\x01":
        return False
    i = 2
    while i < k and em[i] == 0xFF:
        i += 1
    if i >= k or em[i] != 0:
        return False
    i += 1
    if em[i:i + len(SHA256_DIGEST_INFO)] != SHA256_DIGEST_INFO:
        return False
    i += len(SHA256_DIGEST_INFO)
    return em[i:i + HASH_LEN].hex() == hash_sha256(message)


def attack_bleichenbacher_e3(public_key, target_hash_hex):
    """Tạo chữ ký giả cho giá trị băm `target_hash_hex` mà không cần khóa riêng."""
    e, n = public_key
    if e != 3:
        raise ValueError("Tấn công Bleichenbacher này yêu cầu số mũ công khai e = 3!")
    prefix = b"\x00\x01\xff\x00" + SHA256_DIGEST_INFO + bytes.fromhex(target_hash_hex)
    k = byte_length(n)
    garbage = k - len(prefix)
    if garbage <= 0:
        raise ValueError("Modulus n quá nhỏ để chứa cấu trúc đệm")
    s = integer_cuberoot_ceil(bytes_to_int(prefix + b"\x00" * garbage))
    if s ** 3 >= n or int_to_bytes(s ** 3, k)[:len(prefix)] != prefix:
        raise ValueError("Modulus n quá nhỏ: phần rác không đủ chỗ để căn bậc ba giữ nguyên phần đầu "
                         "(cần N khoảng >= 1328 bit)")
    return s


def demo_bleichenbacher(keysize=2048, verbose=True):
    say = print if verbose else (lambda *a, **k: None)
    _, pub = generate_keypair(keysize=keysize, e=3)
    msg = "Thu Trang chuyển toàn bộ tài sản cho Mai Phương"
    say(f"[1] Khóa công khai của Thu Trang dùng e = 3, N {keysize} bit. Mai Phương muốn giả chữ ký cho:\n    '{msg}'")
    s = attack_bleichenbacher_e3(pub, hash_sha256(msg))
    lenient = lenient_verify(msg, s, pub)
    strict = verify_message(msg, s, pub)
    say(f"[2] Mai Phương tính căn bậc ba nguyên -> chữ ký giả S = {hex(s)[:30]}...")
    say("[3] Bộ kiểm tra LỎNG LẺO : " + ("CHẤP NHẬN (bị lừa)" if lenient else "từ chối"))
    say("[4] core/padding.parse_em_strict (kiểm tra CHẶT toàn bộ EM): " + ("chấp nhận" if strict else "TỪ CHỐI"))
    say("[!] Phòng chống: kiểm tra đệm chặt từng byte; dùng e = 65537.")
    return lenient, strict


if __name__ == "__main__":
    demo_bleichenbacher()
