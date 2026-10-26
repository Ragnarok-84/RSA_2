"""
attacks/attacks.py
Mô phỏng các tấn công vào RSA (chỉ để học tập, chạy trên khóa tự sinh trong máy):
1. Phân tích modulus N nhỏ (Small Modulus Factorization)
2. Giả mạo chữ ký RSA không dùng đệm (No-padding Signature Forgery)
3. Giả mạo chữ ký kiểu Bleichenbacher với e = 3 khi bên xác thực kiểm tra đệm lỏng lẻo
"""
import math
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from sha256 import hash_sha256
from math_utils import mod_inverse, mod_exp
from rsa_core import SHA256_PREFIX, HASH_LEN
import rsa_core


# ------------------------------------------------------------------
# 1. Phân tích N nhỏ
# ------------------------------------------------------------------
def attack_small_n(n):
    """
    Phân tích thừa số nguyên tố bằng chia thử (Trial Division).
    :return: (p, q) hoặc None nếu không tìm thấy (n nguyên tố / quá nhỏ)
    """
    if n < 4:
        return None
    if n % 2 == 0:
        return 2, n // 2
    for i in range(3, math.isqrt(n) + 1, 2):
        if n % i == 0:
            return i, n // i
    return None


def recover_private_key(e, n):
    """Sau khi phân tích được N=p*q, kẻ tấn công tính lại khóa riêng d."""
    factors = attack_small_n(n)
    if factors is None:
        return None
    p, q = factors
    return mod_inverse(e, (p - 1) * (q - 1)), p, q


# ------------------------------------------------------------------
# 2. Giả mạo chữ ký không đệm (tính nhân tính của RSA)
# ------------------------------------------------------------------
def attack_no_padding_forgery(public_key, s1, s2):
    """
    (m1^d)(m2^d) = (m1*m2)^d mod n  =>  từ chữ ký s1 của m1 và s2 của m2,
    kẻ tấn công tạo chữ ký s3 = s1*s2 mod n hợp lệ cho m3 = m1*m2 mod n
    mà KHÔNG cần khóa riêng.  (Chỉ xảy ra khi KHÔNG băm/đệm.)
    """
    _, n = public_key
    return (s1 * s2) % n


# ------------------------------------------------------------------
# 3. Bleichenbacher e = 3 (bên xác thực kiểm tra đệm lỏng lẻo)
# ------------------------------------------------------------------
def lenient_verify(message, signature, public_key):
    """
    BÊN XÁC THỰC CÓ LỖI (nạn nhân của tấn công): chỉ kiểm tra 00 01 FF.. 00 DigestInfo
    rồi lấy 32 byte băm, BỎ QUA các byte thừa phía sau.
    (rsa_core.verify_message là bản kiểm tra chặt, không bị lỗi này.)
    """
    e, n = public_key
    k = (n.bit_length() + 7) // 8
    em = mod_exp(signature, e, n).to_bytes(k, "big")
    if em[0] != 0x00 or em[1] != 0x01:
        return False
    i = 2
    while i < k and em[i] == 0xFF:
        i += 1
    if i >= k or em[i] != 0x00:
        return False
    i += 1
    if em[i:i + len(SHA256_PREFIX)] != SHA256_PREFIX:
        return False
    i += len(SHA256_PREFIX)
    return em[i:i + HASH_LEN].hex() == hash_sha256(message)   # byte thừa phía sau bị bỏ qua


def integer_cuberoot_ceil(x):
    """Căn bậc ba nguyên làm tròn lên (Newton, không dùng float nên không tràn số)."""
    if x < 2:
        return x
    r = 1 << ((x.bit_length() + 2) // 3 + 1)
    while True:
        nr = (2 * r + x // (r * r)) // 3
        if nr >= r:
            break
        r = nr
    while r ** 3 < x:
        r += 1
    while (r - 1) ** 3 >= x:
        r -= 1
    return r


def attack_bleichenbacher_e3(public_key, target_hash_hex):
    """
    Tạo chữ ký giả mà KHÔNG cần khóa riêng, khi e = 3 và bên xác thực dùng lenient_verify.

    Ý tưởng: dựng EM = 00 01 FF 00 || DigestInfo || hash || (byte rác), rồi lấy
    s = ceil(căn bậc 3 của EM_với_rác_bằng_0). Vì s^3 chỉ lệch EM một lượng nhỏ nằm gọn
    trong phần byte rác nên s^3 (không cần mod n, do s^3 < n) vẫn bắt đầu bằng phần đầu hợp lệ.
    Điều kiện: N đủ lớn (với SHA-256 cần N >= ~1328 bit).
    """
    e, n = public_key
    if e != 3:
        raise ValueError("Tấn công Bleichenbacher này yêu cầu số mũ công khai e = 3!")

    hash_bytes = bytes.fromhex(target_hash_hex)
    head = b"\x00\x01\xff\x00" + SHA256_PREFIX + hash_bytes
    k = (n.bit_length() + 7) // 8
    garbage_len = k - len(head)
    if garbage_len <= 0:
        raise ValueError("Modulus quá nhỏ để chứa cấu trúc đệm SHA-256")

    target = int.from_bytes(head + b"\x00" * garbage_len, "big")
    s = integer_cuberoot_ceil(target)
    forged_em = (s ** 3).to_bytes(k, "big") if s ** 3 < (1 << (8 * k)) else b""
    if s ** 3 >= n or not forged_em.startswith(head):
        raise ValueError("Modulus quá nhỏ: phần byte rác không đủ chứa sai số (cần N >= ~1328 bit)")
    return s


# ------------------------------------------------------------------
# Demo (dùng cho CLI và test_all)
# ------------------------------------------------------------------
def demo_small_n(n=3233, e=17, verbose=True):
    say = print if verbose else (lambda *a, **k: None)
    res = recover_private_key(e, n)
    if res is None:
        say(f"[Kết quả] Không phân tích được n = {n}")
        return None
    d, p, q = res
    say(f"[+] Phân tích n = {n}: p = {p}, q = {q}")
    say(f"[+] Tính lại khóa riêng: d = e^-1 mod (p-1)(q-1) = {d}")
    return p, q, d


def demo_no_padding_forgery(verbose=True):
    """Dùng khóa nhỏ (e=17, n=3233) và RSA 'sách giáo khoa' (không băm, không đệm)."""
    say = print if verbose else (lambda *a, **k: None)
    from keygen import generate_keypair
    priv, pub = generate_keypair(p=61, q=53, e=17)
    d, n = priv
    e, _ = pub
    m1, m2 = 7, 11
    s1, s2 = pow(m1, d, n), pow(m2, d, n)             # hai chữ ký hợp lệ mà kẻ tấn công thu được
    s3 = attack_no_padding_forgery(pub, s1, s2)       # kẻ tấn công KHÔNG biết d
    m3 = (m1 * m2) % n
    ok = pow(s3, e, n) == m3
    say(f"[+] Có chữ ký của m1={m1}: s1={s1};  của m2={m2}: s2={s2}")
    say(f"[+] Kẻ tấn công tính s3 = s1*s2 mod n = {s3}")
    say(f"[+] Xác thực s3 cho m3 = m1*m2 = {m3}: {'HỢP LỆ (bị giả mạo thành công!)' if ok else 'không hợp lệ'}")
    say("[=] Phòng thủ: luôn BĂM + ĐỆM trước khi ký (rsa_core.sign_message).")
    return ok


def demo_bleichenbacher(keysize=2048, verbose=True):
    say = print if verbose else (lambda *a, **k: None)
    from keygen import generate_keypair
    say(f"[+] Sinh khóa RSA-{keysize} với e = 3 (có thể mất vài giây)...")
    _, pub = generate_keypair(keysize=keysize, e=3)
    message = "Alice chuyen 500 trieu cho Mallory"
    forged = attack_bleichenbacher_e3(pub, hash_sha256(message))
    lenient = lenient_verify(message, forged, pub)
    strict = rsa_core.verify_message(message, forged, pub)
    say(f"[+] Chữ ký giả (không cần khóa riêng): {hex(forged)[:30]}...")
    say(f"[+] Bên xác thực LỎNG LẺO chấp nhận : {lenient}")
    say(f"[+] Bên xác thực CHẶT (rsa_core)     : {strict}")
    say("[=] Phòng thủ: kiểm tra đệm chặt (không byte thừa), dùng e = 65537, khóa >= 2048 bit.")
    return lenient, strict


if __name__ == "__main__":
    print("=== DEMO ATTACKS MODULE ===")
    print("\n-- 1. Phân tích N nhỏ --")
    demo_small_n()
    print("\n-- 2. Giả mạo chữ ký không đệm --")
    demo_no_padding_forgery()
    print("\n-- 3. Bleichenbacher e=3 --")
    demo_bleichenbacher(keysize=1536)
