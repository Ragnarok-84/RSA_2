"""
attacks/small_n.py
[Báo cáo 3.6 - Độ an toàn; 6.4 - Tấn công minh họa]
Tấn công phân tích thừa số modulus N nhỏ (Small Modulus Factorization).
Biết p, q -> tính lại phi(N) và d -> kẻ tấn công ký giả được MỌI văn bản của chủ khóa.
"""
import math
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.rsa_math import mod_inverse, mod_exp


def attack_small_n(n):
    """
    Phân tích n bằng chia thử (Trial Division), độ phức tạp O(sqrt(n)).
    N 2048 bit cần ~2^1024 phép chia -> bất khả thi; N nhỏ bị phá ngay.
    :return: (p, q) hoặc None nếu n nguyên tố
    """
    if n % 2 == 0:
        return 2, n // 2
    limit = math.isqrt(n) + 1
    for i in range(3, limit, 2):
        if n % i == 0:
            return i, n // i
    return None


def recover_private_key(e, n):
    """Phân tích n rồi tính lại d = e^-1 mod phi(n). :return: (d, p, q)"""
    res = attack_small_n(n)
    if not res:
        raise ValueError("Không phân tích được n")
    p, q = res
    return mod_inverse(e, (p - 1) * (q - 1)), p, q


def demo_small_n(n=3233, e=17, verbose=True):
    """Phá khóa (e, n) rồi giả một chữ ký thô lên thông điệp tùy chọn."""
    say = print if verbose else (lambda *a, **k: None)
    d, p, q = recover_private_key(e, n)
    say(f"[1] Khóa công khai (e, N) = ({e}, {n})")
    say(f"[2] Chia thử -> p = {p}, q = {q}; phi = {(p - 1) * (q - 1)}; d = {d}")
    m = 1234 % n
    s = mod_exp(m, d, n)
    ok = mod_exp(s, e, n) == m
    say(f"[3] Mai Phương ký giả M = {m}: S = {s}; kiểm tra bằng khóa công khai: {'HỢP LỆ' if ok else 'sai'}")
    say("[!] Phòng chống: N >= 2048 bit (NIST SP 800-57), p và q sinh ngẫu nhiên bằng CSPRNG.")
    return ok


if __name__ == "__main__":
    demo_small_n()
