"""
attacks/forgery_no_padding.py
[Báo cáo 3.6 - Độ an toàn; 6.4 - Tấn công minh họa]
Giả mạo chữ ký khi KHÔNG có đệm (RSA sách giáo khoa S = M^d mod N).
  1. Giả mạo nhân tính: (M1^d) * (M2^d) = (M1*M2)^d mod N
     -> từ 2 chữ ký thật S1, S2, kẻ tấn công tạo được chữ ký S3 = S1*S2 cho M3 = M1*M2 mà không cần khóa riêng.
  2. Giả mạo tồn tại: chọn S bất kỳ, tính M = S^e mod N -> (M, S) là cặp hợp lệ, không cần chữ ký thật nào.
"""
import os
import secrets
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.rsa_math import generate_keypair, mod_exp
from core.rsa_full import sign_message, verify_message, verify_signature


def attack_no_padding_forgery(public_key, s1, s2):
    """Tạo chữ ký cho M1*M2 từ chữ ký của M1 và M2."""
    e, n = public_key
    return (s1 * s2) % n


def demo_no_padding_forgery(keysize=512, verbose=True):
    say = print if verbose else (lambda *a, **k: None)
    priv, pub = generate_keypair(keysize=keysize)
    d, n = priv
    m1, m2 = 2, 50_000_000                  # "Đồng ý trả 2 đồng", "trả 50 triệu"
    s1, s2 = mod_exp(m1, d, n), mod_exp(m2, d, n)
    say(f"[1] Thu Trang ký (không băm/đệm) M1 = {m1} và M2 = {m2}")
    s3 = attack_no_padding_forgery(pub, s1, s2)
    ok = mod_exp(s3, pub[0], n) == (m1 * m2) % n
    say("[2] Mai Phương nhân hai chữ ký: S3 = S1*S2 mod N, chưa từng hỏi Thu Trang")
    say(f"[3] Kiểm tra S3 với M3 = M1*M2 = {m1 * m2}: " + ("HỢP LỆ -> giả mạo thành công" if ok else "sai"))
    say("[!] Phòng chống: ký trên SHA-256(M) có đệm PKCS#1/PSS (core/padding.py) — tích hai khối "
        "đệm không còn là khối đệm hợp lệ.")
    return ok


def padding_blocks_forgery(keysize=512):
    """Với chữ ký có đệm, S1*S2 không phải chữ ký hợp lệ của bất kỳ thông điệp nào trong số thử."""
    priv, pub = generate_keypair(keysize=keysize)
    s3 = attack_no_padding_forgery(pub, sign_message("a", priv), sign_message("b", priv))
    return not any(verify_message(m, s3, pub) for m in ("a", "b", "ab"))


def attack_existential_forgery(public_key):
    """Chọn S ngẫu nhiên, tính M = S^e mod N. :return: (M, S)"""
    e, n = public_key
    s = secrets.randbelow(n - 2) + 2
    return mod_exp(s, e, n), s


def demo_existential_forgery(keysize=512, tries=1000, verbose=True):
    """:return: (giả được với RSA thuần, không S ngẫu nhiên nào qua được kiểm tra có đệm)"""
    say = print if verbose else (lambda *a, **k: None)
    _, pub = generate_keypair(keysize=keysize)
    m, s = attack_existential_forgery(pub)
    ok = mod_exp(s, pub[0], pub[1]) == m
    say("[1] Mai Phương CHƯA thấy chữ ký nào của Thu Trang. Mai Phương chọn S ngẫu nhiên rồi tính M = S^e mod N.")
    say(f"    M = {hex(m)[:34]}..., S = {hex(s)[:34]}...")
    say(f"[2] Bộ kiểm tra RSA thuần (S^e mod N == M?): {'HỢP LỆ -> giả mạo thành công' if ok else 'sai'}")
    say("    (M là chuỗi byte vô nghĩa, nhưng nếu M chỉ cần là một số tiền / mã giao dịch thì đã đủ gây hại)")
    padded_hits = sum(verify_signature(attack_existential_forgery(pub)[1], pub) is not None for _ in range(tries))
    say(f"[3] Có băm + đệm PKCS#1 v1.5: thử {tries} giá trị S ngẫu nhiên, số S cho khối đệm hợp lệ = {padded_hits}")
    say("    (xác suất ~2^-(độ dài N - 256) / lần, và còn phải tìm được M có SHA-256 khớp)")
    say("[!] Phòng chống: luôn ký trên SHA-256(M) có đệm; bộ kiểm tra so khớp TOÀN BỘ khối đệm.")
    return ok, padded_hits == 0


if __name__ == "__main__":
    demo_no_padding_forgery()
    demo_existential_forgery()
