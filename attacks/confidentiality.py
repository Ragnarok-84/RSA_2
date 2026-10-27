"""
attacks/confidentiality.py
[Bổ sung - TÍNH BẢO MẬT] Tấn công vào mã hóa RSA và cách kết hợp chữ ký với mã hóa:
  1. Tấn công từ điển vào RSA sách giáo khoa (mã hóa tất định)          -> OAEP chặn
  2. Rò rỉ khi "ký song song mã hóa": Enc(M) || Sign(M)                 -> ký rồi mã hóa chặn
  3. Håstad broadcast (e = 3, cùng bản rõ gửi 3 người)                  -> OAEP chặn
  4. Dùng CHUNG một cặp khóa cho ký và giải mã: "nhờ ký" = giải mã hộ   -> tách khóa (key_usage)
"""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.rsa_math import (generate_keypair, mod_inverse, mod_exp, int_to_bytes, bytes_to_int,
                           integer_cuberoot_ceil)
from core.rsa_full import (sign_message, verify_message, textbook_encrypt, oaep_encrypt, oaep_decrypt)


def _say(verbose):
    return print if verbose else (lambda *a, **k: None)


# 1. Tấn công từ điển ------------------------------------------------
def attack_textbook_dictionary(public_key, ciphertext, candidates):
    """Mã hóa thử từng ứng viên bằng khóa CÔNG KHAI, so sánh với bản mã. :return: bản rõ hoặc None"""
    for cand in candidates:
        if textbook_encrypt(bytes_to_int(cand.encode("utf-8")), public_key) == ciphertext:
            return cand
    return None


def attack_oaep_dictionary(public_key, ciphertext, candidates, tries=3):
    """Cùng chiến thuật với OAEP: mã hóa lại ứng viên -> bản mã không bao giờ trùng."""
    for cand in candidates:
        for _ in range(tries):
            if oaep_encrypt(cand, public_key) == ciphertext:
                return cand
    return None


def demo_dictionary(keysize=1024, verbose=True):
    say = _say(verbose)
    priv, pub = generate_keypair(keysize=keysize)
    candidates = ["DONG Y", "KHONG DONG Y", "PHIEU TRANG"]
    secret = "KHONG DONG Y"
    say(f"[1] Bob gửi phiếu bầu mật cho Alice. Tập phiếu chỉ có: {candidates}")
    c_text = textbook_encrypt(bytes_to_int(secret.encode()), pub)
    found_text = attack_textbook_dictionary(pub, c_text, candidates)
    say(f"[2] RSA sách giáo khoa: Eve mã hóa thử 3 ứng viên bằng khóa công khai -> tìm được '{found_text}'")
    c_oaep = oaep_encrypt(secret, pub)
    found_oaep = attack_oaep_dictionary(pub, c_oaep, candidates)
    say(f"[3] RSA-OAEP: bản mã ngẫu nhiên hóa, Eve thử lại -> {found_oaep!r} (không tìm được)")
    say(f"    Alice vẫn giải mã đúng: '{oaep_decrypt(c_oaep, priv).decode()}'")
    return found_text == secret, found_oaep is None


# 2. Ký song song mã hóa ---------------------------------------------
def attack_encrypt_and_sign_leak(signature, sender_public_key, candidates):
    """Chữ ký gửi kèm ở dạng rõ: ai cũng kiểm tra được chữ ký với từng ứng viên -> đoán ra M."""
    for cand in candidates:
        if verify_message(cand, signature, sender_public_key):
            return cand
    return None


def demo_encrypt_and_sign_leak(keysize=1024, verbose=True):
    say = _say(verbose)
    a_priv, a_pub = generate_keypair(keysize=keysize)
    _, b_pub = generate_keypair(keysize=keysize)
    candidates = ["MUA 1000 CO PHIEU", "BAN 1000 CO PHIEU", "GIU NGUYEN"]
    secret = "BAN 1000 CO PHIEU"
    oaep_encrypt(secret, b_pub)                           # nội dung mã hóa đúng chuẩn OAEP...
    s = sign_message(secret, a_priv)                      # ...nhưng chữ ký gửi kèm ở dạng rõ
    say("[1] Alice gửi Bob: OAEP-Encrypt(M) || Sign(M)  (ký SONG SONG mã hóa)")
    found = attack_encrypt_and_sign_leak(s, a_pub, candidates)
    say(f"[2] Eve không giải mã được C, nhưng kiểm tra chữ ký với từng lệnh có thể -> M = '{found}'")
    say("[!] Phòng chống: KÝ RỒI MÃ HÓA cả chữ ký (core/secure_message.seal) — chữ ký nằm trong bản mã.")
    return found == secret


# 3. Håstad broadcast ------------------------------------------------
def attack_hastad_broadcast(ciphertexts, moduli):
    """Ghép 3 bản mã bằng định lý số dư Trung Hoa -> M^3 (không mod) -> lấy căn bậc ba."""
    N = 1
    for n in moduli:
        N *= n
    x = 0
    for c, n in zip(ciphertexts, moduli):
        Ni = N // n
        x += c * Ni * mod_inverse(Ni, n)
    x %= N
    m = integer_cuberoot_ceil(x)
    return m if m ** 3 == x else None


def demo_hastad(keysize=1024, verbose=True):
    say = _say(verbose)
    secret = "Mat khau kho bac: 7749-ATBM-2026-XYZ-quy-tien-mat"   # 49 byte: M^3 > N, không lấy căn trực tiếp
    m = bytes_to_int(secret.encode())
    pubs = [generate_keypair(keysize=keysize, e=3)[1] for _ in range(3)]
    cs = [textbook_encrypt(m, pub) for pub in pubs]
    say("[1] Alice gửi CÙNG một bí mật cho 3 người, mỗi người dùng e = 3, RSA sách giáo khoa")
    rec = attack_hastad_broadcast(cs, [p[1] for p in pubs])
    text = int_to_bytes(rec, (rec.bit_length() + 7) // 8).decode() if rec else None
    say(f"[2] Eve nghe lén 3 bản mã, dùng CRT + căn bậc ba -> '{text}' (không cần khóa riêng nào)")
    oaep_cs = [bytes_to_int(oaep_encrypt(secret, pub)) for pub in pubs]
    rec2 = attack_hastad_broadcast(oaep_cs, [p[1] for p in pubs])
    say(f"[3] Với OAEP mỗi bản rõ đã đệm ngẫu nhiên khác nhau -> tấn công trả về {rec2!r}")
    return text == secret, rec2 is None


# 4. Dùng chung khóa ký và giải mã -----------------------------------
def demo_same_key_sign_decrypt(keysize=512, verbose=True):
    """
    Alice dùng MỘT cặp khóa vừa để nhận thư mật vừa để ký (dịch vụ ký RSA thô).
    Eve chặn được C = M^e. Eve "làm mù" C' = C * r^e, nhờ Alice ký C' -> S = C'^d = M*r -> M = S/r.
    """
    say = _say(verbose)
    priv, pub = generate_keypair(keysize=keysize)
    e, n = pub
    secret = bytes_to_int("Ma OTP: 403912".encode())
    c = mod_exp(secret, e, n)
    say("[1] Bob gửi Alice bản mã C (RSA thô) — Eve chặn được C nhưng không giải được")
    r = 1234567
    c_blind = (c * mod_exp(r, e, n)) % n
    say("[2] Eve gửi C' = C * r^e mod N cho Alice, nhờ 'ký xác nhận' (C' trông như số ngẫu nhiên)")
    s = mod_exp(c_blind, priv[0], n)                       # Alice ký bằng CHÍNH khóa giải mã
    m = (s * mod_inverse(r, n)) % n
    text = int_to_bytes(m, (m.bit_length() + 7) // 8).decode(errors="replace")
    say(f"[3] Eve tính S * r^-1 mod N = '{text}' — chữ ký đã giải mã giúp Eve")
    say("[!] Phòng chống: tách khóa ký / khóa mã hóa (key_usage trong chứng thư); ký trên băm có đệm.")
    return m == secret


if __name__ == "__main__":
    for fn in (demo_dictionary, demo_encrypt_and_sign_leak, demo_hastad, demo_same_key_sign_decrypt):
        print(f"\n--- {fn.__name__} ---")
        fn()
