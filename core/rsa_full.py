# Tệp: core/rsa_full.py
# [Báo cáo 2.2 - Bộ năm (P, A, K, S, V); 3.2 - Sinh khóa, ký, kiểm tra]
# Hệ chữ ký điện tử RSA BẢN ĐẦY ĐỦ (khóa >= 2048 bit), ký trên giá trị băm SHA-256.
#
#   P : tập thông điệp (chuỗi byte bất kỳ, độ dài tùy ý — vì ký trên SHA-256(M))
#   A : tập chữ ký = Z_N
#   K : tập khóa  = {(N, e, d) : N = p*q, e*d ≡ 1 mod phi(N)}  — sinh bởi generate_keypair
#   S : Sig_d(M) = Pad(SHA256(M))^d mod N
#   V : Ver_e(M, S) = True  <=>  S^e mod N là khối đệm hợp lệ của SHA256(M)
#
# Hai lược đồ đệm (core/padding.py): "pkcs1v15" (mặc định, tất định) và "pss" (ngẫu nhiên hóa).
# Bổ sung TÍNH BẢO MẬT: mã hóa / giải mã RSA-OAEP (chữ ký không che giấu nội dung).
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.sha256 import hash_sha256
from core.rsa_math import (generate_keypair, mod_exp, compare_hashes, byte_length,  # noqa: F401
                           int_to_bytes, bytes_to_int)
from core.padding import (add_pkcs1_v15_padding, parse_em_strict, pss_encode, pss_verify,  # noqa: F401
                          oaep_encode, oaep_decode, oaep_max_length, DecodingError,
                          SHA256_DIGEST_INFO, HASH_LEN)

SCHEMES = ("pkcs1v15", "pss")


class DecryptionError(DecodingError):
    """Giải mã OAEP thất bại (sai khóa, sai nhãn hoặc bản mã bị sửa)."""


# ------------------------------------------------------------------ #
# S: KÝ
# ------------------------------------------------------------------ #
def sign_hash(hash_value, private_key, scheme="pkcs1v15"):
    """Ký trên một giá trị băm có sẵn (hex). Dùng khi băm tệp lớn theo từng khối."""
    d, N = private_key
    if scheme == "pkcs1v15":
        em_int = add_pkcs1_v15_padding(hash_value, byte_length(N))
    elif scheme == "pss":
        em_int = bytes_to_int(pss_encode(bytes.fromhex(hash_value), N.bit_length() - 1))
    else:
        raise ValueError(f"scheme phải thuộc {SCHEMES}")
    return mod_exp(em_int, d, N)                    # S = EM^d mod N


def sign_message(message, private_key, scheme="pkcs1v15"):
    """
    Ký số hoàn chỉnh: Băm SHA-256 -> Đệm -> Lũy thừa bằng khóa riêng.
    :param message: Thông điệp (str hoặc bytes)
    :param private_key: Khóa riêng (d, N)
    :return: Chữ ký số S dạng số nguyên
    """
    return sign_hash(hash_sha256(message), private_key, scheme)


# ------------------------------------------------------------------ #
# V: KIỂM TRA
# ------------------------------------------------------------------ #
def verify_signature(signature, public_key):
    """
    (PKCS#1 v1.5) Gỡ chữ ký số để lấy bản băm B.
    :return: Bản băm B (hex) hoặc None nếu chữ ký không đúng định dạng
    """
    e, N = public_key
    if not isinstance(signature, int) or not 0 < signature < N:   # RFC 8017: 0 <= s < N
        return None
    return parse_em_strict(int_to_bytes(mod_exp(signature, e, N), byte_length(N)))


def verify_hash(hash_value, signature, public_key, scheme="pkcs1v15"):
    """Kiểm tra chữ ký trên một giá trị băm có sẵn."""
    if scheme == "pkcs1v15":
        return compare_hashes(hash_value, verify_signature(signature, public_key))
    if scheme == "pss":
        e, N = public_key
        if not isinstance(signature, int) or not 0 < signature < N:
            return False
        em_bits = N.bit_length() - 1
        m = mod_exp(signature, e, N)
        if m.bit_length() > em_bits:
            return False
        return pss_verify(bytes.fromhex(hash_value), int_to_bytes(m, (em_bits + 7) // 8), em_bits)
    raise ValueError(f"scheme phải thuộc {SCHEMES}")


def verify_message(message, signature, public_key, scheme="pkcs1v15"):
    """
    Kiểm tra chữ ký: bản băm A tự tính từ thông điệp nhận được, đối chiếu với chữ ký.
    :return: True (hợp lệ) / False (bị sửa, sai khóa hoặc giả mạo)
    """
    return verify_hash(hash_sha256(message), signature, tuple(public_key), scheme)


def explain_sign(message, private_key, public_key):
    """Trả về dict các giá trị trung gian của quá trình ký/kiểm tra PKCS#1 v1.5 (để in khi thuyết trình)."""
    d, N = private_key
    k = byte_length(N)
    h = hash_sha256(message)
    em = int_to_bytes(add_pkcs1_v15_padding(h, k), k)
    s = sign_hash(h, private_key)
    em2 = int_to_bytes(mod_exp(s, public_key[0], N), k)
    return {"hash": h, "em": em.hex(), "signature": s, "em_recovered": em2.hex(),
            "hash_recovered": parse_em_strict(em2), "valid": verify_message(message, s, public_key)}


# ------------------------------------------------------------------ #
# Bổ sung TÍNH BẢO MẬT: mã hóa RSA
# ------------------------------------------------------------------ #
def textbook_encrypt(m, public_key):
    """RSA sách giáo khoa C = M^e mod N — TẤT ĐỊNH, chỉ để minh họa và so sánh."""
    e, N = public_key
    if not 0 <= m < N:
        raise ValueError("Bản rõ phải thỏa 0 <= M < N")
    return mod_exp(m, e, N)


def textbook_decrypt(c, private_key):
    """M = C^d mod N"""
    d, N = private_key
    return mod_exp(c, d, N)


def max_message_length(public_key):
    return oaep_max_length(byte_length(public_key[1]))


def oaep_encrypt(message, public_key, label=b""):
    """
    Mã hóa RSA-OAEP: C = OAEP(M)^e mod N (bằng khóa công khai của NGƯỜI NHẬN).
    :return: bản mã dạng bytes, dài đúng k byte
    """
    if isinstance(message, str):
        message = message.encode("utf-8")
    e, N = public_key
    k = byte_length(N)
    return int_to_bytes(mod_exp(bytes_to_int(oaep_encode(message, k, label)), e, N), k)


def oaep_decrypt(ciphertext, private_key, label=b""):
    """Giải mã RSA-OAEP: M = OAEP^-1(C^d mod N)."""
    d, N = private_key
    k = byte_length(N)
    if len(ciphertext) != k or bytes_to_int(ciphertext) >= N:
        raise DecryptionError("Giải mã thất bại")
    try:
        return oaep_decode(int_to_bytes(mod_exp(bytes_to_int(ciphertext), d, N), k), k, label)
    except DecodingError:
        raise DecryptionError("Giải mã thất bại") from None


if __name__ == "__main__":
    priv, pub = generate_keypair(keysize=2048)
    r = explain_sign("Hợp đồng số 01/2026", priv, pub)
    print("SHA-256(M) :", r["hash"])
    print("EM         :", r["em"][:24], "...", r["em"][-80:])
    print("Chữ ký S   :", hex(r["signature"])[:40], "...")
    print("Hợp lệ     :", r["valid"])
    print("Sửa 1 ký tự:", verify_message("Hợp đồng số 02/2026", r["signature"], pub))
    s1, s2 = sign_message("x", priv, "pss"), sign_message("x", priv, "pss")
    print("PSS: 2 chữ ký khác nhau:", s1 != s2, "| đều hợp lệ:",
          verify_message("x", s1, pub, "pss") and verify_message("x", s2, pub, "pss"))
    c = oaep_encrypt("Bí mật", pub)
    print("OAEP giải mã:", oaep_decrypt(c, priv).decode())
