from __future__ import annotations

from core.utils import constant_time_eq

# DER của DigestInfo cho SHA-256 
DIGEST_INFO_SHA256 = bytes.fromhex("3031300d060960864801650304020105000420")
HASH_LEN = 32
MIN_PS_LEN = 8


def encode(message_hash: bytes, em_len: int) -> bytes:
    # EMSA-PKCS1-V1_5-ENCODE với giá trị băm SHA-256 đã tính sẵn
    if len(message_hash) != HASH_LEN:
        raise ValueError("Giá trị băm SHA-256 phải dài 32 byte")
    t = DIGEST_INFO_SHA256 + message_hash
    ps_len = em_len - len(t) - 3
    if ps_len < MIN_PS_LEN:
        raise ValueError("intended encoded message length too short: khoá quá ngắn cho PKCS#1 v1.5 + SHA-256 "
                         f"(cần emLen >= {len(t) + 3 + MIN_PS_LEN} byte)")
    return b"\x00\x01" + b"\xff" * ps_len + b"\x00" + t


def verify_strict(em: bytes, message_hash: bytes) -> bool:
    # Cách kiểm tra ĐÚNG: dựng lại EM từ giá trị băm rồi so sánh TOÀN BỘ 
    try:
        expected = encode(message_hash, len(em))
    except ValueError:
        return False
    return constant_time_eq(em, expected)


def verify_sloppy(em: bytes, message_hash: bytes) -> bool:
    # BỘ KIỂM TRA CÓ LỖI CỐ Ý — chỉ dùng cho attacks/a4_small_e_attack.py.
    # Mô phỏng lỗi của nhiều thư viện trước 2006 (Bleichenbacher, CRYPTO 2006 rump session)
    if em[:2] != b"\x00\x01":
        return False
    i = 2
    while i < len(em) and em[i] == 0xFF:
        i += 1
    if i >= len(em) or em[i] != 0x00:
        return False
    i += 1
    if em[i:i + len(DIGEST_INFO_SHA256)] != DIGEST_INFO_SHA256:
        return False
    i += len(DIGEST_INFO_SHA256)
    return em[i:i + HASH_LEN] == message_hash
