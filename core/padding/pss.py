"""EMSA-PSS (RFC 8017 §9.1) với SHA-256 và MGF1-SHA256.

Mã hoá (§9.1.1):
    M'  = 0x00×8 || mHash || salt,     H = SHA256(M')
    DB  = PS(0x00…) || 0x01 || salt
    maskedDB = DB ⊕ MGF1(H, emLen − hLen − 1), xoá 8·emLen − emBits bít cao nhất
    EM  = maskedDB || H || 0xBC
"""
from __future__ import annotations

import secrets

from core.hash.sha256 import sha256
from core.utils import constant_time_eq

HASH_LEN = 32


def mgf1(seed: bytes, mask_len: int) -> bytes:
    """MGF1 (RFC 8017 phụ lục B.2.1): T = SHA256(seed || C(0)) || SHA256(seed || C(1)) || … cắt còn mask_len byte."""
    out = bytearray()
    counter = 0
    while len(out) < mask_len:
        out += sha256(seed + counter.to_bytes(4, "big"))
        counter += 1
    return bytes(out[:mask_len])


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def encode(message_hash: bytes, em_bits: int, salt_len: int = 32, salt: bytes | None = None) -> bytes:
    """EMSA-PSS-ENCODE. Truyền `salt` cố định để kiểm thử tất định; mặc định salt ngẫu nhiên từ secrets."""
    em_len = (em_bits + 7) // 8
    if len(message_hash) != HASH_LEN:
        raise ValueError("Giá trị băm SHA-256 phải dài 32 byte")
    if em_len < HASH_LEN + salt_len + 2:
        raise ValueError("encoding error: khoá quá ngắn cho PSS với salt này")
    if salt is None:
        salt = secrets.token_bytes(salt_len)
    elif len(salt) != salt_len:
        raise ValueError("Độ dài salt không khớp salt_len")
    h = sha256(b"\x00" * 8 + message_hash + salt)
    db = b"\x00" * (em_len - salt_len - HASH_LEN - 2) + b"\x01" + salt
    masked_db = bytearray(_xor(db, mgf1(h, em_len - HASH_LEN - 1)))
    masked_db[0] &= 0xFF >> (8 * em_len - em_bits)
    return bytes(masked_db) + h + b"\xbc"


def verify(message_hash: bytes, em: bytes, em_bits: int, salt_len: int = 32) -> bool:
    """EMSA-PSS-VERIFY (RFC 8017 §9.1.2): True nếu EM nhất quán với giá trị băm."""
    em_len = (em_bits + 7) // 8
    if len(message_hash) != HASH_LEN or len(em) != em_len or em_len < HASH_LEN + salt_len + 2:
        return False
    if em[-1] != 0xBC:
        return False
    masked_db, h = em[:em_len - HASH_LEN - 1], em[em_len - HASH_LEN - 1:-1]
    unused = 8 * em_len - em_bits
    if masked_db[0] & ((0xFF << (8 - unused)) & 0xFF):
        return False
    db = bytearray(_xor(masked_db, mgf1(h, em_len - HASH_LEN - 1)))
    db[0] &= 0xFF >> unused
    ps_len = em_len - HASH_LEN - salt_len - 2
    if any(db[:ps_len]) or db[ps_len] != 0x01:
        return False
    salt = bytes(db[len(db) - salt_len:]) if salt_len else b""
    return constant_time_eq(sha256(b"\x00" * 8 + message_hash + salt), h)
