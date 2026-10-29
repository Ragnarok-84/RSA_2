"""Lược đồ đệm PKCS#1 v1.5, PSS và OAEP (RFC 8017)."""
import secrets

from core.sha256 import sha256_bytes
from core.rsa_math import compare_hashes

HASH_LEN = 32
# DigestInfo (ASN.1 DER) định danh thuật toán SHA-256, RFC 8017 mục 9.2 ghi chú 1
SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")


class DecodingError(ValueError):
    """Gỡ đệm thất bại. Chỉ dùng MỘT thông báo chung cho mọi nguyên nhân (chống tấn công Manger)."""


def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def mgf1(seed, length):
    """MGF1-SHA256: T = Hash(seed||0) || Hash(seed||1) || ... cắt còn `length` byte."""
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += sha256_bytes(seed + counter.to_bytes(4, "big"))
        counter += 1
    return bytes(out[:length])


# EMSA-PKCS1-v1_5
def pkcs1_v15_encode(hash_bytes, em_len):
    """EM = 00 01 | FF..FF (>= 8 byte) | 00 | DigestInfo | H"""
    t = SHA256_DIGEST_INFO + hash_bytes
    if em_len < len(t) + 11:
        raise ValueError("Độ dài khóa quá ngắn để đệm (cần N >= 496 bit, khuyến nghị >= 2048)")
    return b"\x00\x01" + b"\xff" * (em_len - len(t) - 3) + b"\x00" + t


def add_pkcs1_v15_padding(hash_value, em_length):
    """
    Thêm đệm PKCS#1 v1.5 vào giá trị băm trước khi ký (giữ giao diện cũ của nhóm).
    :param hash_value: Giá trị băm SHA-256 (chuỗi hex)
    :param em_length: Độ dài khối EM (byte) = độ dài N tính theo byte
    :return: EM dạng số nguyên
    """
    return int.from_bytes(pkcs1_v15_encode(bytes.fromhex(hash_value), em_length), "big")


def parse_em_strict(em):
    """
    Tách giá trị băm từ khối EM PKCS#1 v1.5, kiểm tra CHẶT từng byte (không thừa, không thiếu).
    Bộ kiểm tra lỏng chỉ tìm byte 00 rồi lấy phần đuôi sẽ bị tấn công Bleichenbacher e=3.
    :return: H dạng hex, hoặc None nếu sai cấu trúc
    """
    ps_len = len(em) - 3 - len(SHA256_DIGEST_INFO) - HASH_LEN
    if ps_len < 8:
        return None
    expected_head = b"\x00\x01" + b"\xff" * ps_len + b"\x00" + SHA256_DIGEST_INFO
    if not compare_hashes(em[:-HASH_LEN], expected_head):
        return None
    return em[-HASH_LEN:].hex()


# EMSA-PSS
def pss_encode(m_hash, em_bits, salt=None, salt_len=HASH_LEN):
    """
    EMSA-PSS-ENCODE (RFC 8017 mục 9.1.1):
        M'  = 00*8 || mHash || salt          H = SHA256(M')
        DB  = 00..00 || 01 || salt
        maskedDB = DB XOR MGF1(H, emLen - hLen - 1), xóa (8*emLen - emBits) bit cao nhất
        EM  = maskedDB || H || BC
    """
    em_len = (em_bits + 7) // 8
    if em_len < HASH_LEN + salt_len + 2:
        raise ValueError("Khóa quá ngắn cho PSS")
    salt = secrets.token_bytes(salt_len) if salt is None else salt
    h = sha256_bytes(b"\x00" * 8 + m_hash + salt)
    db = b"\x00" * (em_len - salt_len - HASH_LEN - 2) + b"\x01" + salt
    masked_db = bytearray(xor_bytes(db, mgf1(h, em_len - HASH_LEN - 1)))
    masked_db[0] &= 0xFF >> (8 * em_len - em_bits)
    return bytes(masked_db) + h + b"\xbc"


def pss_verify(m_hash, em, em_bits, salt_len=HASH_LEN):
    """EMSA-PSS-VERIFY (RFC 8017 mục 9.1.2). :return: True / False"""
    em_len = (em_bits + 7) // 8
    if len(em) != em_len or em_len < HASH_LEN + salt_len + 2 or em[-1] != 0xBC:
        return False
    masked_db, h = em[:em_len - HASH_LEN - 1], em[em_len - HASH_LEN - 1:-1]
    top_mask = (0xFF << (8 - (8 * em_len - em_bits))) & 0xFF
    if masked_db[0] & top_mask:
        return False
    db = bytearray(xor_bytes(masked_db, mgf1(h, em_len - HASH_LEN - 1)))
    db[0] &= 0xFF >> (8 * em_len - em_bits)
    ps_len = em_len - HASH_LEN - salt_len - 2
    if db[:ps_len] != b"\x00" * ps_len or db[ps_len] != 0x01:
        return False
    salt = bytes(db[-salt_len:]) if salt_len else b""
    return compare_hashes(sha256_bytes(b"\x00" * 8 + m_hash + salt), h)


# EME-OAEP (bổ sung - tính bảo mật)
def oaep_max_length(k):
    """Số byte bản rõ tối đa trong một khối OAEP: k - 2*hLen - 2 (190 byte với khóa 2048 bit)."""
    return k - 2 * HASH_LEN - 2


def oaep_encode(message, k, label=b"", seed=None):
    """
    EME-OAEP encoding (RFC 8017 mục 7.1.1):
        DB = lHash || PS(00..00) || 01 || M
        maskedDB   = DB   XOR MGF1(seed, k - hLen - 1)
        maskedSeed = seed XOR MGF1(maskedDB, hLen)
        EM = 00 || maskedSeed || maskedDB
    """
    if len(message) > oaep_max_length(k):
        raise ValueError(f"Thông điệp quá dài: tối đa {oaep_max_length(k)} byte với khóa này")
    l_hash = sha256_bytes(label)
    db = l_hash + b"\x00" * (oaep_max_length(k) - len(message)) + b"\x01" + message
    seed = secrets.token_bytes(HASH_LEN) if seed is None else seed
    masked_db = xor_bytes(db, mgf1(seed, k - HASH_LEN - 1))
    masked_seed = xor_bytes(seed, mgf1(masked_db, HASH_LEN))
    return b"\x00" + masked_seed + masked_db


def oaep_decode(em, k, label=b""):
    """Đảo của oaep_encode. Mọi lỗi đều trả cùng một ngoại lệ DecodingError."""
    if len(em) != k or k < 2 * HASH_LEN + 2:
        raise DecodingError("Giải mã thất bại")
    y, masked_seed, masked_db = em[0], em[1:1 + HASH_LEN], em[1 + HASH_LEN:]
    seed = xor_bytes(masked_seed, mgf1(masked_db, HASH_LEN))
    db = xor_bytes(masked_db, mgf1(seed, k - HASH_LEN - 1))
    l_hash_ok = compare_hashes(db[:HASH_LEN], sha256_bytes(label))
    rest = db[HASH_LEN:]
    sep = rest.find(b"\x01")
    zeros_ok = sep >= 0 and rest[:sep] == b"\x00" * sep
    # Gộp mọi điều kiện rồi mới quyết định -> không lộ "sai ở bước nào"
    if not (y == 0 and l_hash_ok and zeros_ok):
        raise DecodingError("Giải mã thất bại")
    return rest[sep + 1:]
