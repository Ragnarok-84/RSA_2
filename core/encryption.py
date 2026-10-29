"""RSA-OAEP/SHA-256 và gói z cho demo ký rồi mã hoá.

OAEP theo RFC 8017, mục 7.1. Gói nhiều khối là định dạng riêng của demo,
giới hạn thông điệp 16 KiB; không phải định dạng trao đổi chuẩn.
Nhãn OAEP gắn từng khối với mã gói ngẫu nhiên, vị trí và tổng số khối.
"""
from __future__ import annotations

import json
import secrets

from core.hash.sha256 import sha256
from core.number_theory import mod_pow
from core.padding.mgf1 import mgf1
from core.rsa_keygen import RSAPrivateKey, RSAPublicKey
from core.signature import SignatureBundle
from core.utils import constant_time_eq

MAX_MESSAGE_BYTES = 16 * 1024
MAX_PACKAGE_BYTES = 128 * 1024
MAX_ENVELOPE_FILE_BYTES = 1024 * 1024
ALGORITHM = "RSA-OAEP-SHA256-CHUNKS-v1"
HASH_LEN = 32


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def encrypt_oaep(message: bytes, pub: RSAPublicKey, label: bytes = b"") -> bytes:
    """RSAES-OAEP với SHA-256 cho cả lHash và MGF1."""
    k = (pub.n.bit_length() + 7) // 8
    if k < 2 * HASH_LEN + 2 or len(message) > k - 2 * HASH_LEN - 2:
        raise ValueError("Thông điệp quá dài hoặc khoá quá ngắn cho RSA-OAEP/SHA-256")
    db = sha256(label) + b"\x00" * (k - len(message) - 2 * HASH_LEN - 2) + b"\x01" + message
    seed = secrets.token_bytes(HASH_LEN)
    masked_db = _xor(db, mgf1(seed, k - HASH_LEN - 1))
    masked_seed = _xor(seed, mgf1(masked_db, HASH_LEN))
    em = b"\x00" + masked_seed + masked_db
    return mod_pow(int.from_bytes(em, "big"), pub.e, pub.n).to_bytes(k, "big")


def decrypt_oaep(ciphertext: bytes, priv: RSAPrivateKey, label: bytes = b"") -> bytes:
    k = (priv.n.bit_length() + 7) // 8
    error = "Không giải mã được: sai khoá hoặc bản mã đã bị thay đổi"
    if k < 2 * HASH_LEN + 2 or len(ciphertext) != k or int.from_bytes(ciphertext, "big") >= priv.n:
        raise ValueError(error)
    em = mod_pow(int.from_bytes(ciphertext, "big"), priv.d, priv.n).to_bytes(k, "big")
    masked_seed, masked_db = em[1:1 + HASH_LEN], em[1 + HASH_LEN:]
    seed = _xor(masked_seed, mgf1(masked_db, HASH_LEN))
    db = _xor(masked_db, mgf1(seed, k - HASH_LEN - 1))
    rest = db[HASH_LEN:]
    separator = rest.find(b"\x01")
    if (em[0] != 0 or not constant_time_eq(db[:HASH_LEN], sha256(label))
            or separator < 0 or any(rest[:separator])):
        raise ValueError(error)
    return rest[separator + 1:]


def _label(package_id: bytes, index: int, count: int) -> bytes:
    return ALGORITHM.encode("ascii") + package_id + index.to_bytes(4, "big") + count.to_bytes(4, "big")


def seal(message: bytes, bundle: SignatureBundle, pub: RSAPublicKey) -> dict:
    """z = E_public_Thuy(thông điệp, chữ ký). Không đưa khoá vào gói."""
    if len(message) > MAX_MESSAGE_BYTES:
        raise ValueError("Chế độ mã hoá demo hỗ trợ thông điệp tối đa 16 KiB")
    payload = json.dumps({"message_hex": message.hex(), "signature": bundle.to_dict()},
                         ensure_ascii=False).encode("utf-8")
    if len(payload) > MAX_PACKAGE_BYTES:
        raise ValueError("Gói thông điệp và chữ ký quá lớn")
    size = (pub.n.bit_length() + 7) // 8 - 2 * HASH_LEN - 2
    if size <= 0:
        raise ValueError("Khoá quá ngắn cho RSA-OAEP/SHA-256")
    count = (len(payload) + size - 1) // size
    package_id = secrets.token_bytes(16)
    blocks = [encrypt_oaep(payload[i * size:(i + 1) * size], pub, _label(package_id, i, count)).hex()
              for i in range(count)]
    return {"algorithm": ALGORITHM, "package_id": package_id.hex(), "blocks": blocks}


def unseal(envelope: dict, priv: RSAPrivateKey) -> tuple[bytes, SignatureBundle]:
    """Giải mã toàn bộ rồi mới trả thông điệp; chữ ký cần được kiểm tra riêng."""
    try:
        if envelope["algorithm"] != ALGORITHM:
            raise ValueError("Lược đồ bản mã không hỗ trợ")
        package_id = bytes.fromhex(envelope["package_id"])
        blocks = envelope["blocks"]
        size = (priv.n.bit_length() + 7) // 8 - 2 * HASH_LEN - 2
        if (len(package_id) != 16 or not isinstance(blocks, list) or not blocks or size <= 0
                or len(blocks) > (MAX_PACKAGE_BYTES + size - 1) // size):
            raise ValueError("Gói bản mã không hợp lệ")
        payload = b"".join(decrypt_oaep(bytes.fromhex(block), priv, _label(package_id, i, len(blocks)))
                           for i, block in enumerate(blocks))
        if len(payload) > MAX_PACKAGE_BYTES:
            raise ValueError("Gói bản mã quá lớn")
        data = json.loads(payload)
        message = bytes.fromhex(data["message_hex"])
        if len(message) > MAX_MESSAGE_BYTES:
            raise ValueError("Thông điệp quá lớn")
        bundle = SignatureBundle.from_dict(data["signature"])
        # Kiểm tra cú pháp chữ ký trước khi chuyển sang GUI.
        bundle.signature
        return message, bundle
    except (KeyError, TypeError, AttributeError, OverflowError, ValueError) as err:
        raise ValueError("Không giải mã được: sai khoá hoặc gói bản mã không hợp lệ") from err
