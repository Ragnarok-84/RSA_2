from __future__ import annotations

from core.hash.sha256 import sha256


def mgf1(seed: bytes, mask_len: int) -> bytes:
    # MGF1 - tạo mask dài mask_len từ seed bằng SHA-256 (dùng cho RSA-OAEP)
    out = bytearray()
    counter = 0
    while len(out) < mask_len:
        out += sha256(seed + counter.to_bytes(4, "big"))
        counter += 1
    return bytes(out[:mask_len])
