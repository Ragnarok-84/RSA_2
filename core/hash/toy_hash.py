"""Hàm băm thu nhỏ.

- toy_hash: đưa thông điệp về [0, n) cho Tiny RSA (n = 187):  h(M) = OS2IP(SHA256(M)) mod n
- weak_hash16: chỉ 16 bít đầu của SHA-256 — cố ý yếu để demo va chạm theo nghịch lý ngày sinh
  (khoảng 2^8 lần thử là có va chạm với xác suất cao).
"""
from __future__ import annotations

from core.hash.sha256 import sha256
from core.utils import os2ip


def toy_hash(data: bytes, n: int) -> int:
    """h(M) = OS2IP(SHA256(M)) mod n, giá trị trong [0, n)."""
    return os2ip(sha256(data)) % n


def weak_hash16(data: bytes) -> int:
    """16 bít đầu của SHA-256(data), giá trị trong [0, 65536). KHÔNG kháng va chạm."""
    return os2ip(sha256(data)[:2])
