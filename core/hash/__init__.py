"""Hàm băm tự cài: SHA-256 (FIPS 180-4) và hàm băm thu nhỏ cho Tiny RSA / demo va chạm."""
from core.hash.sha256 import SHA256, sha256, sha256_file
from core.hash.toy_hash import toy_hash, weak_hash16

__all__ = ["SHA256", "sha256", "sha256_file", "toy_hash", "weak_hash16"]
