"""Kiểm tra nguyên tố Miller–Rabin và sinh số nguyên tố ngẫu nhiên (nguồn ngẫu nhiên: secrets)."""
from __future__ import annotations

import secrets

from core.number_theory import mod_pow


def _small_primes(limit: int) -> tuple[int, ...]:
    """Sàng Eratosthenes: các số nguyên tố < limit."""
    sieve = bytearray([1]) * limit
    sieve[0:2] = b"\x00\x00"
    for i in range(2, int(limit ** 0.5) + 1):
        if sieve[i]:
            sieve[i * i::i] = bytearray(len(sieve[i * i::i]))
    return tuple(i for i in range(limit) if sieve[i])


SMALL_PRIMES = _small_primes(1000)


def miller_rabin(n: int, rounds: int = 40) -> bool:
    """Miller–Rabin: viết n − 1 = 2^k · q với q lẻ, chọn a ∈ [2, n − 2] ngẫu nhiên.

    n là "có thể nguyên tố" nếu a^q ≡ 1 hoặc a^(2^j·q) ≡ −1 (mod n) với j nào đó trong [0, k).
    Xác suất nhận nhầm hợp số ≤ 4^(−rounds).
    """
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False
    k, q = 0, n - 1
    while q % 2 == 0:
        k += 1
        q //= 2
    for _ in range(rounds):
        a = 2 + secrets.randbelow(n - 3)
        x = mod_pow(a, q, n)
        if x in (1, n - 1):
            continue
        for _ in range(k - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False                      # a là nhân chứng: n chắc chắn là hợp số
    return True


def is_probable_prime(n: int, rounds: int = 40) -> bool:
    """Chia thử các số nguyên tố < 1000 để loại nhanh, rồi Miller–Rabin."""
    if n < 2:
        return False
    for p in SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False
    return miller_rabin(n, rounds)


def generate_prime(bits: int, top_bits: int = 1) -> int:
    """Sinh số nguyên tố ngẫu nhiên đúng `bits` bit.

    Ứng viên ngẫu nhiên từ secrets, bật bit cao nhất (đủ độ dài) và bit thấp nhất (số lẻ).
    `top_bits = 2` bật thêm bit cao thứ hai để tích hai số nguyên tố bits-bit có đúng 2·bits bit.
    """
    if bits < 3:
        raise ValueError("Số bit phải >= 3")
    if top_bits not in (1, 2):
        raise ValueError("top_bits phải là 1 hoặc 2")
    high = (1 << (bits - 1)) | ((1 << (bits - 2)) if top_bits == 2 else 0)
    while True:
        candidate = secrets.randbits(bits) | high | 1
        if is_probable_prime(candidate):
            return candidate
