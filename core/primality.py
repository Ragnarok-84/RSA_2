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
    # MillerR-abin: kiểm tra xác suất n là số nguyên tố. Nếu trả về False thì chắc chắn n là hợp số.
    
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
            return False                      
    return True


def is_probable_prime(n: int, rounds: int = 40) -> bool:
    """Chia thử các số nguyên tố < 1000 để loại nhanh, rồi Miller-Rabin."""
    if n < 2:
        return False
    for p in SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False
    return miller_rabin(n, rounds)


def generate_prime(bits: int, top_bits: int = 1) -> int:
    # Sinh số nguyên tố ngẫu nhiên đúng `bits` bit.

    if bits < 3:
        raise ValueError("Số bit phải >= 3")
    if top_bits not in (1, 2):
        raise ValueError("top_bits phải là 1 hoặc 2")
    high = (1 << (bits - 1)) | ((1 << (bits - 2)) if top_bits == 2 else 0)
    while True:
        candidate = secrets.randbits(bits) | high | 1
        if is_probable_prime(candidate):
            return candidate
