from __future__ import annotations

from dataclasses import dataclass

from core.number_theory import gcd, mod_inverse
from core.primality import generate_prime, is_probable_prime
from core.step_logger import StepLogger

DEFAULT_E = 65537


@dataclass(frozen=True)
class RSAPublicKey:
    n: int
    e: int

    @property
    def bits(self) -> int:
        return self.n.bit_length()


@dataclass(frozen=True)
class RSAPrivateKey:
    n: int
    e: int
    d: int
    p: int
    q: int

    @property
    def bits(self) -> int:
        return self.n.bit_length()

    @property
    def public_key(self) -> RSAPublicKey:
        return RSAPublicKey(self.n, self.e)


def keypair_from_primes(p: int, q: int, e: int, logger: StepLogger | None = None) -> tuple[RSAPublicKey, RSAPrivateKey]:
    """Dựng cặp khoá từ p, q, e cho sẵn (dùng cho Tiny RSA và ví dụ tính tay)."""
    if p == q:
        raise ValueError("p và q phải khác nhau (p = q thì n = p², phân tích được ngay)")
    if not (is_probable_prime(p) and is_probable_prime(q)):
        raise ValueError("p và q phải là số nguyên tố")
    n = p * q
    phi = (p - 1) * (q - 1)
    if logger is not None:
        logger.log("Tính modulus", f"n = p*q = {p}*{q} = {n}")
        logger.log("Tính phi hàm Euler", f"phi(n) = (p - 1)*(q - 1) = {p - 1}*{q - 1} = {phi}")
    g = gcd(e, phi)
    if logger is not None:
        logger.log("Kiểm tra e", f"gcd(e, phi(n)) = gcd({e}, {phi}) = {g}{', hợp lệ' if g == 1 else ' khác 1, không chọn được e này'}", level="" if g == 1 else "bad")
    if not 1 < e < phi or g != 1:
        raise ValueError(f"e = {e} không hợp lệ: cần 1 < e < phi(n) = {phi} và gcd(e, phi(n)) = 1")
    d = mod_inverse(e, phi, logger)
    if logger is not None:
        logger.log("Tính d", f"d = e^(-1) mod phi(n) = {e}^(-1) mod {phi} = {d} (e*d mod phi(n) = {(e * d) % phi})")
        logger.ok("Cặp khoá", f"Khoá công khai (e, n) = ({e}, {n})\nKhoá bí mật (d, p, q) = ({d}, {p}, {q})")
    return RSAPublicKey(n, e), RSAPrivateKey(n, e, d, p, q)


def generate_keypair(bits: int = 2048, e: int = DEFAULT_E) -> tuple[RSAPublicKey, RSAPrivateKey]:
    """Sinh cặp khoá ngẫu nhiên có n đúng `bits` bit.

    - p, q mỗi số khoảng bits/2 bit, bật 2 bit cao nhất để n.bit_length() == bits.
    - gcd(e, p - 1) = gcd(e, q - 1) = 1 (tương đương gcd(e, phi(n)) = 1).
    - |p - q| đủ lớn (chống phân tích Fermat khi p xấp xỉ q).
    """
    if bits < 16:
        raise ValueError("Khoá quá ngắn (cần >= 16 bit)")
    if e < 3 or e % 2 == 0:
        raise ValueError("e phải lẻ và >= 3")
    half = bits // 2
    while True:
        p = generate_prime(half, top_bits=2)
        if gcd(e, p - 1) != 1:
            continue
        q = generate_prime(bits - half, top_bits=2)
        if p == q or gcd(e, q - 1) != 1:
            continue
        if bits >= 256 and abs(p - q).bit_length() < half - 100:
            continue
        pub, priv = keypair_from_primes(p, q, e)
        if pub.n.bit_length() == bits:
            return pub, priv
