"""Số học cho RSA: Euclid, Euclid mở rộng, nghịch đảo modulo, bình phương và nhân, CRT, căn nguyên.

Toàn bộ lõi gọi mod_pow ở đây thay vì pow(a, b, n) built-in.
"""
from __future__ import annotations

from core.step_logger import StepLogger


def gcd(a: int, b: int) -> int:
    """Ước chung lớn nhất (Euclid): gcd(a, b) = gcd(b, a mod b)."""
    a, b = abs(a), abs(b)
    while b:
        a, b = b, a % b
    return a


def egcd(a: int, b: int, logger: StepLogger | None = None) -> tuple[int, int, int]:
    """Euclid mở rộng dạng lặp: trả (d, x, y) với a·x + b·y = d = gcd(a, b).

    Mỗi vòng (như bảng trong slide):
        q = ⌊a / b⌋,  r = a − q·b,  x = x2 − q·x1,  y = y2 − q·y1
    rồi dịch: a ← b, b ← r, x2 ← x1, x1 ← x, y2 ← y1, y1 ← y.
    """
    a0, b0 = a, b
    x2, x1, y2, y1 = 1, 0, 0, 1
    rows: list[tuple[object, ...]] = [("", "", "", "", a, b, x2, x1, y2, y1)]
    while b != 0:
        q = a // b
        r = a - q * b
        x = x2 - q * x1
        y = y2 - q * y1
        a, b = b, r
        x2, x1 = x1, x
        y2, y1 = y1, y
        rows.append((q, r, x, y, a, b, x2, x1, y2, y1))
    d, x, y = a, x2, y2
    if logger is not None:
        logger.table(f"Euclid mở rộng trên ({a0}, {b0})",
                     ("q", "r", "x", "y", "a", "b", "x2", "x1", "y2", "y1"), rows,
                     formula=r"q = \lfloor a / b \rfloor,\; r = a - q b,\; x = x_2 - q x_1,\; y = y_2 - q y_1")
        logger.log("Kết quả Euclid mở rộng", rf"{a0} \cdot ({x}) + {b0} \cdot ({y}) = {d}", f"(d, x, y) = ({d}, {x}, {y})")
    return d, x, y


def mod_inverse(a: int, n: int, logger: StepLogger | None = None) -> int:
    """Nghịch đảo modulo: a⁻¹ mod n qua Euclid mở rộng trên (n, a): n·x + a·y = 1 ⇒ a⁻¹ ≡ y (mod n).

    ValueError nếu gcd(a, n) ≠ 1.
    """
    if n <= 0:
        raise ValueError("Modulo phải dương")
    d, _, y = egcd(n, a % n, logger)
    if d != 1:
        raise ValueError(f"gcd({a}, {n}) = {d} ≠ 1: không tồn tại nghịch đảo modulo")
    inv = y % n
    if logger is not None:
        logger.log("Nghịch đảo modulo", rf"{a}^{{-1}} \mathrm{{mod}}\ {n} = {y} \mathrm{{mod}}\ {n} = {inv}",
                   f"Kiểm tra: {a} · {inv} mod {n} = {(a * inv) % n}")
    return inv


def mod_pow(base: int, exp: int, mod: int, logger: StepLogger | None = None) -> int:
    """Lũy thừa modulo base^exp mod mod bằng thuật toán bình phương và nhân (slide Ch.3).

    Viết exp = (b_k … b_1 b_0)₂, duyệt bit từ trái sang phải, c = 0, f = 1:
        c ← 2c,  f ← f² mod n;   nếu b_i = 1: c ← c + 1,  f ← f·a mod n.
    Kết thúc c = exp và f = a^exp mod n. Khi có logger, ghi bảng (i, b_i, c, f).
    """
    if mod <= 0:
        raise ValueError("Modulo phải dương")
    if exp < 0:
        raise ValueError("Số mũ phải không âm")
    a = base % mod
    c, f = 0, 1 % mod
    rows: list[tuple[object, ...]] | None = [] if logger is not None else None
    k = exp.bit_length() - 1
    for i in range(k, -1, -1):
        c = 2 * c
        f = (f * f) % mod
        if (exp >> i) & 1:
            c = c + 1
            f = (f * a) % mod
        if rows is not None:
            rows.append((i, (exp >> i) & 1, c, f))
    if logger is not None:
        logger.table(f"Bình phương và nhân: {base}^{exp} mod {mod}", ("i", "b_i", "c", "f"), rows or [],
                     formula=rf"{base}^{{{exp}}} \mathrm{{mod}}\ {mod} = {f}")
    return f


def crt(residues: list[int], moduli: list[int]) -> int:
    """Định lý phần dư Trung Hoa: tìm x với x ≡ r_i (mod m_i), các m_i đôi một nguyên tố cùng nhau.

    x = Σ r_i · M_i · (M_i⁻¹ mod m_i)  (mod M),  M = Π m_i, M_i = M / m_i.
    """
    if len(residues) != len(moduli) or not moduli:
        raise ValueError("Số phần dư và số modulo phải bằng nhau và khác 0")
    M = 1
    for m in moduli:
        M *= m
    x = 0
    for r, m in zip(residues, moduli):
        Mi = M // m
        x += r * Mi * mod_inverse(Mi, m)
    return x % M


def isqrt(n: int) -> int:
    """Căn bậc hai nguyên ⌊√n⌋ (Newton trên số nguyên)."""
    return iroot(n, 2)[0]


def iroot(n: int, k: int) -> tuple[int, bool]:
    """Căn bậc k nguyên: trả (r, exact) với r = ⌊n^(1/k)⌋ và exact = (r^k == n).

    Dùng phương pháp Newton trên số nguyên nên không mất chính xác như float với số hàng nghìn bit.
    """
    if n < 0:
        raise ValueError("n phải không âm")
    if k < 1:
        raise ValueError("k phải >= 1")
    if n < 2 or k == 1:
        return n, True
    r = 1 << ((n.bit_length() + k - 1) // k)          # r^k >= n
    while True:
        nr = ((k - 1) * r + n // r ** (k - 1)) // k
        if nr >= r:
            break
        r = nr
    while r ** k > n:
        r -= 1
    while (r + 1) ** k <= n:
        r += 1
    return r, r ** k == n
