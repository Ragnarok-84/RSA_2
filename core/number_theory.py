from __future__ import annotations

from core.step_logger import StepLogger


def gcd(a: int, b: int) -> int:
    # Tính ước chung lớn nhất
    a, b = abs(a), abs(b)
    while b:
        a, b = b, a % b
    return a


def egcd(a: int, b: int, logger: StepLogger | None = None) -> tuple[int, int, int]:
    # Euclid mở rộng dạng lặp    
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
        logger.table(
            f"Euclid mở rộng trên ({a0}, {b0})",
            ("q", "r", "x", "y", "a", "b", "x2", "x1", "y2", "y1"), rows,
            formula=f"q = floor(a / b), r = a - q*b, x = x2 - q*x1, y = y2 - q*y1\n"
                    f"-> Kết quả: {a0}*({x}) + {b0}*({y}) = {d} => (d, x, y) = ({d}, {x}, {y})"
        )
    return d, x, y


def mod_inverse(a: int, n: int, logger: StepLogger | None = None) -> int:
    # Nghịch đảo modulo
    if n <= 0:
        raise ValueError("Modulo phải dương")
    d, _, y = egcd(n, a % n)
    inv = y % n
    if logger is not None and a % n:
        conclusion = (f"r2 = 0 và r1 = 1 => {a}^(-1) mod {n} = {inv}" if d == 1
                      else f"r2 = 0 nhưng r1 = {d} ≠ 1 => không tồn tại {a}^(-1) mod {n}")
        logger.table(
            f"Euclid mở rộng tìm nghịch đảo: {a}^(-1) mod {n}",
            ("Dòng", "r0", "r1", "r2", "q", "t0", "t1"), _inverse_rows(a % n, n),
            formula=f"r2 = r0 mod r1, q = floor(r0 / r1), t1 = (t0 - q*t1 của dòng trên) mod {n}\n"
                    f"-> Kết quả: {conclusion}"
        )
    if d != 1:
        raise ValueError(f"gcd({a}, {n}) = {d} ≠ 1: không tồn tại nghịch đảo modulo")
    return inv


def _inverse_rows(a: int, n: int) -> list[tuple[object, ...]]:
    # Bảng 6 cột tính a^(-1) mod n như slide: dòng mới lấy r0, r1, t0 từ r1, r2, t1 của dòng trên
    rows: list[tuple[object, ...]] = []
    r0, r1, t0, t1 = n, a, 0, 1
    while True:
        q, r2 = divmod(r0, r1)
        rows.append((len(rows), r0, r1, r2, q, t0, t1))
        if r2 == 0:
            return rows
        r0, r1, t0, t1 = r1, r2, t1, (t0 - q * t1) % n


def mod_pow(base: int, exp: int, mod: int, logger: StepLogger | None = None) -> int:
    # Lũy thừa modulo 
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
                     formula=rf"{base}^{exp} mod {mod} = {f}")
    return f


def crt(residues: list[int], moduli: list[int]) -> int:
    # Định lý thặng dư Trung Hoa
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
    # Căn bậc 2 nguyên
    return iroot(n, 2)[0]


def iroot(n: int, k: int) -> tuple[int, bool]:
    # Căn bậc k nguyên
    if n < 0:
        raise ValueError("n phải không âm")
    if k < 1:
        raise ValueError("k phải >= 1")
    if n < 2 or k == 1:
        return n, True
    r = 1 << ((n.bit_length() + k - 1) // k)          
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
