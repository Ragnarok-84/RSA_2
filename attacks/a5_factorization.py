from __future__ import annotations

import secrets

from core.hash.toy_hash import toy_hash
from core.number_theory import gcd, mod_inverse, mod_pow
from core.rsa_keygen import RSAPublicKey, generate_keypair
from core.step_logger import StepLogger
from core.utils import Timer
from attacks import AttackResult

NAME = "A5: n nhỏ → phân tích (Pollard rho) → lộ d"


def pollard_rho(n: int, max_steps: int = 200_000) -> int | None:
    if n % 2 == 0:
        return 2
    steps = 0
    while steps < max_steps:
        c = 1 + secrets.randbelow(n - 1)
        x = y = 2 + secrets.randbelow(n - 2)
        g = 1
        while g == 1 and steps < max_steps:
            x = (x * x + c) % n
            y = (y * y + c) % n
            y = (y * y + c) % n
            g = gcd(abs(x - y), n)
            steps += 1
        if 1 < g < n:
            return g
    return None


def run(logger: StepLogger | None = None, defended: bool = False, bits: int | None = None,
        max_steps: int = 200_000) -> AttackResult:
    log = logger if logger is not None else StepLogger()
    bits = bits or (2048 if defended else 64)
    log.head(f"TẤN CÔNG A5: PHÂN TÍCH n {bits} BÍT")
    pub, _ = generate_keypair(bits)
    log.note("[1] Khoá công khai của trang", f"e = {pub.e}\nn = {pub.n if bits <= 128 else hex(pub.n)[:42] + '…'}")

    with Timer() as t:
        p = pollard_rho(pub.n, max_steps)
    if p is None:
        log.log(f"[2] Pollard rho sau {max_steps:,} bước ({t.elapsed:.2f}s)", None,
                f"Không tìm được thừa số. Với n {bits} bít cần khoảng 2^{bits // 4} bước.", level="ok")
        success, details = False, {"defended": defended, "bits": bits}
    else:
        q = pub.n // p
        phi = (p - 1) * (q - 1)
        d = mod_inverse(pub.e, phi)
        log.log(f"[2] Pollard rho tìm được thừa số sau {t.elapsed:.3f}s",
                r"g = \gcd(|x - y|, n)", f"p = {p}\nq = {q}")
        log.log("[3] Tính lại khoá riêng", r"d = e^{-1} \mathrm{mod}\ (p-1)(q-1)", f"d = {d}")
        fake = "trang đồng ý chuyển 100 triệu cho phuong".encode("utf-8")
        h = toy_hash(fake, pub.n)
        s = mod_pow(h, d, pub.n)
        success = mod_pow(s, pub.e, pub.n) == h
        log.log("[4] phuong ký giả bằng d vừa tính, thuy kiểm tra bằng (n, e) của trang",
                r"s = h^{d} \mathrm{mod}\ n,\; s^{e} \mathrm{mod}\ n = h",
                f"M = {fake.decode()}\nh = {h}, s = {s} → " + ("HỢP LỆ" if success else "sai"),
                level="bad" if success else "ok")
        details = {"defended": defended, "bits": bits, "p": p, "q": q}

    summary = (f"Phân tích được n {bits} bít, lộ d, ký giả thành công." if success else
               f"Thất bại: n {bits} bít quá lớn để phân tích.")
    (log.bad if success else log.ok)("[KẾT LUẬN] " + summary + " Phòng chống: khoá >= 2048 bít.")
    return AttackResult(NAME, success, summary, details)
