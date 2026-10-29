from __future__ import annotations

import argparse
import os
import statistics
import sys
from dataclasses import dataclass
from typing import Callable

from core.hash.sha256 import sha256
from core.rsa_keygen import generate_keypair
from core.signature import sign, verify
from core.utils import Timer

KEY_SIZES = (512, 1024, 2048, 3072)
DATA_SIZES = (1 << 10, 10 << 10, 100 << 10, 1 << 20, 10 << 20)
KINDS = {
    "keygen": "Sinh khoá",
    "sign": "Ký",
    "verify": "Kiểm tra",
    "hash": "Băm SHA-256",
}


@dataclass
class BenchRow:
    kind: str
    param: int                  # số bít khoá hoặc số byte dữ liệu
    median_s: float
    repeats: int


def fmt_size(n: int) -> str:
    for unit, k in (("MB", 1 << 20), ("KB", 1 << 10)):
        if n >= k:
            return f"{n // k} {unit}"
    return f"{n} B"


def _median(fn: Callable[[], object], repeats: int) -> float:
    times = []
    for _ in range(repeats):
        with Timer() as t:
            fn()
        times.append(t.elapsed)
    return statistics.median(times)


def run_benchmark(key_sizes=KEY_SIZES, data_sizes=DATA_SIZES, repeats: int = 3,
                  progress: Callable[[str], None] | None = None) -> list[BenchRow]:
    say = progress or (lambda _s: None)
    rows: list[BenchRow] = []
    msg = b"Benchmark RSA signature"
    for bits in key_sizes:
        say(f"Sinh khoá {bits} bít…")
        rows.append(BenchRow("keygen", bits, _median(lambda: generate_keypair(bits), repeats), repeats))
        pub, priv = generate_keypair(bits)
        sig = sign(msg, priv)
        say(f"Ký / kiểm tra với khoá {bits} bít…")
        rows.append(BenchRow("sign", bits, _median(lambda: sign(msg, priv), repeats), repeats))
        rows.append(BenchRow("verify", bits, _median(lambda: verify(msg, sig, pub), repeats), repeats))
    for size in data_sizes:
        say(f"Băm {fmt_size(size)}…")
        data = os.urandom(size)
        r = repeats if size < (1 << 20) else 1
        rows.append(BenchRow("hash", size, _median(lambda: sha256(data), r), r))
    say("Xong")
    return rows


def to_console(rows: list[BenchRow]) -> str:
    lines = [f"{'Phép đo':<16} {'Tham số':>10} {'Trung vị':>12}"]
    for r in rows:
        param = fmt_size(r.param) if r.kind == "hash" else f"{r.param} bít"
        extra = f"  ({r.param / r.median_s / (1 << 20):.2f} MB/s)" if r.kind == "hash" and r.median_s else ""
        lines.append(f"{KINDS[r.kind]:<16} {param:>10} {r.median_s * 1000:>9.2f} ms{extra}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Benchmark hệ chữ ký RSA")
    ap.add_argument("--quick", action="store_true", help="khoá tới 2048 bít, dữ liệu tới 1 MB")
    ap.add_argument("--repeats", type=int, default=3)
    args = ap.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    keys = KEY_SIZES[:3] if args.quick else KEY_SIZES
    data = DATA_SIZES[:4] if args.quick else DATA_SIZES
    rows = run_benchmark(keys, data, args.repeats, progress=lambda s: print("…", s, flush=True))
    print(to_console(rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
