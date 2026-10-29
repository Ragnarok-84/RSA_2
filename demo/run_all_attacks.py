"""Chạy toàn bộ tấn công a1 → a9 ở cấu hình yếu và khi bật phòng chống, in bảng tổng kết.

    python -m demo.run_all_attacks            # chỉ bảng tổng kết
    python -m demo.run_all_attacks -v         # in từng bước
"""
from __future__ import annotations

import argparse
import sys

from attacks import REGISTRY, load
from core.step_logger import StepLogger


def run_all(verbose: bool = False, emit=print) -> bool:
    rows = []
    for module, title in REGISTRY:
        outcome = []
        for defended in (False, True):
            log = StepLogger()
            result = load(module).run(log, defended=defended)
            outcome.append(result.success)
            if verbose:
                emit(log.to_text() + "\n")
        rows.append((title, *outcome))
    emit(f"{'Tấn công':<52} | {'Cấu hình yếu':<14} | {'Bật phòng chống':<15} | Đúng kỳ vọng")
    emit("-" * 105)
    all_ok = True
    for title, weak, defended in rows:
        ok = weak and not defended
        all_ok &= ok
        emit(f"{title:<52} | {'THÀNH CÔNG' if weak else 'thất bại':<14} | {'thành công' if defended else 'THẤT BẠI':<15} | "
             f"{'ĐẠT' if ok else 'LỖI'}")
    emit(f"\n{sum(w and not d for _, w, d in rows)}/{len(rows)} tấn công đúng kỳ vọng "
         "(thành công khi yếu, thất bại khi bật phòng chống)")
    return all_ok


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Chạy toàn bộ tấn công")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    return 0 if run_all(args.verbose) else 1


if __name__ == "__main__":
    raise SystemExit(main())
