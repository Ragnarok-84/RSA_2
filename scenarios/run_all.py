"""Chạy các kịch bản S1-S6 và in bảng tổng kết."""
import os
import sys
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from scenarios.s1_authentication import run_scenario_s1
from scenarios.s2_nonrepudiation import run_scenario_s2
from scenarios.s3_revocation import run_scenario_s3
from scenarios.s4_replay import run_scenario_s4
from scenarios.s5_key_substitution import run_scenario_s5
from scenarios.s6_confidentiality import run_scenario_s6

SCENARIOS = [
    ("S1", "Xác thực người dùng", "Chứng thực", run_scenario_s1),
    ("S2", "Chống chối bỏ (CA + TSA, đối chiếu HMAC)", "Chống chối bỏ", run_scenario_s2),
    ("S3", "Khóa bị lộ, thu hồi, dấu thời gian", "Chống chối bỏ lâu dài", run_scenario_s3),
    ("S4", "Tấn công phát lại", "Tính tươi mới (nonce)", run_scenario_s4),
    ("S5", "Tấn công thay thế khóa công khai", "Chứng thực khóa (PKI)", run_scenario_s5),
    ("S6", "Ký rồi mã hóa (bổ sung)", "Bảo mật", run_scenario_s6),
]


def run_all(keysize=1024, verbose=True):
    results = []
    for code, name, prop, fn in SCENARIOS:
        t = time.perf_counter()
        ok = fn(keysize=keysize, verbose=verbose)
        results.append((code, name, prop, ok, time.perf_counter() - t))
    print("\n" + "=" * 86)
    print(f"TỔNG KẾT (khóa {keysize} bit)")
    print(f"{'Mã':<4}| {'Kịch bản':<42}| {'Tính chất':<23}| {'Kết quả':<9}| Thời gian")
    print("-" * 86)
    for code, name, prop, ok, dt in results:
        print(f"{code:<4}| {name:<42}| {prop:<23}| {'ĐẠT' if ok else 'LỖI':<9}| {dt:.2f}s")
    return all(r[3] for r in results)


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    sys.exit(0 if run_all(keysize=2048 if "--real" in sys.argv else 1024) else 1)
