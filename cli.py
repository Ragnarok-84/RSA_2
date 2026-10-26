"""
demo/cli.py
Giao diện dòng lệnh (CLI) chạy thử nghiệm tương tác các kịch bản ATBM & Tấn công RSA.
Chạy từ thư mục gốc dự án:   python demo/cli.py
"""
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(ROOT)

from scenarios.s1_authentication import run_scenario_s1
from scenarios.s2_nonrepudiation import run_scenario_s2
from scenarios.s3_revocation import run_scenario_s3
from scenarios.s7_key_substitution import run_scenario_s7
from attacks import attacks
import test_s4
import rsa_mini


def read_int(prompt, default):
    """Đọc số nguyên, nhập sai hoặc để trống thì dùng giá trị mặc định (không bị crash)."""
    raw = input(prompt).strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        print(f"[Lỗi] '{raw}' không phải số nguyên, dùng mặc định {default}.")
        return default


def run_s5_s6():
    try:
        import sa_signature_pki
    except ImportError:
        print("[Lỗi] Cần thư viện cryptography:  pip install cryptography")
        return False
    bits = read_int("Độ dài khóa RSA (mặc định 1024 cho nhanh, 2048 cho thực tế): ", 1024)
    return sa_signature_pki.main(["--bits", str(bits)]) == 0


def run_benchmark_menu():
    import benchmark
    real = input("Chạy chế độ REAL (khóa 1024/2048 bit, chậm hơn)? [y/N]: ").strip().lower() == "y"
    benchmark.run_benchmark(real=real)


def run_full_tests():
    import subprocess
    real = input("Bật REAL = True (khóa 2048 bit, chậm hơn)? [y/N]: ").strip().lower() == "y"
    cmd = [sys.executable, os.path.join(ROOT, "test_all.py")] + (["--real"] if real else [])
    subprocess.run(cmd, cwd=ROOT)


def attack_small_n_menu():
    print("\n--- ATTACK: PHÂN TÍCH N NHỎ ---")
    n_val = read_int("Nhập số n cần phân tích (mặc định 3233): ", 3233)
    e_val = read_int("Nhập e công khai (mặc định 17): ", 17)
    res = attacks.attack_small_n(n_val)
    if not res:
        print("[Kết quả] Không tìm thấy thừa số (n là số nguyên tố hoặc quá nhỏ).")
        return
    p, q = res
    print(f"[Kết quả] p = {p}, q = {q}")
    try:
        d = attacks.recover_private_key(e_val, n_val)[0]
        print(f"[Kết quả] Khóa riêng bị lộ: d = {d}")
    except ValueError:
        print("[Kết quả] e không nguyên tố cùng nhau với phi(n), không tính được d.")


def menu():
    print("\n" + "=" * 65)
    print("       HỆ THỐNG DEMO AN TOÀN BẢO MẬT THÔNG TIN (RSA & PKI)")
    print("=" * 65)
    print("  [1] Kịch bản S1: Xác thực người dùng (Authentication)")
    print("  [2] Kịch bản S2: Chống chối bỏ giao dịch (Non-Repudiation)")
    print("  [3] Kịch bản S3: Thu hồi khóa & Danh sách CRL (Revocation)")
    print("  [4] Kịch bản S7: Tấn công thay thế khóa (Key Substitution)")
    print("  [5] Hacker Attack: Phân tích Modulus n nhỏ (Factorization)")
    print("  [6] Hacker Attack: Giả mạo chữ ký không đệm (Homomorphic)")
    print("  [7] Hacker Attack: Căn bậc ba Bleichenbacher (e=3)")
    print("  [8] Chạy toàn bộ các kịch bản chính (Run All)")
    print("  [9] Kịch bản S4: HMAC không chống chối bỏ")
    print(" [10] Kịch bản S5 + S6: Khóa bị lộ & Chứng thư hết hạn (cần cryptography)")
    print(" [11] RSA thu nhỏ tính tay (p=17, q=11, e=7, M=88)")
    print(" [12] Benchmark tốc độ")
    print(" [13] Chạy bộ test hoàn chỉnh (test_all.py)")
    print("  [0] Thoát chương trình")
    print("=" * 65)


def run_all():
    results = {
        "S1": run_scenario_s1(),
        "S2": run_scenario_s2(),
        "S3": run_scenario_s3(),
        "S4": test_s4.test_S4_hmac_repudiation(),
        "S7": run_scenario_s7(),
    }
    print("\n" + "=" * 40)
    print("TỔNG KẾT")
    for name, ok in results.items():
        print(f"  {name}: {'ĐẠT ✅' if ok else 'KHÔNG ĐẠT ❌'}")
    print("  (S5/S6 chạy riêng ở mục [10]; các tấn công ở mục [5]-[7])")


def main():
    while True:
        menu()
        choice = input("👉 Nhập lựa chọn của bạn (0-13): ").strip()

        if choice == "1":
            run_scenario_s1()
        elif choice == "2":
            run_scenario_s2()
        elif choice == "3":
            run_scenario_s3()
        elif choice == "4":
            run_scenario_s7()
        elif choice == "5":
            attack_small_n_menu()
        elif choice == "6":
            print("\n--- ATTACK: GIẢ MẠO CHỮ KÝ KHÔNG ĐỆM ---")
            attacks.demo_no_padding_forgery()
        elif choice == "7":
            print("\n--- ATTACK: BLEICHENBACHER e=3 ---")
            bits = read_int("Độ dài khóa (>= 1536, mặc định 2048): ", 2048)
            try:
                attacks.demo_bleichenbacher(keysize=bits)
            except ValueError as err:
                print(f"[Lỗi] {err}")
        elif choice == "8":
            run_all()
        elif choice == "9":
            test_s4.test_S4_hmac_repudiation()
        elif choice == "10":
            run_s5_s6()
        elif choice == "11":
            rsa_mini.run_demo()
        elif choice == "12":
            run_benchmark_menu()
        elif choice == "13":
            run_full_tests()
        elif choice == "0":
            print("Đã thoát chương trình.")
            break
        else:
            print("[Lỗi] Lựa chọn không hợp lệ!")

        try:
            input("\nNhấn Enter để tiếp tục...")
        except EOFError:
            break


if __name__ == "__main__":
    main()
