"""
demo/cli.py
[Báo cáo 6.1 - Kịch bản demo; 6.2 - Dữ liệu thật]
Giao diện dòng lệnh (CLI) chạy thử hệ chữ ký điện tử RSA: thuật toán, kịch bản an toàn S1-S6, tấn công.
Giao diện chỉ gọi các module trong core/, pki/, scenarios/, attacks/ (tách phần thuật toán khỏi giao diện).
Chạy từ thư mục gốc dự án:   python demo/cli.py
"""
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from core.rsa_math import generate_keypair
from core import rsa_full, rsa_mini
from core import secure_message as sm
from scenarios.s1_authentication import run_scenario_s1
from scenarios.s2_nonrepudiation import run_scenario_s2
from scenarios.s3_revocation import run_scenario_s3
from scenarios.s4_replay import run_scenario_s4
from scenarios.s5_key_substitution import run_scenario_s5
from scenarios.s6_confidentiality import run_scenario_s6
from scenarios.run_all import run_all
from attacks import small_n, forgery_no_padding, bleichenbacher_e3, confidentiality
from demo import avalanche, file_signer


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


def read_text(prompt, default):
    raw = input(f"{prompt} [{default}]: ").strip()
    return raw or default


# ------------------------------------------------------------------ #
# Chức năng tương tác
# ------------------------------------------------------------------ #
def interactive_sign():
    print("\n--- KÝ & KIỂM TRA THÔNG ĐIỆP ---")
    message = read_text("Nhập thông điệp cần ký", "Tôi đồng ý thanh toán 10.000.000 VNĐ")
    mode = read_text("Khóa: (1) ngẫu nhiên theo số bit  (2) tự nhập p, q, e (bản thu nhỏ)", "1")
    if mode == "2":
        p, q, e = read_int("p = ", 61), read_int("q = ", 53), read_int("e = ", 17)
        try:
            priv, pub = generate_keypair(p=p, q=q, e=e)
        except ValueError as err:
            print("[Lỗi]", err)
            return
        h = rsa_mini.tiny_hash(message, pub[1])
        print(f"N = {pub[1]}, d = {priv[0]}  (N nhỏ -> dùng bản thu nhỏ: h = SHA-256 mod N = {h})")
        s = rsa_mini.show_mod_exp(h, priv[0], pub[1], "S", print)
        print("Kiểm tra:", "HỢP LỆ" if rsa_mini.verify(h, s, pub) else "SAI")
        other = read_text("Nhập thông điệp bên nhận nhận được (sửa thử)", message)
        ok = rsa_mini.verify(rsa_mini.tiny_hash(other, pub[1]), s, pub)
        print("Kết quả:", "HỢP LỆ" if ok else "BỊ TỪ CHỐI — nội dung khác bản đã ký")
        print("[!] N nhỏ chỉ để minh họa: h chỉ có N giá trị -> dễ tìm va chạm; thực tế dùng N >= 2048 bit.")
        return
    bits = read_int("Số bit khóa (mặc định 2048): ", 2048)
    scheme = "pss" if read_text("Lược đồ đệm: (1) PKCS#1 v1.5  (2) PSS", "1") == "2" else "pkcs1v15"
    print(f"Đang sinh khóa {bits} bit...")
    priv, pub = generate_keypair(keysize=bits)
    print(f"e = {pub[0]}\nN = {hex(pub[1])[:50]}...")
    if scheme == "pkcs1v15":
        r = rsa_full.explain_sign(message, priv, pub)
        print(f"[1] SHA-256(M)         = {r['hash']}")
        print(f"[2] EM (đệm PKCS#1)    = {r['em'][:20]}...{r['em'][-90:]}")
        print(f"[3] S = EM^d mod N     = {hex(r['signature'])[:50]}...")
        print(f"[4] S^e mod N -> băm   = {r['hash_recovered']}")
        sig = r["signature"]
    else:
        sig = rsa_full.sign_message(message, priv, "pss")
        sig2 = rsa_full.sign_message(message, priv, "pss")
        print(f"[1] Chữ ký PSS lần 1   = {hex(sig)[:50]}...")
        print(f"[2] Chữ ký PSS lần 2   = {hex(sig2)[:50]}...  (khác nhau do salt ngẫu nhiên)")
    print("    Kiểm tra:", "HỢP LỆ" if rsa_full.verify_message(message, sig, pub, scheme) else "SAI")
    other = read_text("Nhập thông điệp bên nhận nhận được (sửa thử 1 ký tự)", message)
    ok = rsa_full.verify_message(other, sig, pub, scheme)
    print("Kết quả:", "HỢP LỆ" if ok else "BỊ TỪ CHỐI — nội dung đã bị thay đổi")


def interactive_seal():
    print("\n--- TÍNH BẢO MẬT: KÝ RỒI MÃ HÓA THÔNG ĐIỆP ---")
    message = read_text("Nhập thông điệp bí mật", "Mật khẩu Wi-Fi phòng họp: ATBMTT@2026")
    bits = read_int("Số bit khóa (>= 1024, mặc định 2048): ", 2048)
    print("Đang sinh khóa ký của Alice và khóa mã hóa của Bob...")
    a_priv, a_pub = generate_keypair(keysize=bits)
    b_priv, b_pub = generate_keypair(keysize=bits)
    env = sm.seal(message, "Alice", a_priv, "Bob", b_pub)
    print("\n[Alice -> Bob] Phong bì trên đường truyền (Eve thấy):")
    for k, v in env.items():
        print(f"   {k:<5}: {v[:70]}{'...' if len(v) > 70 else ''}")
    e_priv, _ = generate_keypair(keysize=bits)
    try:
        sm.open_sealed(env, "Eve", e_priv, {"Alice": a_pub}.get)
    except sm.SecureMessageError as err:
        print(f"\n[Eve] {err.reason}")
    r = sm.open_sealed(env, "Bob", b_priv, {"Alice": a_pub}.get)
    print(f"[Bob] Giải mã: '{r['message'].decode()}'")
    print(f"[Bob] Chữ ký hợp lệ, người gửi: {r['sender']} lúc {r['meta']['time']}")


def _ask_file(prompt):
    path = read_text(prompt, file_signer.DEFAULT_SAMPLE)
    if not os.path.isfile(path):
        print("[Lỗi] Không tìm thấy tệp.")
        return None
    return path


def file_sign_menu():
    path = _ask_file("Đường dẫn tệp cần ký")
    if path:
        file_signer.demo_sign_file(path, keysize=read_int("Số bit khóa (mặc định 2048): ", 2048))


def file_seal_menu():
    path = _ask_file("Đường dẫn tệp cần ký rồi mã hóa")
    if path:
        file_signer.demo_seal_file(path, keysize=read_int("Số bit khóa (mặc định 2048): ", 2048))


def attack_small_n_menu():
    print("\n--- ATTACK: PHÂN TÍCH N NHỎ ---")
    n_val = read_int("Nhập số n cần phân tích (mặc định 3233): ", 3233)
    e_val = read_int("Nhập e công khai (mặc định 17): ", 17)
    try:
        small_n.demo_small_n(n_val, e_val)
    except ValueError:
        print("[Kết quả] Không phân tích được (n nguyên tố) hoặc e không nguyên tố cùng nhau với phi(n).")


def run_full_tests():
    import subprocess
    real = input("Bật REAL (khóa 2048 bit, chậm hơn)? [y/N]: ").strip().lower() == "y"
    env = dict(os.environ, REAL="1" if real else "0")
    subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"], cwd=ROOT, env=env)


def run_benchmark_menu():
    from demo import benchmark
    real = input("Chạy chế độ REAL (khóa tới 3072 bit, chậm hơn)? [y/N]: ").strip().lower() == "y"
    benchmark.run_benchmark(real=real)


def run_doi_chieu():
    sys.path.insert(0, os.path.join(ROOT, "tests"))
    import doi_chieu
    doi_chieu.run()


MENU = [
    ("THUẬT TOÁN & DỮ LIỆU THẬT", [
        ("1", "RSA thu nhỏ tính tay (p=17, q=11, e=7, M=88) — in từng bước", lambda: rsa_mini.run_demo()),
        ("2", "Tự nhập thông điệp & khóa: KÝ và KIỂM TRA (PKCS#1 v1.5 / PSS)", interactive_sign),
        ("3", "Hiệu ứng thác lũ — vì sao ký trên giá trị băm", lambda: avalanche.run_demo()),
        ("4", "Ký & kiểm tra một TỆP (ảnh / văn bản)", file_sign_menu),
        ("5", "Tự nhập thông điệp: KÝ RỒI MÃ HÓA / GIẢI MÃ (tính bảo mật)", interactive_seal),
        ("6", "Ký rồi mã hóa một TỆP, giải mã lại", file_seal_menu),
    ]),
    ("KỊCH BẢN AN TOÀN", [
        ("7", "S1: Xác thực người dùng (Challenge-Response)", run_scenario_s1),
        ("8", "S2: Chống chối bỏ (CA + TSA, đối chiếu HMAC)", run_scenario_s2),
        ("9", "S3: Khóa bị lộ, thu hồi (CRL), dấu thời gian", run_scenario_s3),
        ("10", "S4: Tấn công phát lại — nonce & thời điểm", run_scenario_s4),
        ("11", "S5: Tấn công thay thế khóa công khai", run_scenario_s5),
        ("12", "S6: TÍNH BẢO MẬT — chỉ ký / ký rồi mã hóa", run_scenario_s6),
        ("13", "Chạy toàn bộ S1-S6 (run_all)", lambda: run_all()),
    ]),
    ("TẤN CÔNG — CHỮ KÝ", [
        ("14", "Phân tích modulus N nhỏ -> lộ khóa riêng", attack_small_n_menu),
        ("15", "Giả mạo chữ ký không đệm (tính đồng cấu)", lambda: forgery_no_padding.demo_no_padding_forgery()),
        ("16", "Bleichenbacher e=3 (bộ kiểm tra đệm lỏng lẻo)", lambda: bleichenbacher_e3.demo_bleichenbacher()),
    ]),
    ("TẤN CÔNG — TÍNH BẢO MẬT", [
        ("17", "Tấn công từ điển: RSA sách giáo khoa vs OAEP", lambda: confidentiality.demo_dictionary()),
        ("18", "Ký song song mã hóa làm lộ nội dung", lambda: confidentiality.demo_encrypt_and_sign_leak()),
        ("19", "Håstad broadcast (e=3, cùng bản rõ gửi 3 người)", lambda: confidentiality.demo_hastad()),
        ("20", "Dùng chung khóa ký & giải mã -> 'nhờ ký' = giải mã hộ",
         lambda: confidentiality.demo_same_key_sign_decrypt()),
    ]),
    ("KIỂM THỬ & ĐÁNH GIÁ", [
        ("21", "Đối chiếu test vector NIST / RFC / thư viện chuẩn", run_doi_chieu),
        ("22", "Benchmark tốc độ theo kích thước khóa và dữ liệu", run_benchmark_menu),
        ("23", "Chạy bộ test (tests/)", run_full_tests),
    ]),
]
ACTIONS = {key: fn for _, items in MENU for key, _, fn in items}


def menu():
    print("\n" + "=" * 70)
    print("     HỆ CHỮ KÝ ĐIỆN TỬ RSA — DEMO AN TOÀN BẢO MẬT THÔNG TIN")
    print("=" * 70)
    for title, items in MENU:
        print(f" {title}")
        for key, label, _ in items:
            print(f"  [{key:>2}] {label}")
    print("  [ 0] Thoát chương trình")
    print("=" * 70)


def main():
    while True:
        menu()
        try:
            choice = input("Nhập lựa chọn của bạn (0-23): ").strip()
        except EOFError:
            break
        if choice == "0":
            print("Đã thoát chương trình.")
            break
        action = ACTIONS.get(choice)
        if action is None:
            print("[Lỗi] Lựa chọn không hợp lệ!")
        else:
            try:
                action()
            except KeyboardInterrupt:
                print("\n[Đã dừng]")
            except Exception as err:          # demo trực tiếp: không để chương trình sập
                print(f"[Lỗi] {type(err).__name__}: {err}")
        try:
            input("\nNhấn Enter để tiếp tục...")
        except EOFError:
            break


if __name__ == "__main__":
    main()
