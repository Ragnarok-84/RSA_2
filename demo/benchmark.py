# Tệp: demo/benchmark.py   [Báo cáo 6.3 - Đo thời gian]
# Đo thời gian chạy theo kích thước khóa và kích thước dữ liệu.
#   python demo/benchmark.py          -> nhanh (khóa 512/1024, dữ liệu tới 64 KB)
#   python demo/benchmark.py --real   -> khóa tới 3072 bit, dữ liệu tới 256 KB
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.rsa_math import generate_keypair
from core.sha256 import hash_sha256
from core import rsa_full
from core import secure_message as sm


def timeit(fn, repeat=1):
    t = time.perf_counter()
    for _ in range(repeat):
        out = fn()
    return (time.perf_counter() - t) / repeat, out


def run_benchmark(real=False):
    key_sizes = (1024, 2048, 3072) if real else (512, 1024, 2048)
    data_sizes = (1024, 16 * 1024, 64 * 1024, 256 * 1024) if real else (1024, 8 * 1024, 64 * 1024)

    print("\n1) THEO KÍCH THƯỚC KHÓA (thông điệp ngắn)")
    print(f"{'Khóa (bit)':>10} | {'Sinh khóa':>10} | {'Ký v1.5':>9} | {'Ký PSS':>9} | {'Kiểm tra':>9} "
          f"| {'OAEP mã':>9} | {'OAEP giải':>9}")
    print("-" * 84)
    msg = "Benchmark chữ ký RSA"
    for bits in key_sizes:
        t_gen, (priv, pub) = timeit(lambda: generate_keypair(keysize=bits))
        t_sign, s = timeit(lambda: rsa_full.sign_message(msg, priv), 3)
        t_pss, _ = timeit(lambda: rsa_full.sign_message(msg, priv, "pss"), 3)
        t_ver, _ = timeit(lambda: rsa_full.verify_message(msg, s, pub), 3)
        if rsa_full.max_message_length(pub) >= 32:
            t_enc, c = timeit(lambda: rsa_full.oaep_encrypt(b"k" * 32, pub), 3)
            t_dec, _ = timeit(lambda: rsa_full.oaep_decrypt(c, priv), 3)
            oaep = f"{t_enc * 1000:>7.1f}ms | {t_dec * 1000:>7.1f}ms"
        else:
            oaep = f"{'(N quá nhỏ)':>9} | {'':>9}"
        print(f"{bits:>10} | {t_gen:>8.2f}s | {t_sign * 1000:>7.1f}ms | {t_pss * 1000:>7.1f}ms "
              f"| {t_ver * 1000:>7.1f}ms | {oaep}")
    print("   Nhận xét: ký/giải mã dùng d (lớn, ~N bit) nên chậm hơn hẳn kiểm tra/mã hóa dùng e = 65537 (17 bit);")
    print("   tăng gấp đôi độ dài khóa thì thời gian ký tăng khoảng 6-8 lần (độ phức tạp ~ O(k^3)).")

    print("\n2) THEO KÍCH THƯỚC DỮ LIỆU (khóa 1024 bit)")
    print(f"{'Dữ liệu':>10} | {'SHA-256':>9} | {'Ký (băm+ký)':>12} | {'Ký rồi mã hóa':>14} | {'Giải mã+kiểm tra':>16}")
    print("-" * 76)
    a_priv, a_pub = generate_keypair(keysize=1024)
    b_priv, b_pub = generate_keypair(keysize=1024)
    for size in data_sizes:
        data = os.urandom(size)
        t_hash, _ = timeit(lambda: hash_sha256(data))
        t_sign, _ = timeit(lambda: rsa_full.sign_message(data, a_priv))
        t_seal, env = timeit(lambda: sm.seal(data, "Alice", a_priv, "Bob", b_pub))
        t_open, _ = timeit(lambda: sm.open_sealed(env, "Bob", b_priv, {"Alice": a_pub}.get))
        label = f"{size // 1024} KB"
        print(f"{label:>10} | {t_hash:>8.3f}s | {t_sign:>11.3f}s | {t_seal:>13.3f}s | {t_open:>15.3f}s")
    print("   Nhận xét: phần RSA có chi phí cố định (1 phép lũy thừa) bất kể dữ liệu dài bao nhiêu;")
    print("   thời gian tăng tuyến tính theo dữ liệu là do băm SHA-256 và dòng khóa đối xứng.")
    print("   => Đây là lý do phải KÝ TRÊN GIÁ TRỊ BĂM và MÃ HÓA LAI thay vì RSA trực tiếp trên dữ liệu.")


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    run_benchmark(real="--real" in sys.argv)
