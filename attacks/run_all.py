"""Chạy toàn bộ tấn công minh họa và in bảng tổng kết."""
import os
import sys
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from attacks import (small_n, forgery_no_padding, bleichenbacher_e3, hash_collision, weak_keys, crt_fault,
                     confidentiality)


def _pair(result):
    """Chuẩn hóa kết quả demo về (tấn công thành công trên cấu hình yếu, bị chặn trên cấu hình đúng)."""
    return result if isinstance(result, tuple) else (result, None)


# (mã, tên, khâu bị tấn công, cấu hình yếu, biện pháp, hàm chạy (verbose) -> kết quả)
ATTACKS = [
    ("A1", "Phân tích N nhỏ", "Độ dài khóa", "N = 3233", "N >= 2048 bit",
     lambda v: small_n.demo_small_n(verbose=v)),
    ("A2", "Giả mạo tồn tại", "Lược đồ ký", "RSA thuần", "Băm + đệm",
     lambda v: forgery_no_padding.demo_existential_forgery(verbose=v)),
    ("A3", "Giả mạo nhân tính", "Lược đồ ký", "RSA thuần", "Băm + đệm",
     lambda v: (forgery_no_padding.demo_no_padding_forgery(verbose=v),
                forgery_no_padding.padding_blocks_forgery())),
    ("A4", "Bleichenbacher 2006 (e = 3)", "Cài đặt kiểm tra", "Kiểm tra đệm lỏng", "Kiểm tra chặt",
     lambda v: (lambda r: (r[0], not r[1]))(bleichenbacher_e3.demo_bleichenbacher(keysize=1536, verbose=v))),
    ("A5", "Va chạm băm (ngày sinh)", "Hàm băm", "Băm 24 bit", "SHA-256",
     lambda v: hash_collision.demo_hash_collision(verbose=v)),
    ("A6", "Phân tích Fermat", "Sinh khóa", "p ≈ q", "|p - q| lớn",
     lambda v: weak_keys.demo_fermat(verbose=v)),
    ("A7", "Chung thừa số (gcd)", "Sinh khóa", "Thiếu entropy", "CSPRNG",
     lambda v: weak_keys.demo_shared_prime(verbose=v)),
    ("A8", "Dùng chung modulus N", "Quản lý khóa", "Chung N", "N riêng",
     lambda v: weak_keys.demo_common_modulus(verbose=v)),
    ("A9", "Lỗi phần cứng khi ký CRT", "Thiết bị ký", "Không tự kiểm tra", "Kiểm tra S^e",
     lambda v: crt_fault.demo_crt_fault(verbose=v)),
    ("A10", "Từ điển (RSA tất định)", "Mã hóa", "RSA thuần", "OAEP",
     lambda v: confidentiality.demo_dictionary(verbose=v)),
    ("A11", "Ký song song mã hóa", "Ghép ký + mã hóa", "Enc(M)||Sig(M)", "Ký rồi mã hóa",
     lambda v: confidentiality.demo_encrypt_and_sign_leak(verbose=v)),
    ("A12", "Håstad (e = 3, 3 người nhận)", "Mã hóa", "RSA thuần", "OAEP",
     lambda v: confidentiality.demo_hastad(verbose=v)),
    ("A13", "Dùng chung khóa ký & giải mã", "Quản lý khóa", "Một cặp khóa", "Tách key_usage",
     lambda v: confidentiality.demo_same_key_sign_decrypt(verbose=v)),
]


def run_all(verbose=True):
    """:return: True nếu mọi tấn công phá được cấu hình yếu và (khi có kiểm tra) bị cấu hình đúng chặn"""
    results = []
    for code, name, target, weak, fix, fn in ATTACKS:
        if verbose:
            print(f"\n=== {code}. {name.upper()} ===")
        t = time.perf_counter()
        broken, blocked = _pair(fn(verbose))
        results.append((code, name, target, weak, fix, broken, blocked, time.perf_counter() - t))
    print("\n" + "=" * 118)
    print("TỔNG KẾT TẤN CÔNG MINH HỌA")
    print(f"{'Mã':<4}| {'Tấn công':<29}| {'Khâu bị tấn công':<17}| {'Cấu hình yếu':<18}| {'Phá được?':<10}"
          f"| {'Biện pháp':<14}| {'Bị chặn?':<9}| Thời gian")
    print("-" * 118)
    for code, name, target, weak, fix, broken, blocked, dt in results:
        blocked_txt = "—" if blocked is None else ("CÓ" if blocked else "KHÔNG")
        print(f"{code:<4}| {name:<29}| {target:<17}| {weak:<18}| {'CÓ' if broken else 'KHÔNG':<10}"
              f"| {fix:<14}| {blocked_txt:<9}| {dt:.2f}s")
    return all(broken and blocked is not False for *_, broken, blocked, _ in results)


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    sys.exit(0 if run_all(verbose="-q" not in sys.argv) else 1)
