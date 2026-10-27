"""
demo/avalanche.py
[Báo cáo 2.5 - Lý do ký trên giá trị băm]
Minh họa vì sao hệ chữ ký RSA ký trên SHA-256(M) thay vì ký trực tiếp M:
  1. Hiệu ứng thác lũ: đổi 1 bit của M -> khoảng 50% bit của SHA-256(M) đổi theo,
     nên không thể sửa M mà giữ nguyên giá trị đã ký.
  2. Kích thước: RSA chỉ ký được số < N. Ký trực tiếp một tệp 88 KB phải chia hàng trăm khối,
     mỗi khối một phép lũy thừa; ký trên băm luôn chỉ 1 phép lũy thừa cho 32 byte.
  3. Ký từng khối rời rạc còn cho phép kẻ tấn công đổi chỗ / xóa / ghép khối mà chữ ký từng khối vẫn đúng.
  4. Tính đồng cấu của RSA thô bị phá (xem attacks/forgery_no_padding.py).
"""
import os
import sys
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.sha256 import hash_sha256, sha256_bytes
from core.rsa_math import generate_keypair, mod_exp, byte_length, bytes_to_int
from core.rsa_full import sign_message


def bit_diff(a, b):
    """Số bit khác nhau giữa hai chuỗi byte cùng độ dài."""
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def flip_bit(data, bit_index):
    b = bytearray(data)
    b[bit_index // 8] ^= 1 << (7 - bit_index % 8)
    return bytes(b)


def avalanche_stats(message, trials=None):
    """Đổi lần lượt từng bit của thông điệp, đo số bit SHA-256 thay đổi. :return: (min, trung bình, max)"""
    base = sha256_bytes(message)
    n_bits = len(message) * 8
    idx = range(n_bits) if trials is None else range(0, n_bits, max(1, n_bits // trials))
    diffs = [bit_diff(base, sha256_bytes(flip_bit(message, i))) for i in idx]
    return min(diffs), sum(diffs) / len(diffs), max(diffs)


def run_demo(verbose=True, keysize=1024):
    say = print if verbose else (lambda *a, **k: None)
    say("=" * 66)
    say("1) HIỆU ỨNG THÁC LŨ CỦA SHA-256")
    say("=" * 66)
    m1 = "Alice chuyển 100.000.000 VNĐ cho Bob".encode()
    m2 = flip_bit(m1, 8 * m1.index(b"1") + 7)    # đổi bit thấp nhất của '1' (0x31) -> '0' (0x30)
    h1, h2 = sha256_bytes(m1), sha256_bytes(m2)
    d = bit_diff(h1, h2)
    say(f"  M  = {m1.decode()}")
    say(f"  M' = {m2.decode()}        (khác M đúng 1 bit)")
    say(f"  SHA-256(M)  = {h1.hex()}")
    say(f"  SHA-256(M') = {h2.hex()}")
    say(f"  -> {d}/256 bit khác nhau ({d / 256:.0%})")
    lo, avg, hi = avalanche_stats(m1)
    say(f"  Đổi lần lượt từng bit trong {len(m1) * 8} bit của M: số bit băm thay đổi "
        f"nhỏ nhất {lo}, trung bình {avg:.1f} ({avg / 256:.1%}), lớn nhất {hi}")
    say("  => Sửa dù 1 bit, bản băm đã ký không còn khớp: chữ ký bảo vệ toàn bộ thông điệp.")

    say("\n" + "=" * 66)
    say("2) KÝ TRỰC TIẾP TỪNG KHỐI vs KÝ TRÊN GIÁ TRỊ BĂM")
    say("=" * 66)
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples", "anh_mau.png")
    with open(path, "rb") as f:
        data = f.read()
    priv, pub = generate_keypair(keysize=keysize)
    d_, N = priv
    block = byte_length(N) - 1                   # mỗi khối phải nhỏ hơn N
    blocks = [data[i:i + block] for i in range(0, len(data), block)]
    t = time.perf_counter()
    block_sigs = [mod_exp(bytes_to_int(b), d_, N) for b in blocks]
    t_blocks = time.perf_counter() - t
    t = time.perf_counter()
    sign_message(data, priv)
    t_hash = time.perf_counter() - t
    say(f"  Tệp {os.path.basename(path)}: {len(data):,} byte, khóa {keysize} bit")
    say(f"  Ký từng khối : {len(blocks)} khối -> {len(blocks)} phép lũy thừa, chữ ký dài "
        f"{len(blocks) * byte_length(N):,} byte, {t_blocks:.2f}s")
    say(f"  Ký trên băm  : 1 phép lũy thừa, chữ ký dài {byte_length(N)} byte, {t_hash:.2f}s (gồm cả băm)")

    say("\n" + "=" * 66)
    say("3) KÝ TỪNG KHỐI BỊ ĐỔI CHỖ KHỐI")
    say("=" * 66)
    contract = [b"Ben A: Alice ", b"tra Bob ", b"100 trieu"]
    sigs = [mod_exp(bytes_to_int(b), d_, N) for b in contract]
    swapped = [contract[0], contract[2], contract[1]]
    swapped_sigs = [sigs[0], sigs[2], sigs[1]]
    each_ok = all(mod_exp(s, pub[0], N) == bytes_to_int(b) for s, b in zip(swapped_sigs, swapped))
    say(f"  Gốc     : {b''.join(contract).decode()}")
    say(f"  Đổi chỗ : {b''.join(swapped).decode()}  -> chữ ký từng khối vẫn đúng: {each_ok}")
    h_ok = hash_sha256(b"".join(contract)) == hash_sha256(b"".join(swapped))
    say(f"  Ký trên băm toàn văn bản: băm trùng nhau? {h_ok} -> đổi chỗ bị phát hiện")
    return {"bit_diff": d, "avg_ratio": avg / 256, "blocks": len(blocks), "swap_undetected": each_ok,
            "hash_detects_swap": not h_ok}


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    run_demo()
