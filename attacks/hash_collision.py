"""
attacks/hash_collision.py
[Báo cáo 2.5, 3.6.2 - Va chạm hàm băm, nghịch lý ngày sinh (tấn công Yuval 1979); 6.4]
Chữ ký ký trên H(M), nên H(M1) = H(M2) thì chữ ký của M1 cũng là chữ ký của M2.
Mai Phương soạn một hợp đồng THẬT và một hợp đồng GIAN, mỗi bản có nhiều biến thể trông giống hệt nhau
(1 hay 2 dấu cách giữa các từ). Với hàm băm k bit, nghịch lý ngày sinh cho va chạm sau ~2^(k/2)
biến thể mỗi bên, thay vì 2^k. Mai Phương đưa bản thật cho Thu Trang ký, rồi dùng chữ ký đó cho bản gian.
Mô phỏng hàm băm yếu bằng cách cắt SHA-256 còn k bit; với SHA-256 đủ 256 bit cần ~2^128 phép băm.
"""
import os
import sys
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.rsa_math import generate_keypair
from core.rsa_full import sign_hash, verify_hash
from core.sha256 import sha256_bytes

HONEST = ("Bên A đồng ý bán cho bên B lô hàng 100 máy tính với giá 1.500.000.000 đồng, "
          "thanh toán trong vòng 30 ngày kể từ ngày giao hàng, bảo hành 24 tháng tại trụ sở bên A")
FRAUD = ("Bên A đồng ý bán cho bên B lô hàng 100 máy tính với giá 150.000.000 đồng, "
         "bên A chịu toàn bộ chi phí vận chuyển và bồi thường gấp đôi nếu giao hàng chậm một ngày")


def weak_hash(message, bits):
    """Hàm băm yếu k bit: k bit đầu của SHA-256, trả về dạng hex đủ 64 ký tự để đưa vào khối đệm."""
    h = int.from_bytes(sha256_bytes(message), "big") >> (256 - bits)
    return (h << (256 - bits)).to_bytes(32, "big").hex()


def variant(text, index):
    """Biến thể thứ `index`: bit thứ i của index = 1 thì sau từ thứ i có 2 dấu cách thay vì 1."""
    words = text.split(" ")
    out = [words[0]]
    for i, w in enumerate(words[1:]):
        out.append(("  " if index >> i & 1 else " ") + w)
    return "".join(out).encode("utf-8")


def birthday_attack(honest, fraud, bits):
    """
    Lưu 2^(k/2 + 1) biến thể bản thật vào bảng băm, rồi thử biến thể bản gian tới khi trùng.
    :return: (bản thật, bản gian, số phép băm) hoặc None
    """
    table = {}
    for i in range(min(1 << (bits // 2 + 1), 1 << (len(honest.split(" ")) - 1))):
        m = variant(honest, i)
        table.setdefault(weak_hash(m, bits), m)
    for j in range(1 << (len(fraud.split(" ")) - 1)):
        m = variant(fraud, j)
        hit = table.get(weak_hash(m, bits))
        if hit is not None:
            return hit, m, len(table) + j + 1
    return None


def demo_hash_collision(bits=24, keysize=1024, verbose=True):
    """:return: (va chạm với hàm băm k bit làm giả được chữ ký, SHA-256 đủ thì chữ ký không dùng lại được)"""
    say = print if verbose else (lambda *a, **k: None)
    priv, pub = generate_keypair(keysize=keysize)
    say(f"[1] Hệ thống dùng hàm băm yếu {bits} bit. Mai Phương soạn 2 hợp đồng:")
    say(f"    THẬT: '{HONEST}'")
    say(f"    GIAN: '{FRAUD}'")
    t = time.perf_counter()
    res = birthday_attack(HONEST, FRAUD, bits)
    dt = time.perf_counter() - t
    if res is None:
        say("    Không tìm được va chạm")
        return False, False
    m1, m2, tries = res
    say(f"[2] Mai Phương tạo biến thể (thêm dấu cách) và tìm va chạm sau {tries} phép băm ({dt:.1f}s), "
        f"thay vì ~2^{bits} = {1 << bits}:")
    say(f"    H(thật) = {weak_hash(m1, bits)[:bits // 4]}  =  H(gian) = {weak_hash(m2, bits)[:bits // 4]}")
    sig = sign_hash(weak_hash(m1, bits), priv)
    say("[3] Thu Trang đọc bản thật (chỉ khác vài dấu cách, trông bình thường) và ký.")
    forged = verify_hash(weak_hash(m2, bits), sig, pub)
    say(f"[4] Mai Phương gắn chữ ký đó vào bản gian -> kiểm tra: "
        f"{'HỢP LỆ -> Thu Trang bị ràng buộc bởi hợp đồng gian' if forged else 'sai'}")
    safe = not verify_hash(sha256_bytes(m2).hex(), sign_hash(sha256_bytes(m1).hex(), priv), pub)
    rate = tries / dt if dt else 0
    years = (2 ** 128 / rate / 3600 / 24 / 365) if rate else float("inf")
    say(f"[5] Với SHA-256 đủ 256 bit: chữ ký bản thật KHÔNG hợp lệ cho bản gian ({safe}); muốn tìm va chạm "
        f"cần ~2^128 phép băm ≈ {years:.1e} năm ở tốc độ {rate:,.0f} băm/giây.")
    say("[!] Phòng chống: hàm băm >= 256 bit, không dùng MD5/SHA-1 (va chạm SHA-1 thật: SHAttered 2017); "
        "PSS thêm muối ngẫu nhiên do người ký chọn.")
    return forged, safe


if __name__ == "__main__":
    demo_hash_collision()
