"""
attacks/weak_keys.py
[Báo cáo 3.6.2 - Sinh khóa yếu, modulus dùng chung; 6.4 - Tấn công minh họa]
Ba tấn công vào KHÂU SINH KHÓA. Thuật toán ký không sai, nhưng khóa sinh kém thì N bị phân tích:
  1. Fermat      : p, q quá gần nhau -> N = a^2 - b^2 với a ≈ sqrt(N), tìm được sau vài bước.
  2. Chung thừa số: bộ sinh số ngẫu nhiên kém làm hai khóa có chung p -> gcd(N1, N2) = p
                   (Lenstra và cộng sự; Heninger và cộng sự, 2012: hàng chục nghìn khóa thật trên Internet).
  3. Dùng chung N : hai người cùng N, khác e. Ai biết (e, d) của mình đều phân tích được N
                   -> tính ra khóa riêng của người kia.
"""
import math
import os
import secrets
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.rsa_math import generate_keypair, generate_prime, is_prime, gcd, mod_inverse
from core.rsa_full import sign_message, verify_message


def _say(verbose):
    return print if verbose else (lambda *a, **k: None)


def next_prime(n):
    n += 1 + n % 2
    while not is_prime(n):
        n += 2
    return n


# 1. Phân tích Fermat ----------------------------------------------------
def fermat_factor(n, max_steps=100_000):
    """
    Tìm a >= sqrt(n) sao cho a^2 - n là số chính phương b^2 -> n = (a - b)(a + b).
    Số bước ≈ (p - q)^2 / (8 sqrt(n)): p, q càng gần nhau càng nhanh.
    :return: (p, q, số bước) hoặc None nếu vượt max_steps
    """
    a = math.isqrt(n)
    if a * a < n:
        a += 1
    for step in range(1, max_steps + 1):
        b2 = a * a - n
        b = math.isqrt(b2)
        if b * b == b2:
            return a - b, a + b, step
        a += 1
    return None


def demo_fermat(keysize=1024, verbose=True):
    """:return: (khóa yếu bị phá, khóa sinh đúng cách không bị phá)"""
    say = _say(verbose)
    half = keysize // 2
    p = generate_prime(half)
    q = next_prime(p + secrets.randbits(half // 2 + 6))  # lỗi: q tìm tiếp từ p thay vì sinh độc lập
    weak_priv, weak_pub = generate_keypair(p=p, q=q)
    say(f"[1] Bộ sinh khóa lỗi: chọn p ngẫu nhiên {half} bit, rồi tìm q từ p cộng thêm một số ngẫu nhiên "
        f"{half // 2 + 6} bit.")
    say(f"    N = {str(weak_pub[1])[:40]}... ({weak_pub[1].bit_length()} bit), |p - q| ≈ 2^{(q - p).bit_length()}"
        f" (rất lớn nhưng nhỏ hơn nhiều so với p ≈ 2^{half})")
    res = fermat_factor(weak_pub[1])
    broken = False
    if res:
        fp, fq, steps = res
        d = mod_inverse(weak_pub[0], (fp - 1) * (fq - 1))
        fake = "Thu Trang chuyển toàn bộ tài sản cho Mai Phương"
        broken = d == weak_priv[0] and verify_message(fake, sign_message(fake, (d, weak_pub[1])), weak_pub)
        say(f"[2] Mai Phương chạy Fermat: tìm ra p, q sau {steps} bước -> tính được d, ký giả '{fake}': "
            f"{'HỢP LỆ' if broken else 'sai'}")
    _, good_pub = generate_keypair(keysize=keysize)
    safe = fermat_factor(good_pub[1], max_steps=20_000) is None
    say(f"[3] Khóa sinh bởi core/rsa_math (bắt buộc |p - q| > 2^(n/2 - 100)): Fermat 20.000 bước -> "
        f"{'không phân tích được' if safe else 'BỊ PHÂN TÍCH'}")
    say("[!] Phòng chống: sinh p, q độc lập, kiểm tra |p - q| đủ lớn (FIPS 186-5 mục A.1.3).")
    return broken, safe


# 2. Hai khóa chung một thừa số nguyên tố --------------------------------
def find_shared_primes(moduli):
    """Tính gcd từng cặp modulus. :return: danh sách (i, j, p) với gcd(N_i, N_j) = p > 1"""
    found = []
    for i in range(len(moduli)):
        for j in range(i + 1, len(moduli)):
            g = gcd(moduli[i], moduli[j])
            if 1 < g < moduli[i]:
                found.append((i, j, g))
    return found


def demo_shared_prime(keysize=1024, count=6, verbose=True):
    """:return: (khóa trùng thừa số bị phá, các khóa còn lại an toàn)"""
    say = _say(verbose)
    half = keysize // 2
    keys = [generate_keypair(keysize=keysize) for _ in range(count - 2)]
    p = generate_prime(half)                             # lỗi: thiết bị khởi động thiếu entropy
    keys += [generate_keypair(p=p, q=generate_prime(half)), generate_keypair(p=p, q=generate_prime(half))]
    order = list(range(count))
    secrets.SystemRandom().shuffle(order)
    keys = [keys[i] for i in order]
    owners = [f"Thiết bị {i + 1}" for i in range(count)]
    moduli = [pub[1] for _, pub in keys]
    say(f"[1] Mai Phương thu thập {count} khóa công khai {keysize} bit trên mạng. Hai thiết bị sinh khóa lúc thiếu "
        "entropy nên vô tình dùng chung một số nguyên tố p.")
    found = find_shared_primes(moduli)
    say(f"[2] Mai Phương tính gcd của {count * (count - 1) // 2} cặp modulus (không cần phân tích N nào):")
    broken = len(found) == 1
    for i, j, g in found:
        for k in (i, j):
            e, n = keys[k][1]
            d = mod_inverse(e, (g - 1) * (n // g - 1))
            broken = broken and d == keys[k][0][0]
        say(f"    gcd(N của {owners[i]}, N của {owners[j]}) = p ({g.bit_length()} bit) "
            f"-> q = N / p -> lộ khóa riêng của CẢ HAI")
    say(f"[3] Các cặp còn lại: gcd = 1, không lộ gì ({count * (count - 1) // 2 - len(found)} cặp).")
    say("[!] Phòng chống: nguồn ngẫu nhiên an toàn (CSPRNG, đủ entropy lúc khởi động), "
        "kiểm tra khóa mới không trùng thừa số với khóa đã biết.")
    return broken, len(found) == 1


# 3. Dùng chung modulus N ------------------------------------------------
def factor_from_private_exponent(e, d, n):
    """
    Biết (e, d) của một khóa thì phân tích được N (thuật toán xác suất, RFC 8017 / Boneh 1999):
    k = e*d - 1 = 2^t * r; với g ngẫu nhiên, dãy g^r, g^2r, ... sớm gặp x ≠ ±1 mà x^2 = 1 mod N
    -> gcd(x - 1, N) là một thừa số.
    """
    k = e * d - 1
    r, t = k, 0
    while r % 2 == 0:
        r //= 2
        t += 1
    for _ in range(100):
        g = secrets.randbelow(n - 3) + 2
        x = pow(g, r, n)
        for _ in range(t):
            y = pow(x, 2, n)
            if y == 1 and x not in (1, n - 1):
                p = gcd(x - 1, n)
                return p, n // p
            x = y
    raise ValueError("Không phân tích được N")


def demo_common_modulus(keysize=1024, verbose=True):
    """:return: (Thu Thủy lấy được khóa riêng của Thu Trang, mỗi người N riêng thì không làm được)"""
    say = _say(verbose)
    half = keysize // 2
    p, q = generate_prime(half), generate_prime(keysize - half)
    alice_priv, alice_pub = generate_keypair(p=p, q=q, e=65537)
    bob_e = next(e for e in (3, 5, 17, 257, 641) if gcd(e, (p - 1) * (q - 1)) == 1)
    bob_priv, bob_pub = generate_keypair(p=p, q=q, e=bob_e)
    n = alice_pub[1]
    say(f"[1] Để 'tiết kiệm', công ty cấp cho mọi nhân viên CÙNG một N ({keysize} bit), chỉ khác e:")
    say(f"    Thu Trang: e = {alice_pub[0]}, Thu Thủy: e = {bob_pub[0]}. Ai cũng chỉ biết d của mình.")
    fp, fq = factor_from_private_exponent(bob_pub[0], bob_priv[0], n)
    d_alice = mod_inverse(alice_pub[0], (fp - 1) * (fq - 1))
    fake = "Thu Trang đồng ý cho Thu Thủy nghỉ phép 365 ngày, hưởng nguyên lương"
    forged = sign_message(fake, (d_alice, n))
    broken = d_alice == alice_priv[0] and verify_message(fake, forged, alice_pub)
    say("[2] Thu Thủy dùng (e_B, d_B) của chính mình phân tích N -> p, q")
    say(f"[3] Thu Thủy tính d_A = e_A^-1 mod phi(N) và ký '{fake}' nhân danh Thu Trang: "
        f"{'HỢP LỆ' if broken else 'sai'}")
    other_priv, other_pub = generate_keypair(keysize=keysize)
    fp2, fq2 = factor_from_private_exponent(other_pub[0], other_priv[0], other_pub[1])
    safe = n % fp2 != 0 and n % fq2 != 0
    say(f"[4] Nếu Thu Thủy có N riêng: phân tích N của Thu Thủy không cho thông tin gì về N của Thu Trang -> "
        f"{'an toàn' if safe else 'lỗi'}")
    say("[!] Phòng chống: mỗi người một N riêng (p, q sinh mới cho từng khóa).")
    return broken, safe


if __name__ == "__main__":
    for fn in (demo_fermat, demo_shared_prime, demo_common_modulus):
        print(f"\n=== {fn.__name__} ===")
        fn()
