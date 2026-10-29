"""Số học RSA: Euclid, bình phương và nhân, Miller-Rabin, sinh khóa."""
import secrets

DEFAULT_E = 65537
MIN_SECURE_BITS = 2048          # NIST SP 800-57: RSA 2048 bit ~ 112 bit an toàn


# Euclid, nghịch đảo modulo
def gcd(a, b):
    """Ước chung lớn nhất (thuật toán Euclid)."""
    while b:
        a, b = b, a % b
    return a


def extended_gcd(a, b):
    """
    Euclid mở rộng (dạng lặp, không bị giới hạn đệ quy với số lớn).
    :return: (g, x, y) sao cho a*x + b*y = g = gcd(a, b)
    """
    old_r, r = a, b
    old_x, x = 1, 0
    old_y, y = 0, 1
    while r:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_x, x = x, old_x - q * x
        old_y, y = y, old_y - q * y
    return old_r, old_x, old_y


def extended_gcd_table(a, b):
    """Euclid mở rộng trả về cả bảng các bước (dùng để in ví dụ tính tay)."""
    rows = []
    old_r, r = a, b
    old_x, x = 1, 0
    old_y, y = 0, 1
    while r:
        q = old_r // r
        rows.append((old_r, r, q, old_x, old_y))
        old_r, r = r, old_r - q * r
        old_x, x = x, old_x - q * x
        old_y, y = y, old_y - q * y
    rows.append((old_r, 0, None, old_x, old_y))
    return rows


def mod_inverse(e, phi):
    """Nghịch đảo modulo: tìm d sao cho e*d ≡ 1 (mod phi)."""
    g, x, _ = extended_gcd(e, phi)
    if g != 1:
        raise ValueError(f"gcd({e}, {phi}) = {g} != 1, không có nghịch đảo modulo")
    return x % phi


# Bình phương và nhân
def mod_exp(base, exp, mod, trace=None):
    """
    Lũy thừa modulo base^exp mod mod bằng thuật toán bình phương và nhân
    (duyệt bit của số mũ từ trái sang phải).
    :param trace: nếu truyền vào một list, mỗi bước được ghi (bit, giá trị sau bước) để in ra.
    """
    if mod == 1:
        return 0
    if exp < 0:
        raise ValueError("Số mũ phải không âm")
    base %= mod
    result = 1
    for bit in bin(exp)[2:]:
        result = (result * result) % mod          # bình phương
        if bit == "1":
            result = (result * base) % mod        # nhân
        if trace is not None:
            trace.append((bit, result))
    return result


# Miller-Rabin, sinh số nguyên tố
SMALL_PRIMES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71)


def is_prime(n, rounds=40):
    """
    Kiểm tra nguyên tố Miller-Rabin. Xác suất nhận nhầm hợp số <= 4^(-rounds).
    Chia thử các số nguyên tố nhỏ trước để loại nhanh.
    """
    if n < 2:
        return False
    for p in SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False
    # n - 1 = 2^r * d với d lẻ
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    for _ in range(rounds):
        a = 2 + secrets.randbelow(n - 3)          # a ngẫu nhiên trong [2, n-2]
        x = mod_exp(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False                          # a là "nhân chứng": n chắc chắn là hợp số
    return True


def random_odd(bits):
    """Số lẻ ngẫu nhiên có đúng `bits` bit (2 bit cao nhất bằng 1 để p*q đủ 2*bits bit)."""
    return secrets.randbits(bits) | (0b11 << (bits - 2)) | 1


def generate_prime(bits):
    """Sinh số nguyên tố ngẫu nhiên có đúng `bits` bit."""
    if bits < 8:
        raise ValueError("Số bit quá nhỏ")
    while True:
        p = random_odd(bits)
        if is_prime(p):
            return p


# Sinh khóa RSA
def generate_keypair(p=None, q=None, e=None, keysize=None):
    """
    Sinh cặp khóa RSA: N = p*q, phi = (p-1)(q-1), e*d ≡ 1 (mod phi).
    - Ví dụ tính tay: truyền p, q (và e nếu đề cho sẵn).
    - Thực tế: chỉ truyền keysize (vd 1024, 2048).

    :return: (khóa riêng (d, N), khóa công khai (e, N))
    """
    if p is None or q is None:
        if keysize is None:
            raise ValueError("Phải truyền p, q hoặc keysize")
        half = keysize // 2
        while True:
            p = generate_prime(half)
            q = generate_prime(keysize - half)
            # p, q phải khác nhau, không quá gần nhau (chống phân tích Fermat), gcd(e, phi) = 1
            if p != q and abs(p - q).bit_length() > half - 100:
                if gcd(e or DEFAULT_E, (p - 1) * (q - 1)) == 1:
                    break
    else:
        if p == q:
            raise ValueError("p và q phải khác nhau (p = q thì N = p^2, phá được ngay)")
        if not (is_prime(p) and is_prime(q)):
            raise ValueError("p và q phải là số nguyên tố")

    N = p * q
    phi = (p - 1) * (q - 1)

    if e is None:
        e = DEFAULT_E
        if gcd(e, phi) != 1:            # chỉ xảy ra với p, q nhỏ do người dùng truyền vào
            e = 3
            while gcd(e, phi) != 1:
                e += 2
    elif not (1 < e < phi and gcd(e, phi) == 1):
        raise ValueError(f"e={e} không hợp lệ: cần 1 < e < phi và gcd(e, phi) = 1")

    d = mod_inverse(e, phi)
    return (d, N), (e, N)


generate_key_pair = generate_keypair      # bí danh theo tên trong thiết kế ban đầu


def explain_keygen(p, q, e):
    """Trả về các dòng giải thích từng bước sinh khóa (dùng cho ví dụ tính tay)."""
    N, phi = p * q, (p - 1) * (q - 1)
    lines = [
        f"N      = p*q = {p}*{q} = {N}",
        f"phi(N) = (p-1)(q-1) = {p - 1}*{q - 1} = {phi}",
        f"Chọn e = {e}, gcd({e}, {phi}) = {gcd(e, phi)}",
        f"Tìm d = e^-1 mod phi bằng Euclid mở rộng trên ({phi}, {e}):",
        "      r_{i-1}    r_i    q    |   x    y",
    ]
    for r0, r1, qq, x, y in extended_gcd_table(phi, e):
        lines.append(f"    {r0:>8} {r1:>7} {'' if qq is None else qq:>4}    | {x:>4} {y:>4}")
    d = mod_inverse(e, phi)
    lines.append(f"  => d = {d}   (kiểm tra e*d mod phi = {e}*{d} mod {phi} = {(e * d) % phi})")
    return lines


# Tiện ích
def compare_hashes(hash_A, hash_B):
    """
    So sánh hai bản băm (hoặc hai chuỗi byte) để kiểm tra toàn vẹn và xác thực.
    So sánh thời gian hằng: luôn duyệt hết chuỗi, tránh lộ thông tin qua thời gian phản hồi.
    :return: True nếu khớp, False nếu khác hoặc một trong hai là None
    """
    if hash_A is None or hash_B is None:
        return False
    a = hash_A.encode() if isinstance(hash_A, str) else bytes(hash_A)
    b = hash_B.encode() if isinstance(hash_B, str) else bytes(hash_B)
    if len(a) != len(b):
        return False
    diff = 0
    for x, y in zip(a, b):
        diff |= x ^ y
    return diff == 0


def int_to_bytes(x, length):
    """I2OSP (RFC 8017): số nguyên -> chuỗi byte độ dài cố định."""
    if x < 0 or x >= 256 ** length:
        raise ValueError("Số nguyên quá lớn so với độ dài yêu cầu")
    return x.to_bytes(length, "big")


def bytes_to_int(b):
    """OS2IP (RFC 8017): chuỗi byte -> số nguyên."""
    return int.from_bytes(b, "big")


def byte_length(n):
    """Số byte để biểu diễn modulus N (k trong RFC 8017)."""
    return (n.bit_length() + 7) // 8


def integer_cuberoot_ceil(x):
    """Căn bậc ba nguyên làm tròn LÊN (Newton trên số nguyên, không tràn số như float)."""
    if x < 2:
        return x
    r = 1 << ((x.bit_length() + 2) // 3 + 1)
    while True:
        nr = (2 * r + x // (r * r)) // 3
        if nr >= r:
            break
        r = nr
    while r ** 3 < x:
        r += 1
    while (r - 1) ** 3 >= x:
        r -= 1
    return r


if __name__ == "__main__":
    print("=== Ví dụ tính tay: p=17, q=11, e=7 ===")
    for line in explain_keygen(17, 11, 7):
        print(line)
    print("\n=== Khóa ngẫu nhiên 1024-bit ===")
    priv, pub = generate_keypair(keysize=1024)
    print("N có", pub[1].bit_length(), "bit; e =", pub[0])
