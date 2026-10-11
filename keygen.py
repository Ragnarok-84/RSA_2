# Tệp: keygen.py
import random


def gcd(a, b):
    """Ước chung lớn nhất (thuật toán Euclid)."""
    while b:
        a, b = b, a % b
    return a


def extended_gcd(a, b):
    """Euclid mở rộng: trả về (gcd, x, y) sao cho a*x + b*y = gcd."""
    if a == 0:
        return b, 0, 1
    g, x1, y1 = extended_gcd(b % a, a)
    return g, y1 - (b // a) * x1, x1


def mod_inverse(e, phi):
    """Nghịch đảo modulo: tìm d sao cho e*d ≡ 1 (mod phi)."""
    g, x, _ = extended_gcd(e, phi)
    if g != 1:
        raise ValueError("e và phi(N) không nguyên tố cùng nhau, không có nghịch đảo")
    return x % phi


def is_prime(n, rounds=20):
    """Kiểm tra nguyên tố Miller-Rabin."""
    if n < 2:
        return False
    for small in (2, 3, 5, 7, 11, 13):
        if n == small:
            return True
        if n % small == 0:
            return False
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits):
    """Sinh số nguyên tố ngẫu nhiên có đúng 'bits' bit."""
    while True:
        p = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if is_prime(p):
            return p


def generate_keypair(p=None, q=None, e=None, keysize=None):
    """
    Sinh cặp khóa RSA.
    - Ví dụ tính tay: truyền p, q (và e nếu đề cho sẵn).
    - Thực tế: chỉ truyền keysize (vd 1024, 2048).

    :return: (khóa riêng (d, N), khóa công khai (e, N))
    """
    if p is None or q is None:
        if keysize is None:
            raise ValueError("Phải truyền p, q hoặc keysize")
        p = generate_prime(keysize // 2)
        q = generate_prime(keysize // 2)
        while q == p:
            q = generate_prime(keysize // 2)

    N = p * q
    phi = (p - 1) * (q - 1)

    if e is None:
        e = 65537
        if gcd(e, phi) != 1:
            e = 3
            while gcd(e, phi) != 1:
                e += 2
    elif not (1 < e < phi and gcd(e, phi) == 1):
        raise ValueError(f"e={e} không hợp lệ: cần 1 < e < phi và gcd(e, phi) = 1")

    d = mod_inverse(e, phi)
    return (d, N), (e, N)


# --- Chạy thử ---
if __name__ == "__main__":
    print("=== Ví dụ tính tay: p=17, q=11, e=7 ===")
    private, public = generate_keypair(p=17, q=11, e=7)
    print("N = p*q        =", 17 * 11)
    print("phi(N)         =", 16 * 10)
    print("Khóa công khai =", public)
    print("Khóa riêng     =", private)

    print("\n=== Khóa ngẫu nhiên 512-bit ===")
    priv, pub = generate_keypair(keysize=512)
    print("N có", pub[1].bit_length(), "bit; e =", pub[0])
