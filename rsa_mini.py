# Tệp: rsa_mini.py
# Bản thu nhỏ RSA với bộ số: p=17, q=11, e=7, M=88
from keygen import generate_keypair


def mod_exp(base, exp, mod):
    """Lũy thừa modulo bằng bình phương liên tiếp."""
    result = 1
    base %= mod
    while exp > 0:
        if exp & 1:
            result = (result * base) % mod
        base = (base * base) % mod
        exp >>= 1
    return result


def encrypt(m, public_key):
    """C = M^e mod N"""
    e, N = public_key
    if not 0 <= m < N:
        raise ValueError(f"Bản rõ phải thỏa 0 <= M < N = {N}")
    return mod_exp(m, e, N)


def decrypt(c, private_key):
    """M = C^d mod N"""
    d, N = private_key
    return mod_exp(c, d, N)


def sign(m, private_key):
    """Ký số (bản thu nhỏ, không băm/đệm): S = M^d mod N"""
    d, N = private_key
    return mod_exp(m, d, N)


def verify(m, s, public_key):
    """Xác thực: M' = S^e mod N, so sánh với M"""
    e, N = public_key
    return mod_exp(s, e, N) == m


if __name__ == "__main__":
    p, q, e, M = 17, 11, 7, 88

    private_key, public_key = generate_keypair(p=p, q=q, e=e)
    d, N = private_key
    phi = (p - 1) * (q - 1)

    print("--- Bước 1: Sinh khóa ---")
    print(f"N = p*q = {p}*{q} = {N}")
    print(f"phi(N) = (p-1)(q-1) = {p-1}*{q-1} = {phi}")
    print(f"e = {e}  (gcd(e, phi) = 1)")
    print(f"d = e^-1 mod phi = {d}  (kiểm tra: e*d mod phi = {(e * d) % phi})")
    print("Khóa công khai (e, N):", public_key)
    print("Khóa riêng     (d, N):", private_key)

    print("\n--- Bước 2: Mã hóa ---")
    C = encrypt(M, public_key)
    print(f"C = M^e mod N = {M}^{e} mod {N} = {C}")

    print("\n--- Bước 3: Giải mã ---")
    M2 = decrypt(C, private_key)
    print(f"M = C^d mod N = {C}^{d} mod {N} = {M2}")
    print("Giải mã đúng bản rõ:", "Thành công ✅" if M2 == M else "Thất bại ❌")

    print("\n--- Bước 4: Ký số & xác thực (mở rộng) ---")
    S = sign(M, private_key)
    print(f"Chữ ký S = M^d mod N = {M}^{d} mod {N} = {S}")
    print("Xác thực chữ ký đúng:", "Thành công ✅" if verify(M, S, public_key) else "Thất bại ❌")
    print("Xác thực với M bị sửa (M=89):", "Thành công ✅" if verify(89, S, public_key) else "Thất bại (Phát hiện giả mạo) ❌")
