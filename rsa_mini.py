# ==================================================
# RSA MINI - THUAT TOAN RSA BAN THU NHO
# Bo so: p = 17, q = 11, e = 7, M = 88
# ==================================================

# 1. KHAI BAO DU LIEU
p = 17
q = 11
e = 7
M = 88


# 2. HAM TINH UCLN (EUCLID)
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


# 3. HAM TIM NGHIEM NGHICH DAO MODULO
def mod_inverse(e, phi):
    for d in range(1, phi):
        if (e * d) % phi == 1:
            return d
    return None


# 4. HAM TAO KHOA RSA
def generate_keys(p, q, e):
    if p <= 1 or q <= 1:
        raise ValueError("p va q phai lon hon 1.")

    n = p * q
    phi = (p - 1) * (q - 1)

    if gcd(p, q) != 1:
        raise ValueError("p va q phai nguyen to cung nhau.")

    if not (1 < e < phi):
        raise ValueError("e phai nam trong khoang tu 1 den phi(n).")

    if gcd(e, phi) != 1:
        raise ValueError("e phai nguyen to cung nhau voi phi(n).")

    d = mod_inverse(e, phi)

    if d is None:
        raise ValueError("Khong tim duoc khoa bi mat d.")

    public_key = (e, n)
    private_key = (d, n)

    return n, phi, public_key, private_key


# 5. HAM MA HOA
def encrypt(M, public_key):
    e, n = public_key

    if not (0 <= M < n):
        raise ValueError("Ban ro M phai thoa man 0 <= M < n.")

    C = pow(M, e, n)
    return C


# 6. HAM GIAI MA
def decrypt(C, private_key):
    d, n = private_key

    if not (0 <= C < n):
        raise ValueError("Ban ma C phai thoa man 0 <= C < n.")

    M = pow(C, d, n)
    return M


# 7. CHUONG TRINH CHINH
def main():
    print("=" * 45)
    print("          CHUONG TRINH RSA MINI")
    print("=" * 45)

    # Tao khoa
    n, phi, public_key, private_key = generate_keys(p, q, e)

    print("\n[1] THONG TIN DAU VAO")
    print("p =", p)
    print("q =", q)
    print("e =", e)
    print("Ban ro M =", M)

    print("\n[2] TINH TOAN")
    print("n = p * q =", n)
    print("phi(n) = (p-1)*(q-1) =", phi)
    print("d =", mod_inverse(e, phi))

    print("\n[3] KHOA RSA")
    print("Khoa cong khai (e, n) =", public_key)
    print("Khoa bi mat (d, n) =", private_key)

    # Ma hoa
    C = encrypt(M, public_key)
    print("\n[4] MA HOA")
    print("C = M^e mod n")
    print(f"C = {M}^{e} mod {n} = {C}")

    # Giai ma
    M_decrypted = decrypt(C, private_key)
    print("\n[5] GIAI MA")
    print("M = C^d mod n")
    print(f"M = {C}^{private_key[0]} mod {n} = {M_decrypted}")

    # Kiem tra
    print("\n[6] KIEM TRA")
    if M == M_decrypted:
        print("THANH CONG: Ban ro sau giai ma trung khop!")
    else:
        print("THAT BAI: Ban ro sau giai ma khong trung khop!")

    print("=" * 45)


if __name__ == "__main__":
    main()
