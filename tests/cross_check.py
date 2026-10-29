"""Đối chiếu với test vector NIST/RFC và thư viện chuẩn."""
import hashlib
import hmac as std_hmac
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.sha256 import hash_sha256
from core.hmac_utils import generate_hmac, pbkdf2_hmac_sha256
from core.rsa_math import generate_keypair, is_prime, mod_exp, byte_length
from core import rsa_full
from core import rsa_mini

ROWS = []


def check(group, name, ours, expected):
    ok = ours == expected
    ROWS.append((group, name, ok, str(ours)[:24], str(expected)[:24]))
    return ok


def skip(group, name, reason):
    ROWS.append((group, name, None, "-", reason))


def run(keysize=1024):
    ROWS.clear()

    # SHA-256: FIPS 180-4 / NIST CSRC example values
    vectors = [
        ("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        ("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
         "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
        ("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
         "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"),
    ]
    for msg, digest in vectors:
        check("SHA-256 (NIST)", f"'{msg[:12]}...' ({len(msg)} byte)", hash_sha256(msg), digest)
    for n in (55, 56, 63, 64, 65, 1000, 100_000):
        data = os.urandom(n)
        check("SHA-256 vs hashlib", f"ngẫu nhiên {n} byte", hash_sha256(data), hashlib.sha256(data).hexdigest())

    # HMAC-SHA256: RFC 4231
    check("HMAC (RFC 4231)", "Test case 1", generate_hmac(b"\x0b" * 20, b"Hi There"),
          "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
    check("HMAC (RFC 4231)", "Test case 2", generate_hmac("Jefe", "what do ya want for nothing?"),
          "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
    check("HMAC (RFC 4231)", "Test case 6 (khóa 131 byte)",
          generate_hmac(b"\xaa" * 131, b"Test Using Larger Than Block-Size Key - Hash Key First"),
          "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")
    for klen in (0, 64, 100):
        k, m = os.urandom(klen), os.urandom(77)
        check("HMAC vs hmac", f"khóa {klen} byte", generate_hmac(k, m), std_hmac.new(k, m, hashlib.sha256).hexdigest())
    check("PBKDF2 vs hashlib", "2000 vòng", pbkdf2_hmac_sha256("matkhau", b"salt1234", 2000).hex(),
          hashlib.pbkdf2_hmac("sha256", b"matkhau", b"salt1234", 2000).hex())

    # Số học RSA
    check("Số học", "Miller-Rabin: 2^127-1 nguyên tố", is_prime(2 ** 127 - 1), True)
    check("Số học", "Miller-Rabin: 561 (Carmichael)", is_prime(561), False)
    check("Số học", "mod_exp vs pow (số 1024 bit)", mod_exp(3 ** 600, 2 ** 1000 + 1, 2 ** 1024 - 105),
          pow(3 ** 600, 2 ** 1000 + 1, 2 ** 1024 - 105))
    r = rsa_mini.run_demo(verbose=False)
    check("RSA thu nhỏ (ví dụ trên lớp)", "p=17,q=11,e=7: (d, C, S)", (r["d"], r["C"], r["S"]), (23, 11, 11))
    check("RSA thu nhỏ (ví dụ trên lớp)", "Ký rồi mã hóa: (C1, C2) -> M", (r["conf_C1"], r["conf_C2"], r["conf_M"]),
          (465, 664, 88))

    # RSA chữ ký & OAEP vs thư viện cryptography
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives.asymmetric.rsa import (RSAPublicNumbers, RSAPrivateNumbers,
                                                                   rsa_crt_iqmp, rsa_crt_dmp1, rsa_crt_dmq1)
        from cryptography.exceptions import InvalidSignature
    except ImportError:
        for name in ("Chữ ký PKCS#1 v1.5", "Chữ ký PSS", "OAEP: ta mã hóa, thư viện giải",
                     "OAEP: thư viện mã hóa, ta giải"):
            skip("RSA vs cryptography", name, "chưa cài cryptography")
        return _report()

    priv, pub = generate_keypair(keysize=keysize)
    (d, N), (e, _) = priv, pub
    k = byte_length(N)
    lib_pub = RSAPublicNumbers(e, N).public_key()
    p, q = _factor_with_d(N, e, d)
    lib_priv = RSAPrivateNumbers(p, q, d, rsa_crt_dmp1(d, p), rsa_crt_dmq1(d, q), rsa_crt_iqmp(p, q),
                                 RSAPublicNumbers(e, N)).private_key()

    msg = "Hợp đồng đối chiếu".encode()
    ours = rsa_full.sign_message(msg, priv)
    theirs = int.from_bytes(lib_priv.sign(msg, padding.PKCS1v15(), hashes.SHA256()), "big")
    check("RSA vs cryptography", "Chữ ký PKCS#1 v1.5 trùng từng bit", ours, theirs)
    try:
        lib_pub.verify(ours.to_bytes(k, "big"), msg, padding.PKCS1v15(), hashes.SHA256())
        lib_ok = True
    except InvalidSignature:
        lib_ok = False
    check("RSA vs cryptography", "Thư viện kiểm tra chữ ký của ta", lib_ok, True)

    pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
    try:
        lib_pub.verify(rsa_full.sign_message(msg, priv, "pss").to_bytes(k, "big"), msg, pss, hashes.SHA256())
        pss_ok = True
    except InvalidSignature:
        pss_ok = False
    check("RSA vs cryptography", "PSS: thư viện kiểm tra chữ ký của ta", pss_ok, True)
    lib_pss_sig = int.from_bytes(lib_priv.sign(msg, pss, hashes.SHA256()), "big")
    check("RSA vs cryptography", "PSS: ta kiểm tra chữ ký của thư viện",
          rsa_full.verify_message(msg, lib_pss_sig, pub, "pss"), True)

    oaep = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    secret = b"Khoa phien 32 byte: 0123456789AB"
    check("RSA vs cryptography", "OAEP: ta mã hóa, thư viện giải",
          lib_priv.decrypt(rsa_full.oaep_encrypt(secret, pub), oaep), secret)
    check("RSA vs cryptography", "OAEP: thư viện mã hóa, ta giải",
          rsa_full.oaep_decrypt(lib_pub.encrypt(secret, oaep), priv), secret)
    return _report()


def _factor_with_d(N, e, d):
    """Khôi phục p, q từ (N, e, d) — chỉ để dựng khóa cho thư viện đối chiếu."""
    import math
    import secrets
    k = e * d - 1
    while True:
        g = 2 + secrets.randbelow(N - 3)
        t = k
        while t % 2 == 0:
            t //= 2
            x = pow(g, t, N)
            if x > 1 and math.gcd(x - 1, N) > 1:
                p = math.gcd(x - 1, N)
                return p, N // p


def _report():
    print(f"{'Nhóm':<30} {'Ca kiểm thử':<38} {'Kết quả':<9}")
    print("-" * 80)
    for group, name, ok, _, note in ROWS:
        status = "BỎ QUA" if ok is None else ("KHỚP" if ok else "LỆCH")
        print(f"{group:<30} {name:<38} {status:<9}" + (f" ({note})" if ok is None else ""))
    passed = sum(1 for r in ROWS if r[2])
    failed = sum(1 for r in ROWS if r[2] is False)
    print("-" * 80)
    print(f"Tổng: {passed} khớp, {failed} lệch, {len(ROWS) - passed - failed} bỏ qua")
    return failed == 0


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    sys.exit(0 if run() else 1)
