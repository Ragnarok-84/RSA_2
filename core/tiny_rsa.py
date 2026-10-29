"""RSA thu nhỏ để tính tay và trình bày từng bước (mặc định ví dụ slide: p = 17, q = 11, e = 7).

    n = 187, φ(n) = 160, d = 23
    Ký h = 88:        s = 88^23 mod 187 = 11
    Kiểm tra:         s^e mod n = 11^7 mod 187 = 88 = h  ⇒ hợp lệ

Đầu vào kiểu int được coi trực tiếp là h; kiểu bytes thì h = toy_hash(M, n) = OS2IP(SHA256(M)) mod n.
Bản thu nhỏ ký không đệm, chỉ để minh hoạ — không an toàn.
"""
from __future__ import annotations

from core.hash.toy_hash import toy_hash
from core.number_theory import mod_pow
from core.rsa_keygen import RSAPrivateKey, RSAPublicKey, keypair_from_primes
from core.step_logger import StepLogger


class TinyRSA:
    def __init__(self, p: int = 17, q: int = 11, e: int = 7) -> None:
        self.p, self.q, self.e = p, q, e
        self.pub: RSAPublicKey
        self.priv: RSAPrivateKey
        self.pub, self.priv = keypair_from_primes(p, q, e)

    @property
    def n(self) -> int:
        return self.pub.n

    @property
    def d(self) -> int:
        return self.priv.d

    @property
    def phi(self) -> int:
        return (self.p - 1) * (self.q - 1)

    def keygen_steps(self, logger: StepLogger) -> None:
        """Ghi lại quá trình sinh khoá: n, φ(n), gcd(e, φ(n)), bảng Euclid mở rộng tìm d."""
        logger.head(f"SINH KHOÁ: p = {self.p}, q = {self.q}, e = {self.e}")
        keypair_from_primes(self.p, self.q, self.e, logger)

    def hash_value(self, message: bytes | int, logger: StepLogger | None = None) -> int:
        if isinstance(message, int):
            if not 0 <= message < self.n:
                raise ValueError(f"h phải thoả 0 <= h < n = {self.n}")
            h = message
            if logger is not None:
                logger.log("Giá trị băm cho trước", None, f"h = {h}")
        else:
            h = toy_hash(message, self.n)
            if logger is not None:
                logger.log("Băm thu nhỏ", r"h = \mathrm{OS2IP}(\mathrm{SHA256}(M)) \mathrm{mod}\ n", f"h = {h}")
        return h

    def sign(self, message: bytes | int, logger: StepLogger | None = None, with_keygen: bool = True) -> int:
        """Ký: s = h^d mod n (bảng bình phương và nhân khi có logger)."""
        if logger is not None and with_keygen:
            self.keygen_steps(logger)
        if logger is not None:
            logger.head("KÝ (Alice dùng khoá riêng d)")
        h = self.hash_value(message, logger)
        s = mod_pow(h, self.d, self.n, logger)
        if logger is not None:
            logger.log("Chữ ký", rf"s = h^{{d}} \mathrm{{mod}}\ n = {h}^{{{self.d}}} \mathrm{{mod}}\ {self.n} = {s}",
                       f"s = {s}", level="ok")
        return s

    def verify(self, message: bytes | int, s: int, logger: StepLogger | None = None) -> bool:
        """Kiểm tra: s^e mod n == h ?"""
        if logger is not None:
            logger.head("KIỂM TRA (Bob dùng khoá công khai (n, e))")
        h = self.hash_value(message, logger)
        if not 0 <= s < self.n:
            if logger is not None:
                logger.bad("Chữ ký nằm ngoài [0, n)", f"s = {s}")
            return False
        v = mod_pow(s, self.e, self.n, logger)
        ok = v == h
        if logger is not None:
            rel = "=" if ok else r"\ne"
            formula = rf"s^{{e}} \mathrm{{mod}}\ n = {s}^{{{self.e}}} \mathrm{{mod}}\ {self.n} = {v} {rel} h = {h}"
            if ok:
                logger.log("Kết luận", formula, "Chữ ký HỢP LỆ", level="ok")
            else:
                logger.log("Kết luận", formula, "Chữ ký KHÔNG HỢP LỆ", level="bad")
        return ok
