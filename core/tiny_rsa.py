from __future__ import annotations

from core.hash.sha256 import sha256
from core.number_theory import mod_pow
from core.rsa_keygen import RSAPrivateKey, RSAPublicKey, keypair_from_primes
from core.step_logger import StepLogger
from core.utils import os2ip


class TinyRSA:
    """RSA bộ số nhỏ để tính tay. Ký hiệu theo slide chữ ký: khoá bí mật a = d, khoá công khai b = e."""

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
    def a(self) -> int:
        return self.priv.d

    @property
    def b(self) -> int:
        return self.e

    @property
    def phi(self) -> int:
        return (self.p - 1) * (self.q - 1)

    def keygen_steps(self, logger: StepLogger, owner: str = "TRANG") -> None:
        # Ghi lại quá trình sinh khoá
        logger.head(f"SINH KHOÁ CỦA {owner}: p = {self.p}, q = {self.q}, e = {self.e}")
        keypair_from_primes(self.p, self.q, self.e, logger)

    def hash_value(self, message: bytes | int, logger: StepLogger | None = None) -> int:
        """h(x): bytes thì băm SHA-256 rồi lấy mod n; số nguyên thì ký thẳng x (ví dụ lớp, không băm)."""
        if isinstance(message, int):
            if not 0 <= message < self.n:
                raise ValueError(f"x phải thoả 0 <= x < n = {self.n}")
            h = message
            if logger is not None:
                logger.log("Không băm (ví dụ lớp)", None, f"h(x) = x = {h}")
        else:
            digest = sha256(message)
            hash_integer = os2ip(digest)
            h = hash_integer % self.n
            if logger is not None:
                logger.log("Băm thu nhỏ", None,
                           f"SHA-256(x) (hex) = {digest.hex()}\n"
                           f"OS2IP(SHA-256(x)) = {hash_integer}\n"
                           f"h(x) = OS2IP(SHA-256(x)) mod {self.n} = {h}")
        return h

    def sign(self, message: bytes | int, logger: StepLogger | None = None, with_keygen: bool = True) -> int:
        """Ký: y = h(x)^a mod n (bảng bình phương và nhân khi có logger)."""
        if logger is not None and with_keygen:
            self.keygen_steps(logger)
        if logger is not None:
            logger.head("KÝ (Trang dùng khoá bí mật)")
        h = self.hash_value(message, logger)
        y = mod_pow(h, self.a, self.n, logger)
        if logger is not None:
            logger.log("Chữ ký", f"y = h(x)^a mod n = {h}^{self.a} mod {self.n} = {y}",
                       f"y = {y}", level="ok")
        return y

    def verify(self, message: bytes | int, y: int, logger: StepLogger | None = None) -> bool:
        """Kiểm tra: y^b mod n == h(x) ?"""
        if logger is not None:
            logger.head("KIỂM TRA (Thủy dùng khoá công khai của Trang)")
        h = self.hash_value(message, logger)
        if not 0 <= y < self.n:
            if logger is not None:
                logger.bad("Chữ ký nằm ngoài [0, n)", f"y = {y}")
            return False
        v = mod_pow(y, self.b, self.n, logger)
        ok = v == h
        if logger is not None:
            rel = "=" if ok else "!="
            formula = f"y^b mod n = {y}^{self.b} mod {self.n} = {v} {rel} h(x) = {h}"
            if ok:
                logger.log("Kết luận", formula, "Chữ ký HỢP LỆ", level="ok")
            else:
                logger.log("Kết luận", formula, "Chữ ký KHÔNG HỢP LỆ", level="bad")
        return ok


def _parts(message: bytes | int, y: int) -> list[tuple[str, int]]:
    # Số nguyên là một khối; bytes thì mỗi byte một khối (cần n_B > 255)
    if isinstance(message, int):
        blocks = [("x", message)]
    else:
        blocks = [(f"x[{i}]", v) for i, v in enumerate(message)]
    return blocks + [("y", y)]


def encrypt_pair(receiver: TinyRSA, message: bytes | int, y: int, logger: StepLogger | None = None) -> list[int]:
    """Ký rồi mã hoá theo slide: z = e_B(x, y), mã hoá từng khối m bằng m^e_B mod n_B."""
    parts = _parts(message, y)
    too_big = [(name, v) for name, v in parts if v >= receiver.n]
    if too_big:
        name, v = too_big[0]
        raise ValueError(f"Không mã hoá được: {name} = {v} >= n_B = {receiver.n}. "
                         f"Cần chọn n_B lớn hơn n_A (để y < n_B) và lớn hơn 255 khi x là văn bản.")
    z = [mod_pow(v, receiver.e, receiver.n) for _, v in parts]
    if logger is not None:
        logger.head("MÃ HOÁ (Trang dùng khoá công khai e_B của Thủy)")
        logger.table(f"Mã hoá z = e_B(x, y) với (e_B, n_B) = ({receiver.e}, {receiver.n})",
                     ("Thành phần", "m", "z = m^e_B mod n_B"),
                     [(name, v, c) for (name, v), c in zip(parts, z)],
                     formula=f"z = m^{receiver.e} mod {receiver.n} cho từng khối")
        logger.ok("Bản mã gửi đi", "z = (" + ", ".join(map(str, z)) + ")")
    return z


def decrypt_pair(receiver: TinyRSA, z: list[int], as_bytes: bool,
                 logger: StepLogger | None = None) -> tuple[bytes | int, int]:
    """Thủy giải mã (x, y) = d_B(z); chữ ký còn phải kiểm tra riêng bằng khoá công khai của Trang."""
    if len(z) < 2:
        raise ValueError("Bản mã z phải có ít nhất một khối x và một khối y")
    parts = [mod_pow(c, receiver.d, receiver.n) for c in z]
    names = [f"x[{i}]" for i in range(len(z) - 1)] if as_bytes else ["x"]
    if logger is not None:
        logger.head("GIẢI MÃ (Thủy dùng khoá bí mật d_B)")
        logger.table(f"Giải mã (x, y) = d_B(z) với (d_B, n_B) = ({receiver.d}, {receiver.n})",
                     ("Thành phần", "z", "m = z^d_B mod n_B"),
                     [(name, c, m) for name, c, m in zip(names + ["y"], z, parts)],
                     formula=f"m = z^{receiver.d} mod {receiver.n} cho từng khối")
    if as_bytes:
        if any(m > 255 for m in parts[:-1]):
            raise ValueError("Giải mã ra khối > 255: sai khoá hoặc bản mã z đã bị sửa")
        return bytes(parts[:-1]), parts[-1]
    return parts[0], parts[-1]
