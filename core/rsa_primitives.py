from __future__ import annotations

from core.number_theory import mod_pow
from core.rsa_keygen import RSAPrivateKey, RSAPublicKey
from core.step_logger import StepLogger


def rsasp1(priv: RSAPrivateKey, m: int, logger: StepLogger | None = None) -> int:
    """Ký trên số đại diện m bằng phép lũy thừa modulo n."""
    if not 0 <= m < priv.n:
        raise ValueError("RSASP1: số đại diện thông điệp nằm ngoài [0, n)")
    s = mod_pow(m, priv.d, priv.n)
    if logger is not None:
        logger.log("Ký RSA", f"s = m^d mod n", f"s = {s}")
    return s


def rsavp1(pub: RSAPublicKey, s: int, logger: StepLogger | None = None) -> int:
    """Kiểm tra nguyên thuỷ: m' = s^e mod n, yêu cầu 0 <= s < n."""
    if not 0 <= s < pub.n:
        raise ValueError("RSAVP1: chữ ký nằm ngoài [0, n)")
    m = mod_pow(s, pub.e, pub.n)
    if logger is not None:
        logger.log("Kiểm tra RSA", f"m' = s^e mod n", f"m' = {m}")
    return m
