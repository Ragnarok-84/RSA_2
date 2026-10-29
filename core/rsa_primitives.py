"""Phép ký / kiểm tra nguyên thuỷ RSASP1, RSAVP1 (RFC 8017 §5.2).

Ký không CRT:   s = m^d mod n
Ký có CRT:      s_p = m^dP mod p,  s_q = m^dQ mod q,  h = qInv·(s_p − s_q) mod p,  s = s_q + h·q
Kiểm tra:       m' = s^e mod n
"""
from __future__ import annotations

from core.number_theory import mod_pow
from core.rsa_keygen import RSAPrivateKey, RSAPublicKey
from core.step_logger import StepLogger


def rsasp1(priv: RSAPrivateKey, m: int, use_crt: bool = True, fault: bool = False,
           logger: StepLogger | None = None) -> int:
    """Ký nguyên thuỷ trên số đại diện m (0 <= m < n).

    `fault=True` chỉ phục vụ attacks/a6_crt_fault_attack.py: mô phỏng lỗi phần cứng làm hỏng s_p
    khi ký CRT (lật bit thấp nhất của s_p).
    """
    if not 0 <= m < priv.n:
        raise ValueError("RSASP1: số đại diện thông điệp nằm ngoài [0, n)")
    if not use_crt:
        s = mod_pow(m, priv.d, priv.n)
        if logger is not None:
            logger.log("Ký RSA (không CRT)", r"s = m^{d} \mathrm{mod}\ n", f"s = {s}")
        return s
    s_p = mod_pow(m, priv.dP, priv.p)
    s_q = mod_pow(m, priv.dQ, priv.q)
    if fault:
        s_p ^= 1
    h = (priv.qInv * (s_p - s_q)) % priv.p
    s = s_q + h * priv.q
    if logger is not None:
        logger.log("Ký RSA bằng CRT",
                   r"s_p = m^{d_P} \mathrm{mod}\ p,\; s_q = m^{d_Q} \mathrm{mod}\ q,\; h = q_{inv}(s_p - s_q) \mathrm{mod}\ p,\; s = s_q + h q",
                   f"s = {s}" + ("  (s_p đã bị lỗi phần cứng làm hỏng)" if fault else ""),
                   level="bad" if fault else "")
    return s


def rsavp1(pub: RSAPublicKey, s: int, logger: StepLogger | None = None) -> int:
    """Kiểm tra nguyên thuỷ: m' = s^e mod n, yêu cầu 0 <= s < n."""
    if not 0 <= s < pub.n:
        raise ValueError("RSAVP1: chữ ký nằm ngoài [0, n)")
    m = mod_pow(s, pub.e, pub.n)
    if logger is not None:
        logger.log("Kiểm tra RSA", r"m' = s^{e} \mathrm{mod}\ n", f"m' = {m}")
    return m
