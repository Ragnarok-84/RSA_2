"""A6 — Tấn công lỗi khi ký CRT (Boneh–DeMillo–Lipton 1997).

Mục tiêu: lộ p, q của thiết bị ký (thẻ thông minh) chỉ từ MỘT chữ ký lỗi.
Điều kiện: thiết bị ký PKCS#1 v1.5 (tất định, Mallory biết m) bằng CRT; Mallory gây lỗi (sụt áp, xung nhiễu)
làm hỏng s_p. Khi đó s' ≡ s (mod q) nhưng s' ≢ s (mod p), nên
    gcd(s'^e − m mod n, n) = q
Phòng chống: thiết bị kiểm tra s^e ≡ m (mod n) trước khi phát hành chữ ký; dùng PSS (m ngẫu nhiên).
"""
from __future__ import annotations

from core.hash.sha256 import sha256
from core.number_theory import gcd, mod_inverse
from core.padding import pkcs1_v15
from core.rsa_keygen import RSAPrivateKey, RSAPublicKey, generate_keypair, keypair_from_primes
from core.rsa_primitives import rsasp1, rsavp1
from core.signature import sign, verify
from core.step_logger import StepLogger
from core.utils import byte_len, i2osp, os2ip
from attacks import AttackResult

NAME = "A6: Lỗi khi ký CRT → lộ p, q"


class FaultDetected(Exception):
    """Thiết bị phát hiện chữ ký tính sai và không trả ra ngoài."""


class SmartCard:
    """Thẻ ký mô phỏng: giữ khoá riêng bên trong, ký PKCS#1 v1.5 bằng CRT."""

    def __init__(self, keypair: tuple[RSAPublicKey, RSAPrivateKey], check_before_release: bool) -> None:
        self.public_key, self._priv = keypair
        self.check = check_before_release
        self.glitch = False

    def sign(self, message: bytes) -> int:
        m = os2ip(pkcs1_v15.encode(sha256(message), byte_len(self.public_key.n)))
        s = rsasp1(self._priv, m, use_crt=True, fault=self.glitch)
        self.glitch = False
        if self.check and rsavp1(self.public_key, s) != m:
            raise FaultDetected("s^e ≢ m (mod n): thẻ từ chối phát hành chữ ký")
        return s


def run(logger: StepLogger | None = None, defended: bool = False, bits: int = 1024) -> AttackResult:
    log = logger if logger is not None else StepLogger()
    log.head(f"TẤN CÔNG A6: LỖI KHI KÝ CRT ({'thẻ CÓ' if defended else 'thẻ KHÔNG'} tự kiểm tra)")
    card = SmartCard(generate_keypair(bits), check_before_release=defended)
    pub = card.public_key
    doc = "Biên bản bàn giao thiết bị số 15".encode("utf-8")
    m = os2ip(pkcs1_v15.encode(sha256(doc), byte_len(pub.n)))
    log.note(f"[1] Thẻ thông minh của Alice ký PKCS#1 v1.5 bằng CRT ({bits} bít)", doc.decode())

    card.glitch = True
    try:
        s_bad = card.sign(doc)
    except FaultDetected as err:
        log.ok("[2] Mallory gây lỗi đúng lúc thẻ tính s_p", f"Thẻ phát hiện: {err} → Mallory không có gì để tính gcd")
        summary = "Thất bại: thẻ kiểm tra s^e ≡ m trước khi phát hành."
        log.ok("[KẾT LUẬN] " + summary)
        return AttackResult(NAME, False, summary, {"defended": defended})

    log.log("[2] Mallory gây lỗi đúng lúc thẻ tính s_p → nhận chữ ký lỗi s'", r"s'_p \ne m^{d_P} \mathrm{mod}\ p",
            f"s' hợp lệ? {verify(doc, i2osp(s_bad, byte_len(pub.n)), pub)}")
    q = gcd((rsavp1(pub, s_bad) - m) % pub.n, pub.n)
    if not 1 < q < pub.n:
        log.bad("[3] gcd không cho thừa số (lỗi không như mong đợi)")
        return AttackResult(NAME, False, "Không lộ thừa số", {"defended": defended})
    p = pub.n // q
    log.log("[3] Mallory tính gcd", r"\gcd(s'^{\,e} - m \mathrm{mod}\ n,\ n) = q",
            f"q = 0x{format(q, 'x')[:32]}… ({q.bit_length()} bít)\np = n / q")
    _, stolen = keypair_from_primes(p, q, pub.e)
    fake = "Alice uỷ quyền toàn bộ tài khoản cho Mallory".encode("utf-8")
    success = verify(fake, sign(fake, stolen), pub)
    log.log("[4] Dựng lại khoá riêng và ký giả", r"d = e^{-1} \mathrm{mod}\ (p-1)(q-1)",
            f"'{fake.decode()}' → " + ("HỢP LỆ: lộ khoá chỉ với 1 chữ ký lỗi" if success else "sai"),
            level="bad" if success else "ok")
    summary = "Lộ p, q từ một chữ ký CRT lỗi." if success else "Không khôi phục được khoá."
    (log.bad if success else log.ok)("[KẾT LUẬN] " + summary + " Phòng chống: kiểm tra s^e ≡ m trước khi phát hành.")
    return AttackResult(NAME, success, summary, {"defended": defended})
