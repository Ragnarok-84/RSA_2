"""A9 — Chuyển tiếp lén (surreptitious forwarding, Davis 2001).

Mục tiêu: Carol tin rằng Alice gửi thư riêng cho Carol, trong khi Alice viết cho Bob.
Điều kiện: Alice "ký rồi mã hoá" nhưng phần được ký chỉ có M (không có tên người nhận). Bob giải mã hợp lệ,
lấy (M, s) rồi mã hoá lại bằng khoá của Carol. Chữ ký của Alice vẫn đúng với M nên Carol chấp nhận.
Lớp mã hoá không liên quan tới tấn công (Bob giải mã hợp pháp), nên ở đây chỉ mô hình hoá phong bì là
(người nhận, M, s); phiên bản có AES-GCM + RSA-OAEP thật nằm ở scenarios/s6_sign_then_encrypt.py.
Phòng chống: ký kèm danh tính người nhận và thời gian: s = Sign(H(to || t || M)); người nhận kiểm tra `to`.
"""
from __future__ import annotations

from core.rsa_keygen import RSAPublicKey, generate_keypair
from core.signature import sign, verify
from core.step_logger import StepLogger
from core.utils import canonical_json
from pki.certificate import now
from attacks import AttackResult

NAME = "A9: Chuyển tiếp lén"


def signed_part(message: bytes, to: str, t: int, bind_recipient: bool) -> bytes:
    return canonical_json({"to": to, "t": t}) + message if bind_recipient else message


def accept(env: dict, me: str, alice_pub: RSAPublicKey, bind_recipient: bool) -> tuple[bool, str]:
    """Người nhận `me` mở phong bì (đã giải mã) và kiểm tra."""
    if not verify(signed_part(env["m"], env["to"], env["t"], bind_recipient), env["s"], alice_pub):
        return False, "chữ ký của Alice không hợp lệ"
    if bind_recipient and env["to"] != me:
        return False, f"Alice ký thư cho '{env['to']}', không phải '{me}' → bị chuyển tiếp lén"
    return True, "chữ ký của Alice hợp lệ → tin rằng Alice viết thư này cho mình"


def run(logger: StepLogger | None = None, defended: bool = False, bits: int = 1024) -> AttackResult:
    log = logger if logger is not None else StepLogger()
    log.head(f"TẤN CÔNG A9: CHUYỂN TIẾP LÉN ({'CÓ' if defended else 'KHÔNG'} ký kèm người nhận)")
    alice_pub, alice_priv = generate_keypair(bits)
    m = "Anh đồng ý với đề nghị của em. Thứ Bảy gặp nhau nhé. — Alice".encode("utf-8")
    t = now()
    s = sign(signed_part(m, "Bob", t, defended), alice_priv)
    phan = r"s = \mathrm{Sign}_{d_A}(H(to \| t \| M))" if defended else r"s = \mathrm{Sign}_{d_A}(H(M))"
    log.log("[1] Alice ký thư rồi mã hoá gửi Bob", phan, m.decode())
    env = {"to": "Bob", "t": t, "m": m, "s": s}
    ok_bob, why_bob = accept(env, "Bob", alice_pub, defended)
    log.log("[2] Bob giải mã và kiểm tra", None, why_bob, level="ok" if ok_bob else "bad")

    forwarded = dict(env, to="Carol") if not defended else dict(env)
    log.note("[3] Bob giải mã, lấy nguyên (M, s) rồi mã hoá lại bằng khoá công khai của Carol")
    success, why = accept(forwarded, "Carol", alice_pub, defended)
    log.log("[4] Carol mở thư", None, why, level="bad" if success else "ok")
    if defended:
        relabeled = dict(env, to="Carol")
        ok2, why2 = accept(relabeled, "Carol", alice_pub, defended)
        log.log("[5] Bob sửa trường 'to' thành Carol", None, why2, level="bad" if ok2 else "ok")
        success = success or ok2

    summary = ("Carol tin Alice viết thư cho mình." if success else
               "Thất bại: danh tính người nhận nằm trong phần được ký.")
    (log.bad if success else log.ok)("[KẾT LUẬN] " + summary + " Phòng chống: ký kèm người nhận + thời gian.")
    return AttackResult(NAME, success, summary, {"defended": defended})
