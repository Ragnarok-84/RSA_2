"""A7 — Thay khoá công khai (man-in-the-middle).

Mục tiêu: Bob chấp nhận chữ ký của Mallory là chữ ký của Alice.
Điều kiện: Bob nhận "khoá công khai của Alice" qua kênh không xác thực; Mallory chặn và thay bằng khoá của mình.
Phòng chống: khoá công khai phải nằm trong chứng chỉ do CA tin cậy ký (pki/); Bob kiểm tra chuỗi chứng chỉ.
Sửa khoá trong chứng chỉ thì chữ ký CA sai; tự lập CA giả thì CA đó không nằm trong danh sách tin cậy.
"""
from __future__ import annotations

from core.rsa_keygen import generate_keypair
from core.signature import sign, verify_detailed
from core.step_logger import StepLogger
from pki.ca import CertificateAuthority
from pki.certificate import Certificate
from pki.chain_verify import verify_chain
from attacks import AttackResult

NAME = "A7: Thay khoá công khai (MITM)"


def run(logger: StepLogger | None = None, defended: bool = False, bits: int = 1024) -> AttackResult:
    log = logger if logger is not None else StepLogger()
    log.head(f"TẤN CÔNG A7: THAY KHOÁ CÔNG KHAI ({'CÓ' if defended else 'KHÔNG'} PKI)")
    alice_pub, _ = generate_keypair(bits)
    mallory_pub, mallory_priv = generate_keypair(bits)
    fake = "Alice: Bob chuyển ngay 200 triệu vào tài khoản 0123 giúp tôi.".encode("utf-8")
    fake_sig = sign(fake, mallory_priv)
    log.note("[1] Mallory soạn lệnh giả và ký bằng khoá riêng của Mallory", fake.decode())

    if not defended:
        received = mallory_pub
        log.note("[2] Alice gửi khoá công khai cho Bob; Mallory chặn và thay bằng khoá của Mallory",
                 f"Bob nhận n = 0x{format(received.n, 'x')[:24]}… — không có cách nào biết đây không phải của Alice")
        res = verify_detailed(fake, fake_sig, received)
        success = res.valid
        log.log("[3] Bob kiểm tra lệnh giả bằng 'khoá của Alice'", None,
                "HỢP LỆ: Bob tin Alice ra lệnh" if success else res.reason, level="bad" if success else "ok")
        details = {"defended": False}
    else:
        root = CertificateAuthority.create("Root CA ATBMTT", bits)
        root.self_signed_root()
        alice_cert = root.issue("Alice", alice_pub)
        log.note("[2] Bob chỉ tin Root CA ATBMTT; khoá của Alice đến kèm chứng chỉ do Root CA ký")
        swapped = Certificate.from_dict({**alice_cert.to_dict(),
                                         "public_key": {"n": format(mallory_pub.n, "x"), "e": format(mallory_pub.e, "x")}})
        r_swap = verify_chain(swapped, [], [root.certificate])
        log.log("[3] Mallory sửa khoá công khai bên trong chứng chỉ của Alice", None, r_swap.reason,
                level="bad" if r_swap.valid else "ok")
        evil = CertificateAuthority.create("Root CA ATBMTT", bits)
        evil.self_signed_root()
        evil_cert = evil.issue("Alice", mallory_pub)
        r_evil = verify_chain(evil_cert, [evil.certificate], [root.certificate])
        log.log("[4] Mallory lập CA giả cùng tên, tự cấp chứng chỉ 'Alice'", None, r_evil.reason,
                level="bad" if r_evil.valid else "ok")
        success = (r_swap.valid and verify_detailed(fake, fake_sig, swapped.public_key).valid) or \
                  (r_evil.valid and verify_detailed(fake, fake_sig, evil_cert.public_key).valid)
        details = {"defended": True, "swapped_cert": r_swap.valid, "fake_ca": r_evil.valid}

    summary = ("Bob chấp nhận chữ ký của Mallory là của Alice." if success else
               "Thất bại: chứng chỉ do CA ký phát hiện khoá bị thay.")
    (log.bad if success else log.ok)("[KẾT LUẬN] " + summary + " Phòng chống: chứng chỉ CA (PKI).")
    return AttackResult(NAME, success, summary, details)
