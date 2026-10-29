from __future__ import annotations

from core.rsa_keygen import generate_keypair
from core.signature import sign, verify_detailed
from core.step_logger import StepLogger
from pki.ca import CertificateAuthority
from pki.certificate import Certificate
from pki.chain_verify import verify_chain
from attacks import AttackResult

NAME = "A6: Thay khoá công khai (MITM)"


def run(logger: StepLogger | None = None, defended: bool = False, bits: int = 1024) -> AttackResult:
    log = logger if logger is not None else StepLogger()
    log.head(f"TẤN CÔNG A6: THAY KHOÁ CÔNG KHAI ({'CÓ' if defended else 'KHÔNG'} PKI)")
    trang_pub, _ = generate_keypair(bits)
    phuong_pub, phuong_priv = generate_keypair(bits)
    fake = "trang: thuy chuyển ngay 200 triệu vào tài khoản 0123 giúp tôi.".encode("utf-8")
    fake_sig = sign(fake, phuong_priv)
    log.note("[1] phuong soạn lệnh giả và ký bằng khoá riêng của phuong", fake.decode())

    if not defended:
        received = phuong_pub
        log.note("[2] trang gửi khoá công khai cho thuy; phuong chặn và thay bằng khoá của phuong",
                 f"thuy nhận n = 0x{format(received.n, 'x')[:24]}… — không có cách nào biết đây không phải của trang")
        res = verify_detailed(fake, fake_sig, received)
        success = res.valid
        log.log("[3] thuy kiểm tra lệnh giả bằng 'khoá của trang'", None,
                "HỢP LỆ: thuy tin trang ra lệnh" if success else res.reason, level="bad" if success else "ok")
        details = {"defended": False}
    else:
        root = CertificateAuthority.create("Root CA ATBMTT", bits)
        root.self_signed_root()
        trang_cert = root.issue("Trang", trang_pub)
        log.note("[2] thuy chỉ tin Root CA ATBMTT; khoá của trang đến kèm chứng chỉ do Root CA ký")
        swapped = Certificate.from_dict({**trang_cert.to_dict(),
                                         "public_key": {"n": format(phuong_pub.n, "x"), "e": format(phuong_pub.e, "x")}})
        r_swap = verify_chain(swapped, [], [root.certificate])
        log.log("[3] phuong sửa khoá công khai bên trong chứng chỉ của trang", None, r_swap.reason,
                level="bad" if r_swap.valid else "ok")
        evil = CertificateAuthority.create("Root CA ATBMTT", bits)
        evil.self_signed_root()
        evil_cert = evil.issue("Trang", phuong_pub)
        r_evil = verify_chain(evil_cert, [evil.certificate], [root.certificate])
        log.log("[4] phuong lập CA giả cùng tên, tự cấp chứng chỉ 'trang'", None, r_evil.reason,
                level="bad" if r_evil.valid else "ok")
        success = (r_swap.valid and verify_detailed(fake, fake_sig, swapped.public_key).valid) or \
                  (r_evil.valid and verify_detailed(fake, fake_sig, evil_cert.public_key).valid)
        details = {"defended": True, "swapped_cert": r_swap.valid, "fake_ca": r_evil.valid}

    summary = ("thuy chấp nhận chữ ký của phuong là của trang." if success else
               "Thất bại: chứng chỉ do CA ký phát hiện khoá bị thay.")
    (log.bad if success else log.ok)("[KẾT LUẬN] " + summary + " Phòng chống: chứng chỉ CA (PKI).")
    return AttackResult(NAME, success, summary, details)
