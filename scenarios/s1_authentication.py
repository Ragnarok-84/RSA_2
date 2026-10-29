from __future__ import annotations

import secrets

from core.rsa_keygen import generate_keypair
from core.signature import sign, verify_detailed
from core.step_logger import StepLogger
from pki.ca import CertificateAuthority
from pki.chain_verify import verify_chain
from scenarios import ScenarioResult

NAME = "S1: Chứng thực nguồn gốc"


def run(logger: StepLogger | None = None, bits: int = 2048) -> ScenarioResult:
    log = logger if logger is not None else StepLogger()
    log.head("KỊCH BẢN S1: CHỨNG THỰC NGUỒN GỐC (AUTHENTICATION)")

    root = CertificateAuthority.create("Root CA ATBMTT", bits)
    root.self_signed_root()
    trang_pub, trang_priv = generate_keypair(bits)
    trang_cert = root.issue("Trang", trang_pub)
    log.note("[1] Root CA cấp chứng chỉ cho trang (gắn tên 'trang' với khoá công khai e_A)", trang_cert.describe())

    message = "trang gửi thuy: hẹn 9h sáng thứ Hai ký hợp đồng tại phòng 301.".encode("utf-8")
    sig = sign(message, trang_priv)
    log.note("[2] trang ký thông điệp bằng khoá riêng d_A", f"M = {message.decode()}\nS = {sig.hex()[:64]}…")

    chain = verify_chain(trang_cert, [], [root.certificate])
    res = verify_detailed(message, sig, trang_cert.public_key)
    log.log("[3] thuy kiểm tra chuỗi chứng chỉ của trang", None, chain.reason, level="ok" if chain.valid else "bad")
    log.log("    thuy kiểm tra chữ ký bằng e_A lấy từ chứng chỉ", r"\mathrm{SHA256}(M) \equiv \mathrm{Decode}(S^{e_A} \mathrm{mod}\ n_A)",
            res.reason, level="ok" if res.valid else "bad")

    phuong_pub, phuong_priv = generate_keypair(bits)
    fake = "trang gửi thuy: chuyển trước 50 triệu tiền cọc vào tài khoản 999-888.".encode("utf-8")
    fake_sig = sign(fake, phuong_priv)
    fake_res = verify_detailed(fake, fake_sig, trang_cert.public_key)
    log.log("[4] phuong không có d_A, ký bằng khoá của mình rồi xưng là trang", None,
            f"M' = {fake.decode()}\nKiểm tra bằng e_A: {fake_res.reason}", level="bad" if fake_res.valid else "ok")

    nonce = secrets.token_bytes(32)
    log.note("[5] Thách – đáp: thuy gửi nonce ngẫu nhiên 256 bít", nonce.hex())
    answer = verify_detailed(nonce, sign(nonce, trang_priv), trang_cert.public_key)
    impostor = verify_detailed(nonce, sign(nonce, phuong_priv), trang_cert.public_key)
    log.log("    trang ký nonce → thuy kiểm tra", None, answer.reason, level="ok" if answer.valid else "bad")
    log.log("    phuong ký nonce bằng khoá của mình → thuy kiểm tra", None, impostor.reason,
            level="bad" if impostor.valid else "ok")

    valid = chain.valid and res.valid and not fake_res.valid and answer.valid and not impostor.valid
    summary = ("Chỉ người giữ d_A tạo được chữ ký kiểm tra được bằng e_A trong chứng chỉ của trang → chứng thực nguồn gốc."
               if valid else "Kịch bản S1 không đạt.")
    (log.ok if valid else log.bad)("[KẾT LUẬN] " + summary)
    return ScenarioResult(NAME, valid, summary, {
        "chain": chain.reason, "trang_signature": res.valid, "phuong_signature": fake_res.valid,
        "challenge_trang": answer.valid, "challenge_phuong": impostor.valid,
    })
