"""S1 — Chứng thực nguồn gốc.

Chỉ người giữ khoá riêng d_A tạo được chữ ký mà khoá công khai e_A kiểm tra được. Bob lấy e_A từ chứng chỉ
do Root CA cấp (nên chắc chắn e_A là của Alice), rồi:
  1. kiểm tra chữ ký của Alice trên thông điệp → chấp nhận;
  2. Mallory ký bằng khoá của mình nhưng xưng là Alice → bị từ chối;
  3. thách – đáp: Bob gửi nonce ngẫu nhiên, Alice ký nonce → chứng thực thực thể; Mallory không làm được.

Tấn công tương ứng khi bỏ PKI: attacks/a7_key_substitution_mitm.py.
"""
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
    alice_pub, alice_priv = generate_keypair(bits)
    alice_cert = root.issue("Alice", alice_pub)
    log.note("[1] Root CA cấp chứng chỉ cho Alice (gắn tên 'Alice' với khoá công khai e_A)", alice_cert.describe())

    message = "Alice gửi Bob: hẹn 9h sáng thứ Hai ký hợp đồng tại phòng 301.".encode("utf-8")
    sig = sign(message, alice_priv)
    log.note("[2] Alice ký thông điệp bằng khoá riêng d_A", f"M = {message.decode()}\nS = {sig.hex()[:64]}…")

    chain = verify_chain(alice_cert, [], [root.certificate])
    res = verify_detailed(message, sig, alice_cert.public_key)
    log.log("[3] Bob kiểm tra chuỗi chứng chỉ của Alice", None, chain.reason, level="ok" if chain.valid else "bad")
    log.log("    Bob kiểm tra chữ ký bằng e_A lấy từ chứng chỉ", r"\mathrm{SHA256}(M) \equiv \mathrm{Decode}(S^{e_A} \mathrm{mod}\ n_A)",
            res.reason, level="ok" if res.valid else "bad")

    mallory_pub, mallory_priv = generate_keypair(bits)
    fake = "Alice gửi Bob: chuyển trước 50 triệu tiền cọc vào tài khoản 999-888.".encode("utf-8")
    fake_sig = sign(fake, mallory_priv)
    fake_res = verify_detailed(fake, fake_sig, alice_cert.public_key)
    log.log("[4] Mallory không có d_A, ký bằng khoá của mình rồi xưng là Alice", None,
            f"M' = {fake.decode()}\nKiểm tra bằng e_A: {fake_res.reason}", level="bad" if fake_res.valid else "ok")

    nonce = secrets.token_bytes(32)
    log.note("[5] Thách – đáp: Bob gửi nonce ngẫu nhiên 256 bít", nonce.hex())
    answer = verify_detailed(nonce, sign(nonce, alice_priv), alice_cert.public_key)
    impostor = verify_detailed(nonce, sign(nonce, mallory_priv), alice_cert.public_key)
    log.log("    Alice ký nonce → Bob kiểm tra", None, answer.reason, level="ok" if answer.valid else "bad")
    log.log("    Mallory ký nonce bằng khoá của mình → Bob kiểm tra", None, impostor.reason,
            level="bad" if impostor.valid else "ok")

    valid = chain.valid and res.valid and not fake_res.valid and answer.valid and not impostor.valid
    summary = ("Chỉ người giữ d_A tạo được chữ ký kiểm tra được bằng e_A trong chứng chỉ của Alice → chứng thực nguồn gốc."
               if valid else "Kịch bản S1 không đạt.")
    (log.ok if valid else log.bad)("[KẾT LUẬN] " + summary)
    return ScenarioResult(NAME, valid, summary, {
        "chain": chain.reason, "alice_signature": res.valid, "mallory_signature": fake_res.valid,
        "challenge_alice": answer.valid, "challenge_mallory": impostor.valid,
    })
