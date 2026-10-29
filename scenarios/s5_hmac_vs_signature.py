"""S5 — HMAC không chống chối bỏ được.

HMAC dùng khoá chung K mà cả Alice và Bob đều biết, nên Bob cũng tạo được thẻ hợp lệ cho bất kỳ thông điệp nào:
trọng tài không phân biệt được thẻ do ai tạo. Với chữ ký RSA, Bob chỉ có khoá CÔNG KHAI của Alice nên không
tạo được chữ ký của Alice.

HMAC (RFC 2104) tự cài trên core/hash/sha256.py, chỉ dùng trong kịch bản này:
    HMAC(K, M) = H((K0 ⊕ opad) || H((K0 ⊕ ipad) || M)),  ipad = 0x36…, opad = 0x5C…
"""
from __future__ import annotations

import secrets

from core.hash.sha256 import sha256
from core.rsa_keygen import generate_keypair
from core.signature import sign, verify_detailed
from core.step_logger import StepLogger
from core.utils import constant_time_eq
from scenarios import ScenarioResult

NAME = "S5: HMAC không chống chối bỏ được"
BLOCK = 64


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    """HMAC-SHA256 theo RFC 2104."""
    if len(key) > BLOCK:
        key = sha256(key)
    k0 = key.ljust(BLOCK, b"\x00")
    inner = sha256(bytes(b ^ 0x36 for b in k0) + message)
    return sha256(bytes(b ^ 0x5C for b in k0) + inner)


def hmac_verify(key: bytes, message: bytes, tag: bytes) -> bool:
    return constant_time_eq(hmac_sha256(key, message), tag)


def run(logger: StepLogger | None = None, bits: int = 2048) -> ScenarioResult:
    log = logger if logger is not None else StepLogger()
    log.head("KỊCH BẢN S5: HMAC KHÔNG CHỐNG CHỐI BỎ, CHỮ KÝ RSA THÌ CÓ")

    K = secrets.token_bytes(32)
    log.note("[1] Alice và Bob thoả thuận khoá chung K (cả hai cùng biết)", K.hex())
    m1 = "Alice đặt mua 10 máy in, tổng 30.000.000 VNĐ.".encode("utf-8")
    t1 = hmac_sha256(K, m1)
    log.log("[2] Alice gửi M1 kèm thẻ HMAC", r"T = \mathrm{HMAC}_K(M)", f"M1 = {m1.decode()}\nT1 = {t1.hex()}")
    log.log("    Bob kiểm tra thẻ", None, "hợp lệ" if hmac_verify(K, m1, t1) else "sai",
            level="ok" if hmac_verify(K, m1, t1) else "bad")

    m2 = "Alice đồng ý bồi thường cho Bob 1.000.000.000 VNĐ.".encode("utf-8")
    t2 = hmac_sha256(K, m2)
    hmac_ambiguous = hmac_verify(K, m2, t2)
    log.log("[3] Bob tự soạn M2 và tự tính thẻ bằng K, rồi kiện Alice", None,
            f"M2 = {m2.decode()}\nT2 = {t2.hex()}")
    log.log("    Trọng tài (được giao K) kiểm tra T2", None,
            "thẻ HỢP LỆ — nhưng Alice và Bob đều tạo được thẻ này, trọng tài không biết ai tạo → HMAC KHÔNG chống chối bỏ",
            level="bad" if hmac_ambiguous else "ok")

    alice_pub, alice_priv = generate_keypair(bits)
    bob_pub, bob_priv = generate_keypair(bits)
    s1 = sign(m1, alice_priv)
    r1 = verify_detailed(m1, s1, alice_pub)
    log.log("[4] Cùng giao dịch với chữ ký RSA: Alice ký M1 bằng d_A", None, r1.reason, level="ok" if r1.valid else "bad")
    forged = verify_detailed(m2, sign(m2, bob_priv), alice_pub)
    log.log("[5] Bob muốn có 'chữ ký của Alice' trên M2 nhưng chỉ có e_A, đành ký bằng d_B", None,
            f"Kiểm tra bằng e_A: {forged.reason}", level="bad" if forged.valid else "ok")
    reuse = verify_detailed(m2, s1, alice_pub)
    log.log("    Bob gắn chữ ký thật của M1 vào M2", None, reuse.reason, level="bad" if reuse.valid else "ok")

    valid = hmac_ambiguous and r1.valid and not forged.valid and not reuse.valid
    summary = ("HMAC: ai giữ K cũng tạo được thẻ → không chống chối bỏ. RSA: chỉ người giữ d_A ký được → chống chối bỏ."
               if valid else "Kịch bản S5 không đạt.")
    (log.ok if valid else log.bad)("[KẾT LUẬN] " + summary)
    return ScenarioResult(NAME, valid, summary, {
        "hmac_bob_forgery_accepted": hmac_ambiguous, "rsa_alice_valid": r1.valid,
        "rsa_bob_forgery_accepted": forged.valid, "rsa_reuse_accepted": reuse.valid,
    })
