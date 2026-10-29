from __future__ import annotations

from core.hash.sha256 import sha256
from core.rsa_keygen import generate_keypair
from core.signature import sign, verify_detailed
from core.step_logger import StepLogger
from scenarios import ScenarioResult, sample_bytes

NAME = "S2: Toàn vẹn: sửa 1 byte → FAIL"

FALLBACK_CONTRACT = "HỢP ĐỒNG MUA BÁN\nTổng giá trị hợp đồng: 2.000.000.000 VNĐ.\n".encode("utf-8")


def _bit_diff(a: bytes, b: bytes) -> int:
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def run(logger: StepLogger | None = None, bits: int = 2048) -> ScenarioResult:
    log = logger if logger is not None else StepLogger()
    log.head("KỊCH BẢN S2: TOÀN VẸN DỮ LIỆU (INTEGRITY)")

    original = sample_bytes("messages/contract.txt", FALLBACK_CONTRACT)
    tampered = sample_bytes("messages/contract_tampered.txt", original.replace(b"2.000", b"9.000", 1))
    diffs = [i for i, (x, y) in enumerate(zip(original, tampered)) if x != y]
    log.note("[1] Hai tệp: contract.txt và contract_tampered.txt",
             f"Độ dài: {len(original)} và {len(tampered)} byte; khác nhau ở {len(diffs)} byte "
             f"(vị trí {diffs[:5]}): {original[diffs[0]:diffs[0] + 1]!r} → {tampered[diffs[0]:diffs[0] + 1]!r}"
             if diffs else "Hai tệp giống hệt nhau (sample bị hỏng?)")

    pub, priv = generate_keypair(bits)
    sig = sign(original, priv)
    h1, h2 = sha256(original), sha256(tampered)
    log.log("[2] trang ký contract.txt", r"S = \mathrm{RSASP1}(d, \mathrm{Encode}(\mathrm{SHA256}(M)))",
            f"SHA256(M)  = {h1.hex()}\nS = {sig.hex()[:64]}…")
    log.log("    Giá trị băm của bản bị sửa", r"\mathrm{SHA256}(M')", f"SHA256(M') = {h2.hex()}\n"
            f"Khác {_bit_diff(h1, h2)}/256 bít so với SHA256(M) (hiệu ứng thác lũ)")

    r_ok = verify_detailed(original, sig, pub)
    r_tamper = verify_detailed(tampered, sig, pub)
    log.log("[3] thuy kiểm tra bản gốc", None, r_ok.reason, level="ok" if r_ok.valid else "bad")
    log.log("[4] thuy kiểm tra bản bị sửa 1 byte với cùng chữ ký", None, r_tamper.reason,
            level="bad" if r_tamper.valid else "ok")

    flipped_msg = bytearray(original)
    flipped_msg[len(flipped_msg) // 2] ^= 0x01
    r_bit = verify_detailed(bytes(flipped_msg), sig, pub)
    flipped_sig = bytearray(sig)
    flipped_sig[-1] ^= 0x01
    r_sig = verify_detailed(original, bytes(flipped_sig), pub)
    log.log("[5] Lật 1 bít của thông điệp", None, r_bit.reason, level="bad" if r_bit.valid else "ok")
    log.log("[6] Lật 1 bít của chữ ký", None, r_sig.reason, level="bad" if r_sig.valid else "ok")

    valid = bool(diffs) and r_ok.valid and not r_tamper.valid and not r_bit.valid and not r_sig.valid
    summary = ("Mọi thay đổi trên thông điệp hoặc chữ ký đều bị phát hiện → toàn vẹn." if valid
               else "Kịch bản S2 không đạt.")
    (log.ok if valid else log.bad)("[KẾT LUẬN] " + summary)
    return ScenarioResult(NAME, valid, summary, {
        "original": r_ok.valid, "tampered": r_tamper.valid, "bit_flip_message": r_bit.valid,
        "bit_flip_signature": r_sig.valid, "hash_bit_diff": _bit_diff(h1, h2),
    })
