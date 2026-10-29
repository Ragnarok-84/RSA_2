from __future__ import annotations

from core.hash.sha256 import sha256
from core.number_theory import iroot
from core.padding import pkcs1_v15
from core.padding.pkcs1_v15 import DIGEST_INFO_SHA256
from core.rsa_keygen import RSAPublicKey, generate_keypair
from core.rsa_primitives import rsavp1
from core.step_logger import StepLogger
from core.utils import byte_len, i2osp, os2ip
from attacks import AttackResult

NAME = "A4: e = 3 + kiểm tra lỏng (Bleichenbacher 2006)"


def forge(pub: RSAPublicKey, message_hash: bytes) -> int:
    if pub.e != 3:
        raise ValueError("Tấn công này cần e = 3")
    k = byte_len(pub.n)
    prefix = b"\x00\x01\xff\x00" + DIGEST_INFO_SHA256 + message_hash
    garbage = k - len(prefix)
    r, exact = iroot(os2ip(prefix + b"\x00" * garbage), 3)
    s = r if exact else r + 1
    if s ** 3 >= pub.n or i2osp(s ** 3, k)[:len(prefix)] != prefix:
        raise ValueError("Modulus quá ngắn: phần rác không đủ chỗ để căn bậc ba giữ nguyên phần đầu")
    return s


def run(logger: StepLogger | None = None, defended: bool = False, bits: int = 3072) -> AttackResult:
    log = logger if logger is not None else StepLogger()
    checker = "verify_strict" if defended else "verify_sloppy"
    log.head(f"TẤN CÔNG A4: e = 3, BỘ KIỂM TRA {checker}")
    pub, _ = generate_keypair(bits, e=3)
    message = "trang chuyển toàn bộ cổ phần công ty cho phuong.".encode("utf-8")
    h = sha256(message)
    log.note(f"[1] Khoá công khai của trang: e = 3, n {bits} bít. phuong muốn chữ ký cho", message.decode())

    s = forge(pub, h)
    log.log("[2] phuong dựng EM có phần rác ở cuối rồi lấy căn bậc ba nguyên",
            r"s = \lceil (00\ 01\ FF\ 00 \| DigestInfo \| H \| 00 \ldots 00)^{1/3} \rceil",
            f"s = 0x{format(s, 'x')[:40]}… ({s.bit_length()} bít, rất nhỏ so với n)")
    em = i2osp(rsavp1(pub, s), byte_len(pub.n))
    log.log("    EM' = s³ mod n (= s³ vì s³ < n)", None, f"{em[:60].hex()}…{em[-8:].hex()}")

    accepted = pkcs1_v15.verify_strict(em, h) if defended else pkcs1_v15.verify_sloppy(em, h)
    log.log(f"[3] Bộ kiểm tra {checker}", None,
            ("CHẤP NHẬN — bị lừa vì không kiểm tra phần sau H" if accepted else
             "TỪ CHỐI — EM' không khớp toàn bộ Encode(H)"), level="bad" if accepted else "ok")

    summary = ("Giả mạo thành công bằng căn bậc ba vì bộ kiểm tra lỏng." if accepted else
               "Thất bại: kiểm tra chặt toàn bộ EM.")
    (log.bad if accepted else log.ok)("[KẾT LUẬN] " + summary + " Phòng chống: verify_strict, e = 65537.")
    return AttackResult(NAME, accepted, summary, {"defended": defended, "bits": bits})
