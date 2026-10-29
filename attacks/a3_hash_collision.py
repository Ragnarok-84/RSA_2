from __future__ import annotations

import time

from core.hash.sha256 import sha256
from core.hash.toy_hash import weak_hash16
from core.rsa_keygen import generate_keypair
from core.signature import sign_hash, verify_hash
from core.step_logger import StepLogger
from attacks import AttackResult

NAME = "A3: Va chạm hàm băm yếu (nghịch lý ngày sinh)"

HONEST = ("Bên A bán cho bên B lô hàng 100 máy tính với giá 1.500.000.000 đồng, thanh toán trong vòng "
          "30 ngày kể từ ngày giao hàng, bảo hành 24 tháng tại trụ sở bên A")
FRAUD = ("Bên A bán cho bên B lô hàng 100 máy tính với giá 150.000.000 đồng, bên A chịu toàn bộ chi phí "
         "vận chuyển và bồi thường gấp đôi nếu giao hàng chậm một ngày")


def variant(text: str, index: int) -> bytes:
    words = text.split(" ")
    out = [words[0]]
    for i, w in enumerate(words[1:]):
        out.append(("  " if (index >> i) & 1 else " ") + w)
    return "".join(out).encode("utf-8")


def weak_digest(data: bytes) -> bytes:
    return weak_hash16(data).to_bytes(2, "big") + b"\x00" * 30


def birthday_search(hash_fn, limit: int) -> tuple[bytes, bytes, int] | None:
    table: dict[bytes, bytes] = {}
    for i in range(limit):
        m = variant(HONEST, i)
        table.setdefault(hash_fn(m), m)
    for j in range(limit):
        m = variant(FRAUD, j)
        hit = table.get(hash_fn(m))
        if hit is not None:
            return hit, m, len(table) + j + 1
    return None


def run(logger: StepLogger | None = None, defended: bool = False, bits: int = 1024) -> AttackResult:
    log = logger if logger is not None else StepLogger()
    hash_name = "SHA-256 (256 bít)" if defended else "weak_hash16 (16 bít)"
    log.head(f"TẤN CÔNG A3: VA CHẠM HÀM BĂM — hệ thống dùng {hash_name}")
    hash_fn = sha256 if defended else weak_digest
    pub, priv = generate_keypair(bits)
    log.note("[1] phuong soạn hai hợp đồng", f"THẬT: {HONEST}\nGIAN: {FRAUD}")

    limit = 1 << 10
    t = time.perf_counter()
    found = birthday_search(hash_fn, limit)
    dt = time.perf_counter() - t
    if found is None:
        log.log(f"[2] Thử {2 * limit} biến thể (thêm dấu cách) mỗi bên", None,
                f"Không tìm được va chạm sau {2 * limit} phép băm ({dt:.2f}s). "
                "Với SHA-256 cần khoảng 2^128 phép băm.", level="ok")
        success = False
        details = {"defended": defended, "hashes": 2 * limit}
    else:
        honest, fraud, tries = found
        log.log("[2] Tìm va chạm theo nghịch lý ngày sinh", r"\Pr[\mathrm{va\ cham}] \approx 1 - e^{-k^2 / 2^{17}}",
                f"Sau {tries} phép băm ({dt:.2f}s), thay vì 2^16 = 65536:\n"
                f"H(thật) = {hash_fn(honest)[:2].hex()} = H(gian) = {hash_fn(fraud)[:2].hex()}")
        sig = sign_hash(hash_fn(honest), priv)
        log.note("[3] trang đọc bản thật (chỉ khác vài dấu cách) và ký")
        res = verify_hash(hash_fn(fraud), sig, pub)
        success = res.valid
        log.log("[4] phuong gắn chữ ký đó vào bản gian", None,
                "HỢP LỆ: trang bị ràng buộc bởi hợp đồng gian" if success else res.reason,
                level="bad" if success else "ok")
        details = {"defended": defended, "hashes": tries}

    summary = ("Va chạm 16 bít tìm được ngay; một chữ ký dùng cho cả hai hợp đồng." if success else
               "Thất bại: SHA-256 kháng va chạm.")
    (log.bad if success else log.ok)("[KẾT LUẬN] " + summary + " Phòng chống: hàm băm >= 256 bít, không dùng MD5/SHA-1.")
    return AttackResult(NAME, success, summary, details)
