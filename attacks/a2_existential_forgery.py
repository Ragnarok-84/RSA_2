"""A2 — Giả mạo tồn tại (existential forgery).

Mục tiêu: tạo một cặp (m, s) hợp lệ mà không cần thấy chữ ký nào của Alice.
Điều kiện: bộ kiểm tra RSA thuần chỉ so s^e mod n == m. Mallory chọn s ngẫu nhiên rồi tính m = s^e mod n.
m vô nghĩa, nhưng nếu hệ thống chỉ cần m là một mã giao dịch / số tiền thì đã đủ gây hại.
Phòng chống: băm + đệm có cấu trúc — s ngẫu nhiên gần như không bao giờ cho EM đúng cấu trúc 00 01 FF… 00 DigestInfo.
"""
from __future__ import annotations

import secrets

from core.padding import pkcs1_v15
from core.rsa_keygen import generate_keypair
from core.rsa_primitives import rsavp1
from core.step_logger import StepLogger
from core.utils import byte_len, i2osp
from attacks import AttackResult

NAME = "A2: Giả mạo tồn tại: chọn s, tính m = s^e"


def run(logger: StepLogger | None = None, defended: bool = False, bits: int = 1024, tries: int = 2000) -> AttackResult:
    log = logger if logger is not None else StepLogger()
    log.head(f"TẤN CÔNG A2: GIẢ MẠO TỒN TẠI ({'CÓ' if defended else 'KHÔNG'} phòng chống)")
    pub, _ = generate_keypair(bits)
    log.note("[1] Mallory chỉ có khoá công khai (n, e) của Alice, chưa thấy chữ ký nào")

    if not defended:
        s = 2 + secrets.randbelow(pub.n - 2)
        m = rsavp1(pub, s)
        log.log("[2] Chọn s ngẫu nhiên, tính m", r"m = s^{e} \mathrm{mod}\ n",
                f"s = 0x{format(s, 'x')[:32]}…\nm = 0x{format(m, 'x')[:32]}…")
        success = rsavp1(pub, s) == m
        log.log("[3] Bộ kiểm tra RSA thuần: s^e mod n == m ?", None,
                "HỢP LỆ: (m, s) là cặp thông điệp – chữ ký 'của Alice'" if success else "sai",
                level="bad" if success else "ok")
        hits = 1 if success else 0
    else:
        k = byte_len(pub.n)
        hits = 0
        for _ in range(tries):
            em = i2osp(rsavp1(pub, 2 + secrets.randbelow(pub.n - 2)), k)
            if pkcs1_v15.verify_strict(em, em[-32:]):
                hits += 1
        success = hits > 0
        log.log(f"[2] Có băm + đệm PKCS#1 v1.5: thử {tries} giá trị s ngẫu nhiên", None,
                f"Số s cho EM đúng cấu trúc: {hits}  (xác suất mỗi lần ≈ 2^-(8k − 256 − 8·|DigestInfo|))",
                level="bad" if success else "ok")
        log.note("    Kể cả khi trúng cấu trúc, còn phải tìm M có SHA256(M) bằng phần đuôi (tiền ảnh) → bất khả thi")

    summary = ("Giả mạo tồn tại thành công với RSA thuần." if success else
               "Thất bại: đệm có cấu trúc khiến s ngẫu nhiên không bao giờ hợp lệ.")
    (log.bad if success else log.ok)("[KẾT LUẬN] " + summary + " Phòng chống: băm + đệm có cấu trúc.")
    return AttackResult(NAME, success, summary, {"defended": defended, "structured_hits": hits})
