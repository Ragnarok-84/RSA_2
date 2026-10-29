"""A8 — Phát lại thông điệp đã ký.

Mục tiêu: một lệnh "chuyển 1 triệu" ký hợp lệ được thực hiện nhiều lần.
Điều kiện: phần được ký không có gì làm nó duy nhất; ngân hàng chỉ kiểm tra chữ ký.
Mallory nghe lén (lệnh, chữ ký) rồi gửi lại y nguyên — chữ ký vẫn đúng.
Phòng chống: đưa nonce / timestamp / số thứ tự VÀO phần được ký; bên nhận ghi nhớ nonce đã dùng và
từ chối lệnh quá cũ. Sửa nonce để lách thì chữ ký không còn khớp.
"""
from __future__ import annotations

import json
import secrets

from core.rsa_keygen import RSAPublicKey, generate_keypair
from core.signature import sign, verify
from core.step_logger import StepLogger
from core.utils import canonical_json
from pki.certificate import now
from attacks import AttackResult

NAME = "A8: Phát lại thông điệp đã ký"
MAX_AGE = 300


class Bank:
    def __init__(self, alice_pub: RSAPublicKey, check_freshness: bool) -> None:
        self.pub, self.check = alice_pub, check_freshness
        self.used: set[str] = set()
        self.moved = 0

    def submit(self, order: bytes, sig: bytes, at: int | None = None) -> tuple[bool, str]:
        if not verify(order, sig, self.pub):
            return False, "chữ ký sai (lệnh bị sửa)"
        data = json.loads(order)
        if self.check:
            if "nonce" not in data or "time" not in data:
                return False, "lệnh thiếu nonce / thời điểm"
            if abs((now() if at is None else at) - data["time"]) > MAX_AGE:
                return False, "lệnh quá cũ"
            if data["nonce"] in self.used:
                return False, "nonce đã dùng → phát lại"
            self.used.add(data["nonce"])
        self.moved += data["amount"]
        return True, "đã chuyển tiền"


def run(logger: StepLogger | None = None, defended: bool = False, bits: int = 1024) -> AttackResult:
    log = logger if logger is not None else StepLogger()
    log.head(f"TẤN CÔNG A8: PHÁT LẠI ({'CÓ' if defended else 'KHÔNG'} nonce + timestamp trong phần được ký)")
    pub, priv = generate_keypair(bits)
    bank = Bank(pub, check_freshness=defended)
    order_obj: dict = {"from": "Alice", "to": "Bob", "amount": 1_000_000}
    if defended:
        order_obj.update(nonce=secrets.token_hex(16), time=now())
    order = canonical_json(order_obj)
    sig = sign(order, priv)
    log.log("[1] Alice ký lệnh chuyển tiền", r"S = \mathrm{Sign}_{d_A}(\mathrm{lenh})", order.decode())

    results = [bank.submit(order, sig) for _ in range(3)]
    for i, (ok, why) in enumerate(results):
        log.log(f"[{i + 2}] {'Alice gửi' if i == 0 else 'Mallory phát lại y nguyên'}", None, why,
                level="" if i == 0 else ("bad" if ok else "ok"))

    if defended:
        tweaked = dict(order_obj, nonce=secrets.token_hex(16))
        ok, why = bank.submit(canonical_json(tweaked), sig)
        log.log("[5] Mallory đổi nonce mới để lách, giữ chữ ký cũ", None, why, level="bad" if ok else "ok")

    accepted = sum(ok for ok, _ in results)
    success = accepted > 1
    log.note("Tổng tiền bị chuyển", f"{bank.moved:,} VNĐ (Alice chỉ muốn chuyển 1.000.000)")
    summary = (f"Lệnh được thực hiện {accepted} lần." if success else "Thất bại: lệnh chỉ được thực hiện một lần.")
    (log.bad if success else log.ok)("[KẾT LUẬN] " + summary + " Phòng chống: nonce/timestamp/số thứ tự trong phần được ký.")
    return AttackResult(NAME, success, summary, {"defended": defended, "accepted": accepted, "moved": bank.moved})
