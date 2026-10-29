"""Kịch bản S4: tấn công phát lại."""
import json
import os
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.rsa_math import generate_keypair
from core.rsa_full import sign_message, verify_message
from pki.timestamp import NonceRegistry, TIME_FMT

MAX_CLOCK_SKEW = timedelta(minutes=5)


class NaiveBank:
    """Chỉ kiểm tra chữ ký."""

    def __init__(self, alice_pub):
        self.alice_pub, self.balance_moved = alice_pub, 0

    def submit(self, order_bytes, sig):
        if not verify_message(order_bytes, sig, self.alice_pub):
            return False, "Chữ ký sai"
        self.balance_moved += json.loads(order_bytes)["amount"]
        return True, "Đã chuyển"


class SecureBank(NaiveBank):
    """Kiểm tra chữ ký + nonce dùng một lần + thời điểm ký nằm trong cửa sổ cho phép."""

    def __init__(self, alice_pub):
        super().__init__(alice_pub)
        self.nonces = NonceRegistry(lifetime_seconds=300)

    def get_nonce(self):
        return self.nonces.issue("Thu Trang")

    def submit(self, order_bytes, sig, now=None):
        now = now or datetime.now()
        if not verify_message(order_bytes, sig, self.alice_pub):
            return False, "Chữ ký sai (lệnh bị sửa)"
        order = json.loads(order_bytes)
        if abs(now - datetime.strptime(order["time"], TIME_FMT)) > MAX_CLOCK_SKEW:
            return False, "Lệnh quá cũ"
        ok, why = self.nonces.consume(order["nonce"], "Thu Trang", now)
        if not ok:
            return False, why
        self.balance_moved += order["amount"]
        return True, "Đã chuyển"


def make_order(amount, to, nonce=None):
    order = {"from": "Thu Trang", "to": to, "amount": amount, "time": datetime.now().strftime(TIME_FMT)}
    if nonce:
        order["nonce"] = nonce
    return json.dumps(order, sort_keys=True, ensure_ascii=False).encode("utf-8")


def run_scenario_s4(keysize=1024, verbose=True):
    say = print if verbose else (lambda *a, **k: None)
    say("\n=======================================================")
    say("KỊCH BẢN S4: TẤN CÔNG PHÁT LẠI (REPLAY) — NONCE & DẤU THỜI GIAN")
    say("=======================================================")
    priv, pub = generate_keypair(keysize=keysize)

    say("\n--- A. NGÂN HÀNG CHỈ KIỂM TRA CHỮ KÝ ---")
    bank = NaiveBank(pub)
    order = make_order(5_000_000, "Thu Thủy")
    sig = sign_message(order, priv)
    say(f"[1] Thu Trang ký lệnh: {order.decode()}")
    results = [bank.submit(order, sig)[0] for _ in range(3)]
    say(f"[2] Mai Phương nghe lén và gửi lại 2 lần nữa -> kết quả 3 lần: {results}")
    say(f"    Tổng tiền bị chuyển: {bank.balance_moved:,} VNĐ (Thu Trang chỉ muốn chuyển 5.000.000)")
    naive_replayed = all(results)

    say("\n--- B. LỆNH CÓ NONCE + THỜI ĐIỂM ---")
    bank2 = SecureBank(pub)
    nonce = bank2.get_nonce()
    order2 = make_order(5_000_000, "Thu Thủy", nonce)
    sig2 = sign_message(order2, priv)
    say(f"[1] Ngân hàng cấp nonce '{nonce}', Thu Trang ký lệnh có nonce: {order2.decode()}")
    first = bank2.submit(order2, sig2)
    say(f"[2] Lần gửi đầu: {first[1]}")
    replay = bank2.submit(order2, sig2)
    say(f"[3] Mai Phương phát lại y nguyên: {'chấp nhận' if replay[0] else 'TỪ CHỐI'} — {replay[1]}")
    fresh = json.loads(order2)
    fresh["nonce"] = bank2.get_nonce()
    forged = json.dumps(fresh, sort_keys=True, ensure_ascii=False).encode("utf-8")
    refresh = bank2.submit(forged, sig2)
    say(f"[4] Mai Phương xin nonce mới, thay vào lệnh cũ, giữ chữ ký cũ: {'chấp nhận' if refresh[0] else 'TỪ CHỐI'} — {refresh[1]}")
    nonce3 = bank2.get_nonce()
    order3 = make_order(5_000_000, "Thu Thủy", nonce3)
    late = bank2.submit(order3, sign_message(order3, priv), now=datetime.now() + timedelta(hours=1))
    say(f"[5] Lệnh hợp lệ nhưng bị Mai Phương giữ lại 1 giờ mới gửi: {'chấp nhận' if late[0] else 'TỪ CHỐI'} — {late[1]}")
    say(f"    Tổng tiền bị chuyển: {bank2.balance_moved:,} VNĐ")

    success = naive_replayed and first[0] and not replay[0] and not refresh[0] and not late[0] \
        and bank2.balance_moved == 5_000_000
    say("[SUCCESS] Nonce dùng một lần + thời điểm ký chặn được tấn công phát lại." if success else "[FAILED]")
    return success


if __name__ == "__main__":
    run_scenario_s4()
