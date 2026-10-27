# Tệp: pki/timestamp.py
# [Báo cáo 4.4 - Dấu thời gian; 4.5 - Nonce, chống phát lại]
#   - TimestampAuthority: TSA ký lên cặp (SHA256(chữ ký), thời điểm) -> bằng chứng chữ ký đã tồn tại
#     tại thời điểm đó. Nhờ vậy chữ ký vẫn có giá trị sau khi chứng thư hết hạn / bị thu hồi,
#     nếu chữ ký được tạo TRƯỚC thời điểm thu hồi.
#   - NonceRegistry: phát nonce ngẫu nhiên dùng MỘT lần, có hạn dùng -> gói tin đã ký bị phát lại
#     (replay) sẽ bị từ chối.
import os
import secrets
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.rsa_math import generate_keypair
from core.sha256 import hash_sha256
from core.rsa_full import sign_message, verify_message

TIME_FMT = "%Y-%m-%d %H:%M:%S"


class TimestampAuthority:
    """Tổ chức cấp dấu thời gian (Time-Stamping Authority, mô phỏng RFC 3161)."""

    def __init__(self, name="TSA ATBMTT", keysize=1024):
        self.name = name
        self._private_key, self.public_key = generate_keypair(keysize=keysize)

    @staticmethod
    def _tbs(sig_hash, when):
        return f"TSA|{sig_hash}|{when}"

    def issue(self, signature, at=None):
        """Đóng dấu thời gian lên một chữ ký (TSA chỉ thấy giá trị băm, không thấy tài liệu)."""
        when = (at or datetime.now()).strftime(TIME_FMT)
        sig_hash = hash_sha256(str(signature))
        return {"tsa": self.name, "time": when, "sig_hash": sig_hash,
                "tsa_signature": sign_message(self._tbs(sig_hash, when), self._private_key)}

    def verify(self, token, signature):
        """Dấu thời gian hợp lệ khi: gắn đúng chữ ký này và chữ ký của TSA đúng."""
        if token.get("sig_hash") != hash_sha256(str(signature)):
            return False
        return verify_message(self._tbs(token["sig_hash"], token["time"]), token["tsa_signature"],
                              self.public_key)


def token_time(token):
    return datetime.strptime(token["time"], TIME_FMT)


class NonceRegistry:
    """Phát và thu hồi nonce dùng một lần (chống tấn công phát lại)."""

    def __init__(self, lifetime_seconds=120):
        self.lifetime = timedelta(seconds=lifetime_seconds)
        self._pending = {}         # nonce -> (chủ thể, thời điểm hết hạn)

    def issue(self, subject, now=None):
        nonce = f"{subject}|{secrets.token_hex(16)}"
        self._pending[nonce] = (subject, (now or datetime.now()) + self.lifetime)
        return nonce

    def consume(self, nonce, subject, now=None):
        """
        Dùng nonce: chỉ thành công MỘT lần, đúng chủ thể, còn hạn.
        :return: (True/False, lý do)
        """
        entry = self._pending.pop(nonce, None)
        if entry is None:
            return False, "Nonce không tồn tại hoặc đã được dùng (phát lại)"
        owner, expires = entry
        if owner != subject:
            return False, "Nonce không cấp cho chủ thể này"
        if (now or datetime.now()) > expires:
            return False, "Nonce đã hết hạn"
        return True, "Nonce hợp lệ"
