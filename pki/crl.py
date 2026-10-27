# Tệp: pki/crl.py
# [Báo cáo 4.4 - Khóa bị lộ, thu hồi chứng thư]
# Danh sách chứng thư bị thu hồi (CRL - Certificate Revocation List).
#   - Mỗi mục ghi: số serial, THỜI ĐIỂM thu hồi, lý do.
#   - Ghi thời điểm để phân biệt chữ ký TRƯỚC khi lộ khóa (vẫn có giá trị nếu có dấu thời gian)
#     và chữ ký SAU khi lộ khóa (bị từ chối).
#   - CA ký lên bản CRL công bố, để kẻ tấn công không xóa được mục thu hồi trên đường truyền.
import json
from datetime import datetime

TIME_FMT = "%Y-%m-%d %H:%M:%S"
REASONS = ("keyCompromise", "cessationOfOperation", "superseded", "unspecified")


class CertificateRevocationList:
    """CRL do một CA quản lý."""

    def __init__(self, issuer):
        self.issuer = issuer
        self.entries = {}          # serial -> {"time": ..., "reason": ...}

    def revoke(self, serial, at=None, reason="keyCompromise"):
        if reason not in REASONS:
            raise ValueError(f"reason phải thuộc {REASONS}")
        self.entries[serial] = {"time": (at or datetime.now()).strftime(TIME_FMT), "reason": reason}

    def revoked_at(self, serial):
        """Thời điểm thu hồi (datetime) hoặc None nếu chưa bị thu hồi."""
        entry = self.entries.get(serial)
        return datetime.strptime(entry["time"], TIME_FMT) if entry else None

    def is_revoked(self, serial, now=None):
        """Chứng thư đã bị thu hồi TẠI thời điểm `now` chưa?"""
        at = self.revoked_at(serial)
        return at is not None and (now or datetime.now()) >= at

    def __contains__(self, serial):
        return serial in self.entries

    def tbs_string(self, this_update):
        """Nội dung cần ký của bản CRL công bố."""
        return json.dumps({"issuer": self.issuer, "this_update": this_update, "entries": self.entries},
                          sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def publish_crl(crl, ca_private_key, sign_data):
    """CA ký và công bố một bản chụp CRL. :return: dict có thể gửi đi"""
    this_update = datetime.now().strftime(TIME_FMT)
    return {"issuer": crl.issuer, "this_update": this_update,
            "entries": {str(k): v for k, v in crl.entries.items()},
            "signature": sign_data(crl.tbs_string(this_update), ca_private_key)}


def verify_published_crl(published, ca_cert, verify_data):
    """Kiểm tra chữ ký của CA trên bản CRL nhận được."""
    crl = CertificateRevocationList(published["issuer"])
    crl.entries = {int(k): v for k, v in published["entries"].items()}
    if published["issuer"] != ca_cert["subject"]:
        return False
    return verify_data(crl.tbs_string(published["this_update"]), published["signature"], ca_cert["public_key"])
