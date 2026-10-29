"""Chứng thư số và tổ chức chứng thực (CA)."""
import json
import os
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.rsa_math import generate_keypair
from core.rsa_full import sign_message, verify_message
from pki.crl import CertificateRevocationList, publish_crl

DATE_FMT = "%Y-%m-%d"
USAGES = ("signature", "encryption", "ca", "timestamp")


# Hàm ký / xác thực dữ liệu bất kỳ (băm SHA-256 + đệm PKCS#1 v1.5 + RSA)
def sign_data(data, private_key):
    """Ký số: S = (padding(SHA256(data)))^d mod N"""
    return sign_message(data, private_key)


def verify_data(data, signature, public_key):
    """Xác thực: so sánh SHA256(data) với bản băm gỡ ra từ chữ ký."""
    try:
        return verify_message(data, signature, tuple(public_key))
    except (ValueError, OverflowError, TypeError):
        return False


# Chứng thư số
TBS_FIELDS = ("serial", "subject", "issuer", "public_key", "not_before", "not_after", "key_usage")


def tbs_string(cert):
    """Phần nội dung cần ký của chứng thư (To-Be-Signed), dạng chuỗi cố định."""
    tbs = {k: cert[k] for k in TBS_FIELDS}
    return json.dumps(tbs, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def print_certificate(cert, say=print):
    e, N = cert["public_key"]
    say(f"  Số serial     : {cert['serial']}")
    say(f"  Chủ thể       : {cert['subject']}")
    say(f"  Bên cấp phát  : {cert['issuer']}")
    say(f"  Hiệu lực      : {cert['not_before']} -> {cert['not_after']}")
    say(f"  Mục đích khóa : {cert['key_usage']}")
    say(f"  Khóa công khai: e={e}, N={str(N)[:20]}... ({N.bit_length()} bit)")
    say(f"  Chữ ký CA     : {str(cert['signature'])[:20]}...")


class CertificateAuthority:
    """Tổ chức chứng thực số: giữ khóa riêng, cấp phát và thu hồi chứng thư."""

    def __init__(self, name, keysize=1024):
        self.name = name
        self._private_key, self.public_key = generate_keypair(keysize=keysize)
        self._next_serial = 1
        self.crl = CertificateRevocationList(name)
        # Chứng thư gốc: CA tự ký cho chính mình
        self.certificate = self.issue_certificate(name, self.public_key, days=3650, key_usage="ca")

    def issue_certificate(self, subject, public_key, days=365, start=None, key_usage="signature"):
        """Cấp chứng thư: gắn danh tính (subject) với khóa công khai rồi ký bằng khóa riêng của CA."""
        if key_usage not in USAGES:
            raise ValueError(f"key_usage phải thuộc {USAGES}")
        start = start or datetime.now()
        cert = {
            "serial": self._next_serial,
            "subject": subject,
            "issuer": self.name,
            "public_key": list(public_key),
            "not_before": start.strftime(DATE_FMT),
            "not_after": (start + timedelta(days=days)).strftime(DATE_FMT),
            "key_usage": key_usage,
        }
        self._next_serial += 1
        cert["signature"] = sign_data(tbs_string(cert), self._private_key)
        return cert

    def revoke(self, serial, at=None, reason="keyCompromise"):
        """Thu hồi chứng thư theo số serial, kể từ thời điểm `at` (mặc định: bây giờ)."""
        self.crl.revoke(serial, at, reason)

    def publish_crl(self):
        """Công bố CRL có chữ ký của CA."""
        return publish_crl(self.crl, self._private_key, sign_data)


def verify_certificate(cert, ca_cert, crl=None, now=None, usage=None):
    """
    Kiểm tra một chứng thư có đáng tin hay không tại thời điểm `now`.
    :param crl: CertificateRevocationList của CA (None = không kiểm tra thu hồi)
    :param usage: mục đích cần dùng ("signature"/"encryption"); None = không kiểm tra
    :return: (True/False, lý do)
    """
    now = now or datetime.now()

    # 1. Đúng bên cấp phát
    if cert["issuer"] != ca_cert["subject"]:
        return False, "Bên cấp phát không khớp với CA đang tin cậy"

    # 2. Chữ ký của CA trên chứng thư
    if not verify_data(tbs_string(cert), cert["signature"], ca_cert["public_key"]):
        return False, "Chữ ký CA không hợp lệ (chứng thư bị sửa hoặc do CA giả mạo cấp)"

    # 3. Thời hạn hiệu lực
    not_before = datetime.strptime(cert["not_before"], DATE_FMT)
    not_after = datetime.strptime(cert["not_after"], DATE_FMT) + timedelta(days=1)
    if now < not_before:
        return False, "Chứng thư chưa có hiệu lực"
    if now >= not_after:
        return False, "Chứng thư đã hết hạn"

    # 4. Danh sách thu hồi
    if crl is not None and crl.is_revoked(cert["serial"], now):
        return False, f"Chứng thư đã bị thu hồi từ {crl.entries[cert['serial']]['time']}"

    # 5. Mục đích sử dụng khóa
    if usage and cert.get("key_usage") != usage:
        return False, f"Khóa chỉ được cấp cho mục đích '{cert.get('key_usage')}', không dùng cho '{usage}'"

    return True, "Chứng thư hợp lệ"


def run_demo(keysize=1024, verbose=True):
    say = print if verbose else (lambda *a, **k: None)
    r = {}
    say("=== 1. CA tự ký chứng thư gốc ===")
    ca = CertificateAuthority("CA Goc ATBMTT", keysize=keysize)
    print_certificate(ca.certificate, say)
    r["root"], msg = verify_certificate(ca.certificate, ca.certificate)
    say("  Kiểm tra chứng thư gốc:", msg)

    say("\n=== 2. Thu Trang xin cấp chứng thư ===")
    alice_private, alice_public = generate_keypair(keysize=keysize)
    alice_cert = ca.issue_certificate("Thu Trang", alice_public, days=365)
    print_certificate(alice_cert, say)

    say("\n=== 3. Thu Thủy xác thực chứng thư của Thu Trang ===")
    r["alice_valid"], msg = verify_certificate(alice_cert, ca.certificate, ca.crl, usage="signature")
    say("  Kết quả:", msg)

    say("\n=== 4. Thu Trang ký tài liệu, Thu Thủy kiểm tra bằng khóa trong chứng thư ===")
    document = "Hop dong mua ban so 01/2026"
    signature = sign_data(document, alice_private)
    r["doc_ok"] = verify_data(document, signature, alice_cert["public_key"])
    r["doc_tampered"] = verify_data(document + " (sua)", signature, alice_cert["public_key"])
    say("  Tài liệu gốc        :", r["doc_ok"])
    say("  Tài liệu bị sửa     :", r["doc_tampered"])

    say("\n=== 5. Kẻ gian thay khóa công khai trong chứng thư ===")
    mallory_private, mallory_public = generate_keypair(keysize=keysize)
    forged = dict(alice_cert)
    forged["public_key"] = list(mallory_public)
    r["forged_key"], msg = verify_certificate(forged, ca.certificate, ca.crl)
    say("  Kết quả:", msg)

    say("\n=== 6. CA giả mạo cùng tên cấp chứng thư ===")
    fake_ca = CertificateAuthority("CA Goc ATBMTT", keysize=keysize)
    fake_cert = fake_ca.issue_certificate("Thu Trang", mallory_public)
    r["fake_ca"], msg = verify_certificate(fake_cert, ca.certificate, ca.crl)
    say("  Kết quả:", msg)

    say("\n=== 7. Chứng thư hết hạn ===")
    old_cert = ca.issue_certificate("Tuyết Linh", alice_public, days=30,
                                    start=datetime.now() - timedelta(days=400))
    r["expired"], msg = verify_certificate(old_cert, ca.certificate, ca.crl)
    say("  Kết quả:", msg)

    say("\n=== 8. Dùng khóa ký để mã hóa (sai mục đích) ===")
    r["wrong_usage"], msg = verify_certificate(alice_cert, ca.certificate, ca.crl, usage="encryption")
    say("  Kết quả:", msg)

    say("\n=== 9. Thu hồi chứng thư của Thu Trang ===")
    ca.revoke(alice_cert["serial"])
    r["revoked"], msg = verify_certificate(alice_cert, ca.certificate, ca.crl)
    say("  Kết quả:", msg)
    return r


if __name__ == "__main__":
    run_demo()
