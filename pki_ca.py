# Tệp: pki_ca.py
# Chứng thư số và CA (Certificate Authority)
import json
from datetime import datetime, timedelta

from keygen import generate_keypair
from sha256 import hash_sha256
from math_utils import add_pkcs1_v15_padding, verify_signature, compare_hashes

DATE_FMT = "%Y-%m-%d"


# ---------------------------------------------------------------
# Hàm ký / xác thực dữ liệu bất kỳ (băm SHA-256 + đệm PKCS#1 v1.5 + RSA)
# ---------------------------------------------------------------
def sign_data(data, private_key):
    """Ký số: S = (padding(SHA256(data)))^d mod N"""
    d, N = private_key
    hash_hex = hash_sha256(data)
    em_length = (N.bit_length() + 7) // 8
    padded = add_pkcs1_v15_padding(hash_hex, em_length)
    return pow(padded, d, N)


def verify_data(data, signature, public_key):
    """Xác thực: so sánh SHA256(data) với bản băm gỡ ra từ chữ ký."""
    try:
        hash_a = hash_sha256(data)                              # bản băm tự tính
        hash_b = verify_signature(signature, tuple(public_key)) # bản băm gỡ từ chữ ký
        return compare_hashes(hash_a, hash_b)
    except (ValueError, OverflowError):
        return False


# ---------------------------------------------------------------
# Chứng thư số
# ---------------------------------------------------------------
def tbs_string(cert):
    """Phần nội dung cần ký của chứng thư (To-Be-Signed), dạng chuỗi cố định."""
    fields = ("serial", "subject", "issuer", "public_key", "not_before", "not_after")
    tbs = {k: cert[k] for k in fields}
    return json.dumps(tbs, sort_keys=True, separators=(",", ":"))


def print_certificate(cert):
    e, N = cert["public_key"]
    print(f"  Số serial     : {cert['serial']}")
    print(f"  Chủ thể       : {cert['subject']}")
    print(f"  Bên cấp phát  : {cert['issuer']}")
    print(f"  Hiệu lực      : {cert['not_before']} -> {cert['not_after']}")
    print(f"  Khóa công khai: e={e}, N={str(N)[:20]}... ({N.bit_length()} bit)")
    print(f"  Chữ ký CA     : {str(cert['signature'])[:20]}...")


class CertificateAuthority:
    """Tổ chức chứng thực số: giữ khóa riêng, cấp phát và thu hồi chứng thư."""

    def __init__(self, name, keysize=1024):
        self.name = name
        self._private_key, self.public_key = generate_keypair(keysize=keysize)
        self._next_serial = 1
        self.crl = set()  # danh sách thu hồi chứng thư (Certificate Revocation List)
        # Chứng thư gốc: CA tự ký cho chính mình
        self.certificate = self.issue_certificate(name, self.public_key, days=3650)

    def issue_certificate(self, subject, public_key, days=365, start=None):
        """Cấp chứng thư: gắn danh tính (subject) với khóa công khai rồi ký bằng khóa riêng của CA."""
        start = start or datetime.now()
        cert = {
            "serial": self._next_serial,
            "subject": subject,
            "issuer": self.name,
            "public_key": list(public_key),
            "not_before": start.strftime(DATE_FMT),
            "not_after": (start + timedelta(days=days)).strftime(DATE_FMT),
        }
        self._next_serial += 1
        cert["signature"] = sign_data(tbs_string(cert), self._private_key)
        return cert

    def revoke(self, serial):
        """Thu hồi chứng thư theo số serial."""
        self.crl.add(serial)


def verify_certificate(cert, ca_cert, crl=None, now=None):
    """
    Kiểm tra một chứng thư có đáng tin hay không.
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
    if crl and cert["serial"] in crl:
        return False, "Chứng thư đã bị thu hồi"

    return True, "Chứng thư hợp lệ"


# ---------------------------------------------------------------
# Chạy thử
# ---------------------------------------------------------------
if __name__ == "__main__":
    print("=== 1. CA tự ký chứng thư gốc ===")
    ca = CertificateAuthority("CA Goc ATBMTT", keysize=1024)
    print_certificate(ca.certificate)
    ok, msg = verify_certificate(ca.certificate, ca.certificate)
    print("  Kiểm tra chứng thư gốc:", msg)

    print("\n=== 2. Alice xin cấp chứng thư ===")
    alice_private, alice_public = generate_keypair(keysize=1024)
    alice_cert = ca.issue_certificate("Alice", alice_public, days=365)
    print_certificate(alice_cert)

    print("\n=== 3. Bob xác thực chứng thư của Alice ===")
    ok, msg = verify_certificate(alice_cert, ca.certificate, ca.crl)
    print("  Kết quả:", msg)

    print("\n=== 4. Alice ký tài liệu, Bob kiểm tra bằng khóa trong chứng thư ===")
    document = "Hop dong mua ban so 01/2026"
    signature = sign_data(document, alice_private)
    print("  Tài liệu gốc        :", verify_data(document, signature, alice_cert["public_key"]))
    print("  Tài liệu bị sửa     :", verify_data(document + " (sua)", signature, alice_cert["public_key"]))

    print("\n=== 5. Kẻ gian thay khóa công khai trong chứng thư ===")
    mallory_private, mallory_public = generate_keypair(keysize=1024)
    forged = dict(alice_cert)
    forged["public_key"] = list(mallory_public)
    ok, msg = verify_certificate(forged, ca.certificate, ca.crl)
    print("  Kết quả:", msg)

    print("\n=== 6. CA giả mạo cùng tên cấp chứng thư ===")
    fake_ca = CertificateAuthority("CA Goc ATBMTT", keysize=1024)
    fake_cert = fake_ca.issue_certificate("Alice", mallory_public)
    ok, msg = verify_certificate(fake_cert, ca.certificate, ca.crl)
    print("  Kết quả:", msg)

    print("\n=== 7. Chứng thư hết hạn ===")
    old_cert = ca.issue_certificate("Charlie", alice_public, days=30,
                                    start=datetime.now() - timedelta(days=400))
    ok, msg = verify_certificate(old_cert, ca.certificate, ca.crl)
    print("  Kết quả:", msg)

    print("\n=== 8. Thu hồi chứng thư của Alice ===")
    ca.revoke(alice_cert["serial"])
    ok, msg = verify_certificate(alice_cert, ca.certificate, ca.crl)
    print("  Kết quả:", msg)
