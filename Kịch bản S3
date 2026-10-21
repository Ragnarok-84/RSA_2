"""
scenarios/s3_revocation.py
Kịch bản S3: Quản lý Danh sách chứng thư bị thu hồi (CRL - Certificate Revocation List).
"""
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

class SimpleCRL:
    def __init__(self):
        self.revoked_serials = set()
    def revoke(self, serial):
        self.revoked_serials.add(serial)
    def is_revoked(self, serial):
        return serial in self.revoked_serials

def run_scenario_s3():
    print("\n=======================================================")
    print("KỊCH BẢN S3: THU HỒI KHÓA VÀ KIỂM TRA CRL (REVOCATION)")
    print("=======================================================")
    
    crl = SimpleCRL()
    cert_serial = 888899
    
    print(f"[1] Chứng thư số của Bob có Serial: {cert_serial} (Trạng thái: Hợp lệ)")
    print("[2] SỰ CỐ: Bob bị mất thiết bị lưu trữ khóa riêng (Key Compromised).")
    
    crl.revoke(cert_serial)
    print(f"[3] CA đã đưa Serial {cert_serial} vào hệ thống CRL.")
    
    print("\n[4] Hệ thống tiến hành kiểm tra chứng thư khi nhận thông điệp từ Bob:")
    if crl.is_revoked(cert_serial):
        print(f"[REJECTED] Chứng thư số {cert_serial} đã BỊ THU HỒI! Giao dịch bị từ chối lập tức.")
        return True
    else:
        print("[ACCEPTED] Chứng thư hợp lệ.")
        return False

if __name__ == "__main__":
    run_scenario_s3()
