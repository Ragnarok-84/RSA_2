"""
scenarios/s2_nonrepudiation.py
Kịch bản S2: Chống chối bỏ giao dịch (Non-Repudiation) kết hợp Dấu thời gian (Timestamp).
"""
import sys
import os
import time
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from sha256 import hash_sha256
from keygen import generate_keypair
from rsa_core import sign_message, verify_message

def run_scenario_s2():
    print("\n=======================================================")
    print("KỊCH BẢN S2: CHỐNG CHỐI BỎ GIAO DỊCH (NON-REPUDIATION)")
    print("=======================================================")
    
    transaction = "Alice chuyển 100.000.000 VNĐ cho Bob"
    print(f"[1] Nội dung giao dịch: '{transaction}'")
    
    alice_priv, alice_pub = generate_keypair(keysize=512)
    signature = sign_message(transaction, alice_priv)   # băm SHA-256 + đệm PKCS#1 + ký RSA thật
    print(f"[2] Alice ký xác nhận giao dịch. Chữ ký: {str(signature)[:30]}...")
    
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"[3] Cơ quan Dấu thời gian (TSA) ghi nhận thời điểm giao dịch: {timestamp}")
    
    print("\n[4] Kiểm tra tranh chấp:")
    sig_ok = verify_message(transaction, signature, alice_pub)
    print(f"    - Chữ ký khớp với khóa công khai của Alice: {sig_ok}")
    # Bob thử sửa số tiền rồi dùng lại chữ ký
    forged_ok = verify_message("Alice chuyển 900.000.000 VNĐ cho Bob", signature, alice_pub)
    print(f"    - Bob sửa số tiền thành 900 triệu, dùng lại chữ ký: {'CHẤP NHẬN (lỗi!)' if forged_ok else 'BỊ TỪ CHỐI'}")
    print("    - Dấu thời gian: chỉ là mô phỏng bằng đồng hồ máy (TSA thật phải ký lên chữ ký, xem S5/S6)")
    if sig_ok and not forged_ok:
        print("[SUCCESS] Alice KHÔNG THỂ CHỐI BỎ giao dịch này trước tòa án!")
        return True
    print("[FAILED] Kiểm tra không đạt.")
    return False

if __name__ == "__main__":
    run_scenario_s2()
