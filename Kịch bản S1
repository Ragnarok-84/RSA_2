"""
scenarios/s1_authentication.py
Kịch bản S1: Xác thực danh tính người dùng (Authentication) thông qua Thách - Đáp (Challenge-Response) và Chữ ký số.
"""
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from sha256 import hash_sha256

def run_scenario_s1():
    print("\n=======================================================")
    print("KỊCH BẢN S1: XÁC THỰC NGƯỜI DÙNG (AUTHENTICATION)")
    print("=======================================================")
    
    # Giả lập khóa RSA của Alice
    alice_pub = (65537, 3233)
    alice_priv = (2753, 3233)
    
    nonce_challenge = "Server_Nonce_Random_2026_XYZ"
    print(f"[1] Server gửi chuỗi thử thách (Challenge/Nonce): '{nonce_challenge}'")
    
    # Alice ký vào thách thức
    h_val = hash_sha256(nonce_challenge)
    signature = pow(int(h_val[:8], 16), alice_priv[0], alice_priv[1])
    print(f"[2] Alice dùng Khóa riêng ký lên Challenge, sinh chữ ký: {signature}")
    
    # Server xác thực
    recovered_h = pow(signature, alice_pub[0], alice_pub[1])
    expected_h = int(h_val[:8], 16) % alice_pub[1]
    
    if recovered_h == expected_h:
        print("[SUCCESS] Xác thực THÀNH CÔNG! Danh tính Alice được xác thực chính xác.")
        return True
    else:
        print("[FAILED] Xác thực THẤT BẠI!")
        return False

if __name__ == "__main__":
    run_scenario_s1()
