import os as _os
import sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))

from core.sha256 import hash_sha256
from core.rsa_math import compare_hashes

def generate_hmac(key, message):
    """
    Hàm tạo mã xác thực thông điệp HMAC sử dụng thuật toán băm SHA-256.
    
    :param key: Khóa bí mật dùng để xác thực (chuỗi văn bản hoặc bytes)
    :param message: Thông điệp gốc cần tạo mã (chuỗi văn bản hoặc bytes)
    :return: Mã HMAC đã được tạo dạng chuỗi hex
    """
    block_size = 64  # Kích thước khối của thuật toán SHA-256 là 64 byte (512 bit)
    
    if isinstance(key, str):
        key = key.encode('utf-8')
    if isinstance(message, str):
        message = message.encode('utf-8')
        
    # Bước 1: Xử lý độ dài của Khóa (Key)
    if len(key) > block_size:
        # Nếu khóa dài hơn block_size, băm khóa để nén lại
        key = bytes.fromhex(hash_sha256(key))
        
    if len(key) < block_size:
        # Nếu khóa ngắn hơn block_size, thêm đệm (padding) các byte 0x00 vào bên phải
        key = key.ljust(block_size, b'\x00')
        
    # Bước 2: Tạo inner_pad (ipad) và outer_pad (opad)
    # ipad = 0x36 lặp lại block_size lần, opad = 0x5C lặp lại block_size lần
    ipad = bytes((x ^ 0x36) for x in key)
    opad = bytes((x ^ 0x5C) for x in key)
    
    # Bước 3: Tính băm bên trong -> Hash(ipad || message)
    inner_hash_hex = hash_sha256(ipad + message)
    inner_hash_bytes = bytes.fromhex(inner_hash_hex)
    
    # Bước 4: Tính băm bên ngoài để ra kết quả HMAC -> Hash(opad || inner_hash_bytes)
    hmac_hex = hash_sha256(opad + inner_hash_bytes)
    
    return hmac_hex

def verify_hmac(key, message, received_hmac):
    """
    Hàm xác thực tính toàn vẹn và nguồn gốc của HMAC.
    
    :param key: Khóa bí mật chia sẻ giữa hai bên (chuỗi hoặc bytes)
    :param message: Thông điệp nhận được
    :param received_hmac: Mã HMAC đính kèm theo thông điệp để kiểm tra
    :return: True nếu HMAC hợp lệ (thông điệp không bị giả mạo), False nếu ngược lại
    """
    calculated_hmac = generate_hmac(key, message)
    
    return compare_hashes(calculated_hmac, received_hmac)

def pbkdf2_hmac_sha256(password, salt, iterations, dklen=32):
    """
    PBKDF2 (RFC 8018) với HMAC-SHA256: sinh khóa từ mật khẩu, lặp nhiều lần để làm chậm
    tấn công dò mật khẩu. Dùng để mã hóa tệp khóa riêng.
    T_i = U_1 XOR U_2 XOR ... XOR U_c,  U_1 = HMAC(P, S || INT(i)),  U_j = HMAC(P, U_{j-1})
    """
    if isinstance(password, str):
        password = password.encode('utf-8')
    out = b''
    block = 1
    while len(out) < dklen:
        u = bytes.fromhex(generate_hmac(password, salt + block.to_bytes(4, 'big')))
        t = int.from_bytes(u, 'big')
        for _ in range(iterations - 1):
            u = bytes.fromhex(generate_hmac(password, u))
            t ^= int.from_bytes(u, 'big')
        out += t.to_bytes(32, 'big')
        block += 1
    return out[:dklen]

if __name__ == "__main__":
    secret_key = "KhoaBiMat_ATBMTT_2026"
    msg = "Giao dich chuyen khoan 1000 VNĐ"
    
    hmac_result = generate_hmac(secret_key, msg)
    print("Thông điệp gốc:", msg)
    print("Mã HMAC-SHA256 sinh ra:", hmac_result)
    
    print("\n--- Tiến hành xác thực ---")
    is_valid = verify_hmac(secret_key, msg, hmac_result)
    print("Xác thực thông điệp nguyên vẹn:", "Thành công" if is_valid else "Thất bại")
    
    fake_msg = "Giao dich chuyen khoan 9999 VNĐ"
    is_valid_fake = verify_hmac(secret_key, fake_msg, hmac_result)
    print("\nXác thực thông điệp bị sửa đổi:", "Thành công" if is_valid_fake else "Thất bại (Phát hiện giả mạo)")
