from sha256 import hash_sha256

def add_pkcs1_v15_padding(hash_value, em_length):
    """
    Hàm thêm đệm PKCS#1 v1.5 vào giá trị băm trước khi ký[cite: 5].
    :param hash_value: Giá trị băm SHA-256 (chuỗi hex)
    :param em_length: Độ dài của thông điệp mã hóa (tính bằng byte)
    :return: Dữ liệu đã được thêm đệm dạng số nguyên
    """
    hash_bytes = bytes.fromhex(hash_value)
    # Prefix định danh chuẩn của SHA-256 trong PKCS#1 v1.5[cite: 2]
    prefix = b'\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20'
    t = prefix + hash_bytes
    
    if em_length < len(t) + 11:
        raise ValueError("Độ dài khóa quá ngắn để đệm (cần ít nhất 1024-bit)")
        
    # Tạo chuỗi padding với các byte 0xFF[cite: 2]
    ps = b'\xff' * (em_length - len(t) - 3)
    padded_msg = b'\x00\x01' + ps + b'\x00' + t
    
    return int.from_bytes(padded_msg, 'big')

def sign_message(message, private_key):
    """
    Hàm thực hiện ký số hoàn chỉnh: Băm -> Đệm -> Ký (mã hóa bằng khóa riêng).
    :param message: Tài liệu/Thông điệp cần ký
    :param private_key: Khóa riêng (d, N)
    :return: Chữ ký số S dạng số nguyên
    """
    d, N = private_key
    em_length = (N.bit_length() + 7) // 8
    
    # Bước 1: Băm thông điệp bằng thuật toán SHA-256[cite: 4]
    hash_value = hash_sha256(message)
    
    # Bước 2: Thêm đệm PKCS#1 v1.5
    padded_msg_int = add_pkcs1_v15_padding(hash_value, em_length)
    
    # Bước 3: Ký số bằng phép lũy thừa modulo (S = M^d mod N)
    signature = pow(padded_msg_int, d, N)
    return signature

def verify_signature(signature, public_key):
    """
    Hàm gỡ chữ ký số để lấy bản băm (Bản băm B)[cite: 5].
    :param signature: Chữ ký số S từ người gửi (dạng số nguyên)
    :param public_key: Khóa công khai (e, N)
    :return: Bản băm B sau khi dùng khóa công khai để giải mã
    """
    e, N = public_key
    
    # Giải mã chữ ký (M' = S^e mod N)[cite: 2]
    padded_hash_int = pow(signature, e, N)
    
    # Chuyển số nguyên về lại dạng byte[cite: 2]
    em_length = (N.bit_length() + 7) // 8
    padded_msg = padded_hash_int.to_bytes(em_length, 'big')
    
    # Cắt bỏ phần đệm để trích xuất mã băm[cite: 2]
    try:
        # Tìm vị trí byte 0x00 kết thúc chuỗi đệm FF[cite: 2]
        zero_idx = padded_msg.index(b'\x00', 2)
        # Bỏ qua phần đệm và 19 byte prefix của SHA-256[cite: 2]
        hash_bytes = padded_msg[zero_idx + 1 + 19:]
        return hash_bytes.hex()
    except ValueError:
        return None

def compare_hashes(hash_A, hash_B):
    """
    Hàm so sánh hai bản băm để kiểm tra tính toàn vẹn và xác thực[cite: 5].
    :param hash_A: Bản băm tự tính từ tài liệu nhận được
    :param hash_B: Bản băm gỡ ra từ chữ ký số
    :return: True nếu chữ ký hợp lệ, False nếu bị giả mạo[cite: 5]
    """
    return hash_A == hash_B and hash_B is not None

def verify_message(message, signature, public_key):
    """
    Hàm kiểm tra chữ ký tổng hợp (Tự động Băm tài liệu và so sánh với Chữ ký).
    :param message: Tài liệu nhận được
    :param signature: Chữ ký số đi kèm
    :param public_key: Khóa công khai của người gửi
    :return: True (Hợp lệ) / False (Bị giả mạo)
    """
    # Bản băm A tự tính từ tài liệu[cite: 5]
    hash_A = hash_sha256(message)
    # Bản băm B gỡ từ chữ ký[cite: 5]
    hash_B = verify_signature(signature, public_key)
    
    return compare_hashes(hash_A, hash_B)
