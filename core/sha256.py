"""Hàm băm SHA-256 (FIPS 180-4)."""
# 8 giá trị ban đầu của SHA-256
H0 = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]

# 64 hằng số K của SHA-256
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]


def _compress(H, block):
    """Hàm nén: xử lý một block 512 bit (64 byte), cập nhật 8 giá trị băm H tại chỗ."""
    W = []
    for i in range(16):
        word = int.from_bytes(block[i * 4:(i + 1) * 4], byteorder='big')
        W.append(word)

    for i in range(16, 64):
        s0 = (((W[i - 15] >> 7) | (W[i - 15] << 25)) ^
              ((W[i - 15] >> 18) | (W[i - 15] << 14)) ^
              (W[i - 15] >> 3)) & 0xffffffff

        s1 = (((W[i - 2] >> 17) | (W[i - 2] << 15)) ^
              ((W[i - 2] >> 19) | (W[i - 2] << 13)) ^
              (W[i - 2] >> 10)) & 0xffffffff

        W.append((W[i - 16] + s0 + W[i - 7] + s1) & 0xffffffff)

    a, b, c, d, e, f, g, h = H

    for i in range(64):
        S1 = (((e >> 6) | (e << 26)) ^
              ((e >> 11) | (e << 21)) ^
              ((e >> 25) | (e << 7))) & 0xffffffff
        ch = (e & f) ^ (~e & g)
        T1 = (h + S1 + ch + K[i] + W[i]) & 0xffffffff

        S0 = (((a >> 2) | (a << 30)) ^
              ((a >> 13) | (a << 19)) ^
              ((a >> 22) | (a << 10))) & 0xffffffff
        maj = (a & b) ^ (a & c) ^ (b & c)
        T2 = (S0 + maj) & 0xffffffff

        h = g
        g = f
        f = e
        e = (d + T1) & 0xffffffff
        d = c
        c = b
        b = a
        a = (T1 + T2) & 0xffffffff

    for i, v in enumerate((a, b, c, d, e, f, g, h)):
        H[i] = (H[i] + v) & 0xffffffff


class SHA256:
    """Băm theo từng phần (cấu trúc Merkle-Damgård): update(...) nhiều lần rồi hexdigest()."""

    def __init__(self, data=b""):
        self._H = list(H0)
        self._buffer = bytearray()
        self._length = 0              # tổng số byte đã nạp
        self.update(data)

    def update(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8')
        self._buffer += data
        self._length += len(data)
        n_full = len(self._buffer) // 64 * 64
        for i in range(0, n_full, 64):
            _compress(self._H, self._buffer[i:i + 64])
        del self._buffer[:n_full]
        return self

    def digest(self):
        H = list(self._H)
        # Đệm: thêm bit 1 (byte 0x80), các byte 0 tới khi độ dài ≡ 56 (mod 64), rồi 8 byte độ dài (bit)
        tail = bytearray(self._buffer) + b'\x80'
        while (len(tail) % 64) != 56:
            tail.append(0x00)
        tail += (self._length * 8).to_bytes(8, byteorder='big')
        for i in range(0, len(tail), 64):
            _compress(H, tail[i:i + 64])
        return b''.join(x.to_bytes(4, 'big') for x in H)

    def hexdigest(self):
        return self.digest().hex()


def hash_sha256(message):
    """
    Hàm băm thông điệp sử dụng SHA-256.
    :param message: Tài liệu gốc dạng chuỗi văn bản hoặc bytes
    :return: Dữ liệu đã được băm dạng chuỗi hex
    """
    return SHA256(message).hexdigest()


def sha256_bytes(message):
    """SHA-256 trả về 32 byte thô."""
    return SHA256(message).digest()


def hash_file(path, chunk_size=64 * 1024):
    """Băm một tệp theo từng khối (không phải đọc cả tệp vào bộ nhớ)."""
    h = SHA256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(chunk_size), b''):
            h.update(chunk)
    return h.hexdigest()


if __name__ == "__main__":
    msg = input("Nhập dữ liệu: ")
    result = hash_sha256(msg)
    print("SHA-256:", result)
