from __future__ import annotations

from pathlib import Path

MASK = 0xFFFFFFFF
BLOCK_SIZE = 64
DIGEST_SIZE = 32
CHUNK_SIZE = 64 * 1024            # đọc tệp 64 KB / lần

H0 = (
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
)

K = (
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
)


# Các phép phụ (FIPS 180-4 §3.2, §4.1.2)
def rotr(x: int, n: int) -> int:
    """ROTR^n(x): xoay phải n bít trên từ 32 bít."""
    return ((x >> n) | (x << (32 - n))) & MASK


def ch(x: int, y: int, z: int) -> int:
    """Ch(x, y, z) = (x ∧ y) ⊕ (¬x ∧ z)"""
    return (x & y) ^ (~x & z)


def maj(x: int, y: int, z: int) -> int:
    """Maj(x, y, z) = (x ∧ y) ⊕ (x ∧ z) ⊕ (y ∧ z)"""
    return (x & y) ^ (x & z) ^ (y & z)


def big_sigma0(x: int) -> int:
    """Σ0(x) = ROTR²(x) ⊕ ROTR¹³(x) ⊕ ROTR²²(x)"""
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)


def big_sigma1(x: int) -> int:
    """Σ1(x) = ROTR⁶(x) ⊕ ROTR¹¹(x) ⊕ ROTR²⁵(x)"""
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)


def small_sigma0(x: int) -> int:
    """σ0(x) = ROTR⁷(x) ⊕ ROTR¹⁸(x) ⊕ SHR³(x)"""
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)


def small_sigma1(x: int) -> int:
    """σ1(x) = ROTR¹⁷(x) ⊕ ROTR¹⁹(x) ⊕ SHR¹⁰(x)"""
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)


def pad(length: int) -> bytes:
    """Phần đệm thêm vào sau thông điệp dài `length` byte (FIPS 180-4 §5.1.1)."""
    zeros = (55 - length) % 64
    return b"\x80" + b"\x00" * zeros + (length * 8).to_bytes(8, "big")


def _compress(H: list[int], block: bytes) -> None:
    """Hàm nén cho một khối 512 bít, cập nhật H tại chỗ.

    Vòng lặp viết khai triển các phép Σ, σ, Ch, Maj ở trên (không gọi hàm) để băm tệp lớn nhanh hơn;
    test/unit kiểm tra hai cách viết cho cùng kết quả.
    """
    W = [int.from_bytes(block[i:i + 4], "big") for i in range(0, 64, 4)]
    for t in range(16, 64):
        x, y = W[t - 15], W[t - 2]
        s0 = (((x >> 7) | (x << 25)) ^ ((x >> 18) | (x << 14)) ^ (x >> 3)) & MASK
        s1 = (((y >> 17) | (y << 15)) ^ ((y >> 19) | (y << 13)) ^ (y >> 10)) & MASK
        W.append((W[t - 16] + s0 + W[t - 7] + s1) & MASK)

    a, b, c, d, e, f, g, h = H
    for t in range(64):
        S1 = (((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))) & MASK
        T1 = (h + S1 + ((e & f) ^ (~e & g)) + K[t] + W[t]) & MASK
        S0 = (((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10))) & MASK
        T2 = (S0 + ((a & b) ^ (a & c) ^ (b & c))) & MASK
        h, g, f, e, d, c, b, a = g, f, e, (d + T1) & MASK, c, b, a, (T1 + T2) & MASK

    for i, v in enumerate((a, b, c, d, e, f, g, h)):
        H[i] = (H[i] + v) & MASK


def compress_reference(H: list[int], block: bytes) -> list[int]:
    """Hàm nén viết đúng ký hiệu FIPS 180-4 (gọi các phép phụ), trả H mới; dùng để đối chiếu trong test."""
    W = [int.from_bytes(block[i:i + 4], "big") for i in range(0, 64, 4)]
    for t in range(16, 64):
        W.append((small_sigma1(W[t - 2]) + W[t - 7] + small_sigma0(W[t - 15]) + W[t - 16]) & MASK)
    a, b, c, d, e, f, g, h = H
    for t in range(64):
        T1 = (h + big_sigma1(e) + ch(e, f, g) + K[t] + W[t]) & MASK
        T2 = (big_sigma0(a) + maj(a, b, c)) & MASK
        h, g, f, e, d, c, b, a = g, f, e, (d + T1) & MASK, c, b, a, (T1 + T2) & MASK
    return [(x + y) & MASK for x, y in zip(H, (a, b, c, d, e, f, g, h))]


class SHA256:
    """Băm theo từng phần (Merkle–Damgård): update() nhiều lần rồi digest()."""

    digest_size = DIGEST_SIZE
    block_size = BLOCK_SIZE

    def __init__(self, data: bytes = b"") -> None:
        self._H = list(H0)
        self._buffer = bytearray()
        self._length = 0
        if data:
            self.update(data)

    def update(self, data: bytes) -> "SHA256":
        self._buffer += data
        self._length += len(data)
        full = len(self._buffer) // BLOCK_SIZE * BLOCK_SIZE
        view = bytes(self._buffer[:full])
        for i in range(0, full, BLOCK_SIZE):
            _compress(self._H, view[i:i + BLOCK_SIZE])
        del self._buffer[:full]
        return self

    def copy(self) -> "SHA256":
        other = SHA256()
        other._H, other._buffer, other._length = list(self._H), bytearray(self._buffer), self._length
        return other

    def digest(self) -> bytes:
        H = list(self._H)
        tail = bytes(self._buffer) + pad(self._length)
        for i in range(0, len(tail), BLOCK_SIZE):
            _compress(H, tail[i:i + BLOCK_SIZE])
        return b"".join(x.to_bytes(4, "big") for x in H)

    def hexdigest(self) -> str:
        return self.digest().hex()


def sha256(data: bytes) -> bytes:
    """SHA-256(data), 32 byte."""
    return SHA256(data).digest()


def sha256_file(path: Path, progress=None) -> bytes:
    """Băm tệp theo khối 64 KB (không đọc cả tệp vào bộ nhớ). `progress(done, total)` nếu cần báo tiến độ."""
    path = Path(path)
    total = path.stat().st_size
    h, done = SHA256(), 0
    with path.open("rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            h.update(chunk)
            done += len(chunk)
            if progress is not None:
                progress(done, total)
    return h.digest()
