"""Tiện ích dùng chung: chuyển đổi số nguyên <-> chuỗi byte (RFC 8017 §4), hex, đo thời gian, so sánh hằng thời gian."""
from __future__ import annotations

import json
import time


def i2osp(x: int, length: int) -> bytes:
    """Integer-to-Octet-String (RFC 8017 §4.1): số nguyên không âm -> chuỗi byte big-endian dài đúng `length`.

    Ném ValueError nếu x < 0 hoặc x >= 256^length ("integer too large").
    """
    if x < 0:
        raise ValueError("i2osp: số nguyên phải không âm")
    if x >= 256 ** length:
        raise ValueError(f"i2osp: số nguyên quá lớn so với độ dài {length} byte")
    return x.to_bytes(length, "big")


def os2ip(b: bytes) -> int:
    """Octet-String-to-Integer (RFC 8017 §4.2): chuỗi byte big-endian -> số nguyên."""
    return int.from_bytes(b, "big")


def byte_len(n: int) -> int:
    """Số byte của modulus n: k = ceil(bitlen(n) / 8)."""
    return (n.bit_length() + 7) // 8


def to_hex(b: bytes) -> str:
    return b.hex()


def from_hex(s: str) -> bytes:
    """Đọc hex, bỏ qua khoảng trắng, xuống dòng và tiền tố 0x."""
    s = "".join(s.split())
    if s[:2].lower() == "0x":
        s = s[2:]
    return bytes.fromhex(s)


def constant_time_eq(a: bytes, b: bytes) -> bool:
    """So sánh hai chuỗi byte trong thời gian không phụ thuộc vị trí byte khác nhau đầu tiên.

    Luôn duyệt hết chuỗi rồi mới kết luận, tránh lộ thông tin qua thời gian phản hồi (timing attack).
    Độ dài khác nhau thì trả False ngay (độ dài không phải bí mật).
    """
    if len(a) != len(b):
        return False
    diff = 0
    for x, y in zip(a, b):
        diff |= x ^ y
    return diff == 0


def canonical_json(obj: object) -> bytes:
    """Dạng chuẩn tắc của một cấu trúc JSON trước khi ký: khoá sắp xếp, không khoảng trắng, UTF-8.

    Hai bên ký và kiểm tra phải băm cùng một chuỗi byte, nên mọi cấu trúc được ký đều đi qua hàm này.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def short_hex(x: int | bytes, head: int = 16, tail: int = 8) -> str:
    """Rút gọn số/chuỗi byte dài để hiển thị: 0x1a2b…9f (2048 bit)."""
    if isinstance(x, int):
        h, bits = format(x, "x"), x.bit_length()
    else:
        h, bits = x.hex(), len(x) * 8
    body = h if len(h) <= head + tail + 1 else f"{h[:head]}…{h[-tail:]}"
    return f"0x{body} ({bits} bit)"


class Timer:
    """Đo thời gian một khối lệnh bằng time.perf_counter.

        with Timer() as t:
            ...
        t.elapsed   # giây
    """

    def __enter__(self) -> "Timer":
        self.start = time.perf_counter()
        self.elapsed = 0.0
        return self

    def __exit__(self, *exc: object) -> None:
        self.elapsed = time.perf_counter() - self.start
