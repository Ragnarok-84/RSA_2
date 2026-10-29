"""Tổ chức cấp dấu thời gian (TSA, mô phỏng RFC 3161).

    token = Sign_{d_TSA}( SHA256(S) || t )

TSA chỉ thấy giá trị băm của chữ ký S, không thấy tài liệu. Token chứng minh S đã tồn tại tại thời điểm t,
nên chữ ký tạo TRƯỚC lúc khoá bị thu hồi vẫn giữ giá trị (scenarios/s4_key_compromise.py).
"""
from __future__ import annotations

from dataclasses import dataclass

from core.hash.sha256 import sha256
from core.rsa_keygen import RSAPrivateKey, RSAPublicKey, generate_keypair
from core.signature import sign, verify
from core.utils import constant_time_eq, from_hex
from pki.certificate import Certificate, now


@dataclass
class TimestampToken:
    tsa: str
    time: int
    signature_hash_hex: str
    token_signature_hex: str = ""

    def tbs_bytes(self) -> bytes:
        """SHA256(S) || t  (t: 8 byte big-endian, số giây Unix)."""
        return from_hex(self.signature_hash_hex) + self.time.to_bytes(8, "big")

    def to_dict(self) -> dict:
        return {"tsa": self.tsa, "time": self.time, "signature_hash_hex": self.signature_hash_hex,
                "token_signature_hex": self.token_signature_hex}

    @classmethod
    def from_dict(cls, d: dict) -> "TimestampToken":
        return cls(d["tsa"], int(d["time"]), d["signature_hash_hex"], d.get("token_signature_hex", ""))


class TimestampAuthority:
    def __init__(self, name: str, keypair: tuple[RSAPublicKey, RSAPrivateKey],
                 certificate: Certificate | None = None) -> None:
        self.name = name
        self.public_key, self._private_key = keypair
        self.certificate = certificate

    @classmethod
    def create(cls, name: str = "TSA ATBMTT", bits: int = 2048) -> "TimestampAuthority":
        return cls(name, generate_keypair(bits))

    def stamp(self, signature_bytes: bytes, at: int | None = None) -> TimestampToken:
        """Đóng dấu thời gian lên chữ ký. `at` chỉ để mô phỏng đồng hồ TSA trong kịch bản."""
        token = TimestampToken(self.name, now() if at is None else at, sha256(signature_bytes).hex())
        token.token_signature_hex = sign(token.tbs_bytes(), self._private_key).hex()
        return token


def verify_token(token: TimestampToken, signature_bytes: bytes, tsa_public_key: RSAPublicKey) -> bool:
    """Token hợp lệ khi gắn đúng chữ ký này (băm khớp) và chữ ký của TSA trên (SHA256(S) || t) đúng."""
    if not constant_time_eq(sha256(signature_bytes), from_hex(token.signature_hash_hex)):
        return False
    try:
        return verify(token.tbs_bytes(), from_hex(token.token_signature_hex), tsa_public_key)
    except ValueError:
        return False
