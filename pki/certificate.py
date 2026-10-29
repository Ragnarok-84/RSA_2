from __future__ import annotations

import time
from dataclasses import dataclass

from core.hash.sha256 import sha256
from core.key_io import public_key_from_dict, public_key_to_dict
from core.rsa_keygen import RSAPublicKey
from core.utils import canonical_json

DAY = 24 * 3600


def now() -> int:
    return int(time.time())


def fmt_time(t: int) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t))


@dataclass
class Certificate:
    serial: int
    subject: str
    issuer: str
    public_key: RSAPublicKey
    not_before: int
    not_after: int
    is_ca: bool = False
    signature_hex: str = ""

    def tbs_dict(self) -> dict:
        pk = public_key_to_dict(self.public_key)
        return {
            "serial": self.serial,
            "subject": self.subject,
            "issuer": self.issuer,
            "public_key": {"n": pk["n"], "e": pk["e"]},
            "not_before": self.not_before,
            "not_after": self.not_after,
            "is_ca": self.is_ca,
        }

    def tbs_bytes(self) -> bytes:
        return canonical_json(self.tbs_dict())

    def to_dict(self) -> dict:
        return {**self.tbs_dict(), "signature_hex": self.signature_hex}

    @classmethod
    def from_dict(cls, d: dict) -> "Certificate":
        return cls(serial=int(d["serial"]), subject=d["subject"], issuer=d["issuer"],
                   public_key=public_key_from_dict(d["public_key"]), not_before=int(d["not_before"]),
                   not_after=int(d["not_after"]), is_ca=bool(d.get("is_ca", False)),
                   signature_hex=d.get("signature_hex", ""))

    @property
    def is_self_signed(self) -> bool:
        return self.subject == self.issuer

    def valid_at(self, t: int) -> bool:
        return self.not_before <= t <= self.not_after

    def fingerprint(self) -> str:
        return sha256(canonical_json(self.to_dict())).hex()[:16]

    def describe(self) -> str:
        return "\n".join((
            f"Số serial      : {self.serial}",
            f"Chủ thể        : {self.subject}",
            f"Bên cấp        : {self.issuer}",
            f"Hiệu lực       : {fmt_time(self.not_before)} → {fmt_time(self.not_after)}",
            f"Là CA          : {'có' if self.is_ca else 'không'}",
            f"Khoá công khai : e = {self.public_key.e}, n = {self.public_key.n.bit_length()} bit "
            f"(0x{format(self.public_key.n, 'x')[:24]}…)",
            f"Chữ ký của CA  : {self.signature_hex[:32]}…",
            f"Dấu vân tay    : {self.fingerprint()}",
        ))
