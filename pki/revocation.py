from __future__ import annotations

from dataclasses import dataclass, field

from core.rsa_keygen import RSAPrivateKey, RSAPublicKey
from core.signature import sign, verify
from core.utils import canonical_json, from_hex
from pki.certificate import now


@dataclass
class CRL:
    issuer: str
    revoked: dict[int, int] = field(default_factory=dict)       # serial -> thời điểm thu hồi
    this_update: int = 0
    signature_hex: str = ""

    def tbs_bytes(self) -> bytes:
        return canonical_json({"issuer": self.issuer, "this_update": self.this_update,
                               "revoked": {str(k): v for k, v in sorted(self.revoked.items())}})

    @classmethod
    def create(cls, issuer: str, revoked: dict[int, int], priv: RSAPrivateKey, this_update: int | None = None) -> "CRL":
        crl = cls(issuer, dict(revoked), now() if this_update is None else this_update)
        crl.signature_hex = sign(crl.tbs_bytes(), priv).hex()
        return crl

    def verify_signature(self, issuer_pub: RSAPublicKey) -> bool:
        try:
            return verify(self.tbs_bytes(), from_hex(self.signature_hex), issuer_pub)
        except ValueError:
            return False

    def revoked_at(self, serial: int) -> int | None:
        return self.revoked.get(serial)

    def is_revoked(self, serial: int, at_time: int) -> bool:
        t = self.revoked.get(serial)
        return t is not None and at_time >= t

    def to_dict(self) -> dict:
        return {"issuer": self.issuer, "this_update": self.this_update,
                "revoked": {str(k): v for k, v in self.revoked.items()}, "signature_hex": self.signature_hex}

    @classmethod
    def from_dict(cls, d: dict) -> "CRL":
        return cls(d["issuer"], {int(k): int(v) for k, v in d["revoked"].items()}, int(d["this_update"]),
                   d.get("signature_hex", ""))
