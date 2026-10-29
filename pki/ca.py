"""Tổ chức chứng thực (CA): tự ký chứng chỉ gốc, cấp chứng chỉ, thu hồi và công bố CRL."""
from __future__ import annotations

import secrets

from core.rsa_keygen import RSAPrivateKey, RSAPublicKey, generate_keypair
from core.signature import sign
from pki.certificate import DAY, Certificate, now
from pki.revocation import CRL


class CertificateAuthority:
    def __init__(self, name: str, keypair: tuple[RSAPublicKey, RSAPrivateKey],
                 certificate: Certificate | None = None) -> None:
        self.name = name
        self.public_key, self._private_key = keypair
        self.certificate = certificate
        self.revoked: dict[int, int] = {}

    @classmethod
    def create(cls, name: str, bits: int = 2048) -> "CertificateAuthority":
        """Sinh khoá cho CA mới (chưa có chứng chỉ; gọi self_signed_root() hoặc để CA cấp trên cấp)."""
        return cls(name, generate_keypair(bits))

    def _sign_certificate(self, cert: Certificate) -> Certificate:
        cert.signature_hex = sign(cert.tbs_bytes(), self._private_key).hex()
        return cert

    def self_signed_root(self, days: int = 3650, not_before: int | None = None) -> Certificate:
        """Chứng chỉ gốc: CA tự ký cho chính mình (subject = issuer, is_ca = True)."""
        start = now() if not_before is None else not_before
        cert = Certificate(secrets.randbits(63), self.name, self.name, self.public_key, start, start + days * DAY, True)
        self.certificate = self._sign_certificate(cert)
        return self.certificate

    def issue(self, subject: str, public_key: RSAPublicKey, days: int = 365, is_ca: bool = False,
              not_before: int | None = None) -> Certificate:
        """Cấp chứng chỉ: gắn `subject` với `public_key`, ký phần TBS bằng khoá riêng của CA."""
        start = now() if not_before is None else not_before
        cert = Certificate(secrets.randbits(63), subject, self.name, public_key, start, start + days * DAY, is_ca)
        return self._sign_certificate(cert)

    def create_intermediate(self, name: str, bits: int = 2048, days: int = 1825,
                            not_before: int | None = None) -> "CertificateAuthority":
        """Tạo CA trung gian có chứng chỉ (is_ca = True) do CA này cấp."""
        sub = CertificateAuthority.create(name, bits)
        sub.certificate = self.issue(name, sub.public_key, days, is_ca=True, not_before=not_before)
        return sub

    def revoke(self, serial: int, at: int | None = None) -> None:
        """Thu hồi chứng chỉ kể từ thời điểm `at` (mặc định: bây giờ)."""
        self.revoked[serial] = now() if at is None else at

    def publish_crl(self, at: int | None = None) -> CRL:
        """Công bố CRL có chữ ký của CA."""
        return CRL.create(self.name, self.revoked, self._private_key, at)
