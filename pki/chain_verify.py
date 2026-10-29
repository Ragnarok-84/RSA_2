from __future__ import annotations

from typing import Iterable

from core.signature import VerifyResult, verify
from core.utils import from_hex
from pki.certificate import Certificate, fmt_time, now
from pki.revocation import CRL

MAX_DEPTH = 8


def signed_by(cert: Certificate, issuer: Certificate) -> bool:
    try:
        return verify(cert.tbs_bytes(), from_hex(cert.signature_hex), issuer.public_key)
    except ValueError:
        return False


def _same(a: Certificate, b: Certificate) -> bool:
    return a.to_dict() == b.to_dict()


def verify_chain(leaf: Certificate, intermediates: Iterable[Certificate], trusted_roots: Iterable[Certificate],
                 crl: CRL | Iterable[CRL] | None = None, at_time: int | None = None) -> VerifyResult:
    at = now() if at_time is None else at_time
    roots = list(trusted_roots)
    pool = list(intermediates) + roots
    crls = [] if crl is None else ([crl] if isinstance(crl, CRL) else list(crl))
    crl_by_issuer = {c.issuer: c for c in crls}

    path = [leaf.subject]
    cur = leaf
    for _ in range(MAX_DEPTH):
        if not cur.valid_at(at):
            when = "chưa có hiệu lực" if at < cur.not_before else "đã hết hạn"
            return VerifyResult(False, f"chứng chỉ của '{cur.subject}' {when} tại {fmt_time(at)}")

        if any(_same(cur, r) for r in roots):
            if not signed_by(cur, cur):
                return VerifyResult(False, f"chữ ký tự ký của root '{cur.subject}' không hợp lệ")
            return VerifyResult(True, "chuỗi chứng chỉ hợp lệ: " + " → ".join(path))

        if cur.is_self_signed:
            return VerifyResult(False, f"'{cur.subject}' tự ký nhưng không nằm trong danh sách root tin cậy")

        candidates = [c for c in pool if c.subject == cur.issuer]
        if not candidates:
            return VerifyResult(False, f"không tìm thấy chứng chỉ của bên cấp '{cur.issuer}'")
        issuer = next((c for c in candidates if signed_by(cur, c)), None)
        if issuer is None:
            return VerifyResult(False, f"chữ ký của '{cur.issuer}' trên chứng chỉ '{cur.subject}' không hợp lệ "
                                       "(chứng chỉ bị sửa hoặc do CA giả cấp)")
        if not issuer.is_ca:
            return VerifyResult(False, f"'{issuer.subject}' không phải CA (is_ca = False) nên không được cấp chứng chỉ")

        issuer_crl = crl_by_issuer.get(issuer.subject)
        if issuer_crl is not None:
            if not issuer_crl.verify_signature(issuer.public_key):
                return VerifyResult(False, f"CRL của '{issuer.subject}' có chữ ký không hợp lệ (bị sửa)")
            if issuer_crl.is_revoked(cur.serial, at):
                t_r = issuer_crl.revoked_at(cur.serial)
                return VerifyResult(False, f"chứng chỉ của '{cur.subject}' đã bị thu hồi từ {fmt_time(t_r)}")

        path.append(issuer.subject)
        cur = issuer
    return VerifyResult(False, "chuỗi chứng chỉ quá dài")
