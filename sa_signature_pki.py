#!/usr/bin/env python3
"""Mô phỏng hệ chữ ký điện tử RSA trên PKI: kịch bản S5 (khóa bị lộ) và S6 (chứng thư hết hạn)."""
from __future__ import annotations

import argparse
import csv
import dataclasses
import hashlib
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
from cryptography.x509.oid import NameOID

UTC = timezone.utc
PUBLIC_EXPONENT = 65537
DEFAULT_KEY_BITS = 2048
ORGANIZATION = "Demo PKI"
CA_NAME = "Demo Root CA"
TSA_NAME = "Demo TSA"
SUBJECT_NAME = "Alice"

MSG_ORIGINAL = "Hợp đồng số 2026/HD-001: Alice đồng ý bán lô hàng A cho Bob, giá 100.000.000 VND.".encode("utf-8")
MSG_FORGED = "Lệnh chuyển khoản: Alice chuyển 500.000.000 VND cho Mallory.".encode("utf-8")


# --------------------------------------------------------------------------- #
# Tiện ích thời gian và định dạng
# --------------------------------------------------------------------------- #
def utc(year: int, month: int, day: int, hour: int = 0, minute: int = 0, second: int = 0) -> datetime:
    return datetime(year, month, day, hour, minute, second, tzinfo=UTC)


def fmt(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%d %H:%M UTC")


def hex_preview(value: int, full: bool = False) -> str:
    text = format(value, "x")
    if full or len(text) <= 40:
        return text
    return f"{text[:20]}...{text[-12:]}"


def verdict(accepted: bool) -> str:
    return "HỢP LỆ" if accepted else "TỪ CHỐI"


# --------------------------------------------------------------------------- #
# X.509 và CRL
# --------------------------------------------------------------------------- #
def _name(common_name: str) -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORGANIZATION),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])


def issue_certificate(
    subject: str,
    subject_key,
    issuer: str,
    issuer_key,
    not_before: datetime,
    not_after: datetime,
    serial: int,
    is_ca: bool = False,
) -> x509.Certificate:
    return (
        x509.CertificateBuilder()
        .subject_name(_name(subject))
        .issuer_name(_name(issuer))
        .public_key(subject_key)
        .serial_number(serial)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
        .sign(issuer_key, hashes.SHA256())
    )


def _as_utc(attribute: str, legacy: str, obj) -> datetime:
    aware = getattr(obj, attribute, None)
    return aware if aware is not None else getattr(obj, legacy).replace(tzinfo=UTC)


def not_before(cert: x509.Certificate) -> datetime:
    return _as_utc("not_valid_before_utc", "not_valid_before", cert)


def not_after(cert: x509.Certificate) -> datetime:
    return _as_utc("not_valid_after_utc", "not_valid_after", cert)


def revoked_at(entry: x509.RevokedCertificate) -> datetime:
    return _as_utc("revocation_date_utc", "revocation_date", entry)


def is_issued_by(cert: x509.Certificate, ca_cert: x509.Certificate) -> bool:
    try:
        ca_cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
    except InvalidSignature:
        return False
    return cert.issuer == ca_cert.subject


def build_crl(
    ca_cert: x509.Certificate,
    ca_key,
    revoked: list[tuple[int, datetime]],
    this_update: datetime,
    next_update: datetime,
) -> x509.CertificateRevocationList:
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(this_update)
        .next_update(next_update)
    )
    for serial, when in revoked:
        entry = (
            x509.RevokedCertificateBuilder()
            .serial_number(serial)
            .revocation_date(when)
            .add_extension(x509.CRLReason(x509.ReasonFlags.key_compromise), critical=False)
            .build()
        )
        builder = builder.add_revoked_certificate(entry)
    return builder.sign(ca_key, hashes.SHA256())


# --------------------------------------------------------------------------- #
# Dấu thời gian
# --------------------------------------------------------------------------- #
@dataclass
class TimestampToken:
    serial: int
    gen_time: datetime
    imprint: bytes
    tsa_cert: x509.Certificate
    signature: bytes = b""

    def to_be_signed(self) -> bytes:
        return f"TST|{self.serial}|{self.gen_time.isoformat()}|{self.imprint.hex()}".encode()


class TimestampAuthority:
    def __init__(self, key, cert: x509.Certificate) -> None:
        self._key = key
        self.cert = cert
        self._counter = 0

    def issue(self, signature: bytes, at: datetime) -> TimestampToken:
        self._counter += 1
        token = TimestampToken(self._counter, at, hashlib.sha256(signature).digest(), self.cert)
        token.signature = self._key.sign(token.to_be_signed(), padding.PKCS1v15(), hashes.SHA256())
        return token


def validate_token(token: TimestampToken, signature: bytes, ca_cert: x509.Certificate) -> tuple[bool, str]:
    if token.imprint != hashlib.sha256(signature).digest():
        return False, "imprint không khớp chữ ký"
    if not is_issued_by(token.tsa_cert, ca_cert):
        return False, "chứng thư TSA không do CA tin cậy cấp"
    if not (not_before(token.tsa_cert) <= token.gen_time <= not_after(token.tsa_cert)):
        return False, "chứng thư TSA không hiệu lực tại genTime"
    try:
        token.tsa_cert.public_key().verify(
            token.signature, token.to_be_signed(), padding.PKCS1v15(), hashes.SHA256()
        )
    except InvalidSignature:
        return False, "chữ ký TSA sai (token bị sửa hoặc giả mạo)"
    return True, ""


# --------------------------------------------------------------------------- #
# Ký số
# --------------------------------------------------------------------------- #
@dataclass
class SignedPackage:
    message: bytes
    claimed_time: datetime
    signature: bytes
    cert: x509.Certificate
    timestamp: Optional[TimestampToken] = None


def signing_digest(message: bytes, claimed_time: datetime) -> bytes:
    return hashlib.sha256(message + b"|signingTime=" + claimed_time.isoformat().encode()).digest()


def sign(key, cert: x509.Certificate, message: bytes, claimed_time: datetime) -> SignedPackage:
    digest = signing_digest(message, claimed_time)
    signature = key.sign(digest, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))
    return SignedPackage(message, claimed_time, signature, cert)


# --------------------------------------------------------------------------- #
# Xác minh
# --------------------------------------------------------------------------- #
class Mode(str, Enum):
    VERIFY_TIME = "VERIFY_TIME"
    CLAIMED = "CLAIMED"
    TSA = "TSA"


@dataclass(frozen=True)
class Outcome:
    accepted: bool
    reason: str
    effective_time: Optional[datetime] = None


def verify(
    package: SignedPackage,
    ca_cert: x509.Certificate,
    crl: x509.CertificateRevocationList,
    verification_time: datetime,
    mode: Mode,
) -> Outcome:
    cert = package.cert

    if not is_issued_by(cert, ca_cert):
        return Outcome(False, "Chứng thư không do CA tin cậy ký")

    digest = signing_digest(package.message, package.claimed_time)
    try:
        cert.public_key().verify(
            package.signature, digest, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256())
        )
    except InvalidSignature:
        return Outcome(False, "Chữ ký RSA không khớp H(M) (nội dung hoặc signingTime bị sửa)")

    if mode is Mode.VERIFY_TIME:
        moment, source = verification_time, "thời điểm kiểm tra"
    elif mode is Mode.CLAIMED:
        moment, source = package.claimed_time, "signingTime tự khai"
    else:
        if package.timestamp is None:
            return Outcome(False, "Không có dấu thời gian TSA -> không chứng minh được thời điểm ký")
        valid, detail = validate_token(package.timestamp, package.signature, ca_cert)
        if not valid:
            return Outcome(False, f"Dấu thời gian không hợp lệ: {detail}")
        moment, source = package.timestamp.gen_time, "dấu thời gian TSA"

    valid_from, valid_to = not_before(cert), not_after(cert)
    if moment < valid_from:
        return Outcome(False, f"Chứng thư chưa có hiệu lực tại t={fmt(moment)} ({source})", moment)
    if moment > valid_to:
        return Outcome(
            False,
            f"Chứng thư đã hết hạn tại t={fmt(moment)} ({source}); notAfter={fmt(valid_to)}",
            moment,
        )

    if not crl.is_signature_valid(ca_cert.public_key()):
        return Outcome(False, "CRL không hợp lệ (chữ ký CA sai)", moment)
    entry = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
    if entry is not None and moment >= revoked_at(entry):
        return Outcome(
            False,
            f"Chứng thư đã bị thu hồi (keyCompromise) lúc {fmt(revoked_at(entry))}; "
            f"t={fmt(moment)} ({source}) >= t_r",
            moment,
        )

    return Outcome(
        True,
        f"Hợp lệ: chữ ký đúng, t={fmt(moment)} ({source}) nằm trong hiệu lực và chưa thu hồi",
        moment,
    )


# --------------------------------------------------------------------------- #
# Hạ tầng PKI mô phỏng
# --------------------------------------------------------------------------- #
@dataclass
class PKI:
    ca_key: object
    ca_cert: x509.Certificate
    tsa: TimestampAuthority
    subject_key: object
    cert_long_lived: x509.Certificate
    cert_short_lived: x509.Certificate


def build_pki(key_bits: int) -> PKI:
    def new_key():
        return rsa.generate_private_key(public_exponent=PUBLIC_EXPONENT, key_size=key_bits)

    ca_key, tsa_key, subject_key = new_key(), new_key(), new_key()
    ca_cert = issue_certificate(
        CA_NAME, ca_key.public_key(), CA_NAME, ca_key,
        utc(2025, 1, 1), utc(2035, 1, 1), 1, is_ca=True,
    )
    tsa_cert = issue_certificate(
        TSA_NAME, tsa_key.public_key(), CA_NAME, ca_key,
        utc(2025, 6, 1), utc(2032, 6, 1), 2,
    )
    long_lived = issue_certificate(
        SUBJECT_NAME, subject_key.public_key(), CA_NAME, ca_key,
        utc(2026, 1, 1), utc(2027, 1, 1), 1001,
    )
    short_lived = issue_certificate(
        SUBJECT_NAME, subject_key.public_key(), CA_NAME, ca_key,
        utc(2026, 1, 1), utc(2026, 6, 30, 23, 59, 59), 1002,
    )
    return PKI(ca_key, ca_cert, TimestampAuthority(tsa_key, tsa_cert), subject_key, long_lived, short_lived)


# --------------------------------------------------------------------------- #
# Kịch bản
# --------------------------------------------------------------------------- #
@dataclass
class TestCase:
    case_id: str
    title: str
    package: SignedPackage
    verification_time: datetime
    expected: bool
    rationale: str


@dataclass
class Scenario:
    title: str
    timeline: list[tuple[str, datetime, str]]
    cert: x509.Certificate
    crl: x509.CertificateRevocationList
    cases: list[TestCase]
    conclusions: list[str]


def scenario_s5(pki: PKI) -> Scenario:
    key, cert, tsa = pki.subject_key, pki.cert_long_lived, pki.tsa
    t_sign = utc(2026, 3, 10, 9)
    t_compromise = utc(2026, 4, 1, 8)
    t_forge_before = utc(2026, 4, 5, 14)
    t_revoke = utc(2026, 4, 10)
    t_forge_after = utc(2026, 5, 1, 20)
    t_verify = utc(2026, 6, 1, 9)
    backdated = utc(2026, 3, 20, 10)

    crl = build_crl(pki.ca_cert, pki.ca_key, [(cert.serial_number, t_revoke)], t_revoke, utc(2026, 12, 31))

    timeline = [
        ("t_s", t_sign, "Alice ký hợp đồng thật"),
        ("t_c", t_compromise, "Khóa bí mật d của Alice bị lộ"),
        ("t_f1", t_forge_before, "Mallory ký giả (trước khi CA thu hồi)"),
        ("t_r", t_revoke, "CA thu hồi chứng thư (CRL, keyCompromise)"),
        ("t_f2", t_forge_after, f"Mallory ký giả, khai signingTime lùi về {fmt(backdated)}"),
        ("t_v", t_verify, "Bob kiểm tra chữ ký"),
    ]

    cases: list[TestCase] = []

    pkg = sign(key, cert, MSG_ORIGINAL, t_sign)
    pkg.timestamp = tsa.issue(pkg.signature, t_sign)
    cases.append(TestCase(
        "S5.1", "Ký thật trước khi lộ, có dấu thời gian", pkg, t_verify, True,
        "TSA chứng minh ký trước t_r nên chữ ký vẫn hợp lệ dù chứng thư sau đó bị thu hồi",
    ))

    pkg = sign(key, cert, MSG_ORIGINAL, t_sign)
    cases.append(TestCase(
        "S5.2", "Ký thật trước khi lộ, không dấu thời gian", pkg, t_verify, False,
        "Không có TSA thì chữ ký thật cũng không chứng minh được thời điểm ký",
    ))

    pkg = sign(key, cert, MSG_FORGED, backdated)
    cases.append(TestCase(
        "S5.3", "Ký lùi ngày sau thu hồi, không dấu thời gian", pkg, t_verify, False,
        "Chế độ CLAIMED chấp nhận signingTime tự khai: giới hạn của PKI khi thiếu dấu thời gian",
    ))

    pkg = sign(key, cert, MSG_FORGED, backdated)
    pkg.timestamp = tsa.issue(pkg.signature, t_forge_after)
    cases.append(TestCase(
        "S5.4", "Ký lùi ngày, xin TSA thật sau thu hồi", pkg, t_verify, False,
        "TSA ghi thời điểm sau t_r nên bị từ chối; dấu thời gian chặn được ký lùi ngày",
    ))

    pkg = sign(key, cert, MSG_FORGED, backdated)
    genuine = tsa.issue(pkg.signature, t_forge_after)
    pkg.timestamp = dataclasses.replace(genuine, gen_time=backdated)
    cases.append(TestCase(
        "S5.5", "Ký lùi ngày, giả mạo token TSA", pkg, t_verify, False,
        "Kẻ tấn công không có khóa TSA nên chữ ký trên token không hợp lệ",
    ))

    pkg = sign(key, cert, MSG_FORGED, t_forge_before)
    pkg.timestamp = tsa.issue(pkg.signature, t_forge_before)
    cases.append(TestCase(
        "S5.6", "Ký giả trong khoảng t_c đến t_r, có TSA thật", pkg, t_verify, True,
        "CA chưa biết khóa bị lộ nên PKI không phân biệt được: giới hạn cố hữu của PKI",
    ))

    conclusions = [
        "- Dấu thời gian là cơ chế chặn được ký lùi ngày (S5.3, S5.4, S5.5).",
        "- Không có TSA, sau thu hồi không thể phân biệt chữ ký thật (S5.2) với chữ ký giả lùi ngày (S5.3).",
        "- Chữ ký giả trong khoảng t_c đến t_r (S5.6) vẫn hợp lệ vì CA chưa biết khóa bị lộ.",
        "  Giảm thiểu: thu hồi nhanh, CRL/OCSP cập nhật thường xuyên, bảo vệ khóa bằng HSM hoặc token.",
    ]
    return Scenario("S5 - KHÓA BỊ LỘ", timeline, cert, crl, cases, conclusions)


def scenario_s6(pki: PKI) -> Scenario:
    key, cert, tsa = pki.subject_key, pki.cert_short_lived, pki.tsa
    t_sign = utc(2026, 6, 20, 10)
    t_verify_before = utc(2026, 6, 25, 9)
    t_late = utc(2026, 8, 1, 10)
    t_verify_after = utc(2026, 9, 1, 9)
    backdated = utc(2026, 6, 15, 10)

    crl = build_crl(pki.ca_cert, pki.ca_key, [], utc(2026, 6, 1), utc(2027, 1, 1))

    timeline = [
        ("notBefore", not_before(cert), "Chứng thư bắt đầu có hiệu lực"),
        ("t_sign", t_sign, "Alice ký khi chứng thư còn hạn"),
        ("t_v1", t_verify_before, "Kiểm tra trước khi hết hạn"),
        ("notAfter", not_after(cert), "Chứng thư hết hạn"),
        ("t_late", t_late, "Chữ ký tạo sau khi hết hạn"),
        ("t_v2", t_verify_after, "Kiểm tra sau khi hết hạn"),
    ]

    cases: list[TestCase] = []

    pkg = sign(key, cert, MSG_ORIGINAL, t_sign)
    pkg.timestamp = tsa.issue(pkg.signature, t_sign)
    cases.append(TestCase(
        "S6.1", "Ký trước hết hạn, kiểm tra trước hết hạn", pkg, t_verify_before, True,
        "Cả ba chế độ đều chấp nhận",
    ))

    pkg = sign(key, cert, MSG_ORIGINAL, t_sign)
    pkg.timestamp = tsa.issue(pkg.signature, t_sign)
    cases.append(TestCase(
        "S6.2", "Ký trước hết hạn có TSA, kiểm tra sau hết hạn", pkg, t_verify_after, True,
        "TSA chứng minh ký khi còn hạn nên hợp lệ lâu dài; chế độ VERIFY_TIME từ chối oan",
    ))

    pkg = sign(key, cert, MSG_ORIGINAL, t_sign)
    cases.append(TestCase(
        "S6.3", "Ký trước hết hạn không TSA, kiểm tra sau hết hạn", pkg, t_verify_after, False,
        "Không có bằng chứng thời điểm ký nên không thể xác nhận",
    ))

    pkg = sign(key, cert, MSG_FORGED, t_late)
    pkg.timestamp = tsa.issue(pkg.signature, t_late)
    cases.append(TestCase(
        "S6.4", "Ký sau hết hạn (khai đúng), có TSA", pkg, t_verify_after, False,
        "signingTime và TSA đều sau notAfter",
    ))

    pkg = sign(key, cert, MSG_FORGED, backdated)
    cases.append(TestCase(
        "S6.5", "Ký sau hết hạn, lùi signingTime, không TSA", pkg, t_verify_after, False,
        "Chế độ CLAIMED bị đánh lừa; cần TSA bắt buộc để chặn",
    ))

    pkg = sign(key, cert, MSG_FORGED, backdated)
    pkg.timestamp = tsa.issue(pkg.signature, t_late)
    cases.append(TestCase(
        "S6.6", "Ký sau hết hạn, lùi signingTime, xin TSA thật", pkg, t_verify_after, False,
        "TSA ghi thời điểm sau notAfter nên bị từ chối, bất kể signingTime tự khai",
    ))

    conclusions = [
        "- Chữ ký tạo sau notAfter bị từ chối (S6.4, S6.5, S6.6).",
        "- Chữ ký tạo lúc còn hạn vẫn kiểm chứng được sau khi hết hạn nếu có TSA (S6.2); không có TSA thì không (S6.3).",
        "- Tin signingTime tự khai cho phép ký sau hết hạn bằng cách lùi ngày (S6.5).",
        "  Tính không chối bỏ dài hạn đòi hỏi dấu thời gian và lưu trữ bằng chứng kiểm chứng dài hạn (LTV).",
    ]
    return Scenario("S6 - CHỨNG THƯ HẾT HẠN", timeline, cert, crl, cases, conclusions)


# --------------------------------------------------------------------------- #
# Báo cáo
# --------------------------------------------------------------------------- #
def print_inputs(pki: PKI, scenario: Scenario, full: bool) -> None:
    private = pki.subject_key.private_numbers()
    public = private.public_numbers
    digest = hashlib.sha256(MSG_ORIGINAL).hexdigest()

    print("  [Dữ liệu đầu vào]")
    print(f"  Khóa RSA của Alice: {public.n.bit_length()} bit")
    print(f"    n = {hex_preview(public.n, full)}")
    print(f"    e = {public.e}")
    print(f"    d = {hex_preview(private.d, full)}")
    print(f"    p = {hex_preview(private.p, full)}")
    print(f"    q = {hex_preview(private.q, full)}")
    print("  Hàm băm / padding: SHA-256 / PKCS#1 v1.5, ký trên H(M || signingTime)")
    print(f"  H(M gốc) = {digest if full else digest[:32] + '...'}")
    print(f"  Chứng thư: serial={scenario.cert.serial_number}  Issuer={CA_NAME}")
    print(f"    notBefore = {fmt(not_before(scenario.cert))}   notAfter = {fmt(not_after(scenario.cert))}")
    entries = [(entry.serial_number, revoked_at(entry)) for entry in scenario.crl]
    if entries:
        for serial, when in entries:
            print(f"  CRL: serial {serial} bị thu hồi lúc {fmt(when)} (keyCompromise)")
    else:
        print("  CRL: không có chứng thư bị thu hồi")
    print("  Mốc thời gian:")
    for label, moment, description in scenario.timeline:
        print(f"    {label:<9} {fmt(moment)}  {description}")
    print()


def run_scenario(pki: PKI, scenario: Scenario, full: bool, writer: Optional[csv.writer]) -> bool:
    rule = "=" * 100
    print(rule)
    print(f"  {scenario.title}")
    print(rule)
    print_inputs(pki, scenario, full)

    results = {
        case.case_id: {
            mode: verify(case.package, pki.ca_cert, scenario.crl, case.verification_time, mode)
            for mode in Mode
        }
        for case in scenario.cases
    }

    if writer is not None:
        for case in scenario.cases:
            for mode, outcome in results[case.case_id].items():
                writer.writerow([
                    scenario.title.split()[0], case.case_id, case.title,
                    fmt(case.verification_time), mode.value, verdict(outcome.accepted), outcome.reason,
                ])

    header = (
        f"  {'Mã':<6}{'Test case':<54}{'VERIFY_TIME':<13}{'CLAIMED':<10}"
        f"{'TSA':<10}{'Kỳ vọng':<10}{'Khớp'}"
    )
    print("  [Bảng kết quả]")
    print(header)
    print("  " + "-" * (len(header) - 2))

    all_match = True
    for case in scenario.cases:
        by_mode = results[case.case_id]
        match = by_mode[Mode.TSA].accepted == case.expected
        all_match &= match
        print(
            f"  {case.case_id:<6}{case.title:<54}"
            f"{verdict(by_mode[Mode.VERIFY_TIME].accepted):<13}"
            f"{verdict(by_mode[Mode.CLAIMED].accepted):<10}"
            f"{verdict(by_mode[Mode.TSA].accepted):<10}"
            f"{verdict(case.expected):<10}{'OK' if match else 'SAI'}"
        )
    print()

    print("  [Chi tiết]")
    for case in scenario.cases:
        print(f"  {case.case_id}: {case.title}  (kiểm tra lúc {fmt(case.verification_time)})")
        print(f"      {case.rationale}")
        for mode in Mode:
            outcome = results[case.case_id][mode]
            print(f"      {mode.value:<12}{verdict(outcome.accepted):<9}{outcome.reason}")
        print()

    print("  [Kết luận]")
    for line in scenario.conclusions:
        print(f"  {line}")
    print()
    return all_match


# --------------------------------------------------------------------------- #
# Điểm vào
# --------------------------------------------------------------------------- #
def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Mô phỏng chữ ký điện tử RSA: kịch bản S5 và S6")
    parser.add_argument("--scenario", choices=["s5", "s6", "all"], default="all")
    parser.add_argument("--bits", type=int, default=DEFAULT_KEY_BITS, help="độ dài khóa RSA")
    parser.add_argument("--csv", help="đường dẫn file CSV xuất kết quả")
    parser.add_argument("--full", action="store_true", help="in đầy đủ n, d, p, q và H(M)")
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    print(f"Đang sinh khóa RSA-{args.bits} cho CA, TSA và Alice ...\n")
    pki = build_pki(args.bits)

    handle = open(args.csv, "w", newline="", encoding="utf-8-sig") if args.csv else None
    writer = csv.writer(handle) if handle else None
    if writer is not None:
        writer.writerow(["Kịch bản", "Mã", "Test case", "Thời điểm kiểm tra", "Chế độ", "Kết quả", "Lý do"])

    builders = {"s5": scenario_s5, "s6": scenario_s6}
    selected = list(builders) if args.scenario == "all" else [args.scenario]

    try:
        all_match = True
        for name in selected:
            all_match &= run_scenario(pki, builders[name](pki), args.full, writer)
    finally:
        if handle is not None:
            handle.close()

    if args.csv:
        print(f"Đã ghi kết quả ra {args.csv}")
    print("Kết quả chế độ TSA khớp kỳ vọng ở mọi test case" if all_match else "Có test case không khớp kỳ vọng")
    return 0 if all_match else 1


if __name__ == "__main__":
    sys.exit(main())
