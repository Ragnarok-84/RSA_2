"""Bảng đối chiếu kết quả (ca, ours, reference, nguồn, khớp) cho GUI, CLI và báo cáo.

Các file test/required/test_r*.py gọi các hàm check_*() ở đây rồi `assert row.match`, nên dữ liệu và logic
kiểm tra chỉ viết một lần. Đây là nơi (cùng test/) được phép dùng hashlib, cryptography và pow built-in để đối chiếu.

    python -m test.report                       # in bảng ra console
    python -m test.report --out docs/report/test_results.md [--slow]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from core import signature as sg
from core.hash.sha256 import sha256
from core.number_theory import crt, egcd, mod_inverse, mod_pow
from core.padding import pkcs1_v15
from core.rsa_keygen import RSAPrivateKey, RSAPublicKey, generate_keypair, keypair_from_primes
from core.tiny_rsa import TinyRSA


ROOT = Path(__file__).resolve().parents[1]
VECTORS = Path(__file__).resolve().parent / "vectors"

SIGNATURE_CASES = (
    "PKCS#1: thông điệp rỗng",
    "PKCS#1: văn bản tiếng Việt UTF-8",
    "PKCS#1: tệp ảnh nhị phân logo.png",
    "PSS: thông điệp rỗng",
    "PSS: văn bản tiếng Việt UTF-8",
    "PSS: tệp ảnh nhị phân logo.png",
    "Sửa 1 bít thông điệp → từ chối",
    "Sửa 1 bít chữ ký → từ chối",
    "Dùng sai khoá công khai → từ chối",
    "PSS: sửa 1 bít thông điệp → từ chối",
    "Ký CRT = ký không CRT",
)


@dataclass
class CheckRow:
    group: str
    case: str
    ours: str
    reference: str
    source: str
    match: bool


def _short(v: object, width: int = 20) -> str:
    s = v.hex() if isinstance(v, bytes) else str(v)
    return s if len(s) <= width else s[:width - 1] + "…"


def _row(group: str, case: str, ours: object, reference: object, source: str) -> CheckRow:
    return CheckRow(group, case, _short(ours), _short(reference), source, ours == reference)


@lru_cache(maxsize=None)
def shared_keypair(bits: int = 2048, slot: int = 0) -> tuple[RSAPublicKey, RSAPrivateKey]:
    """Khoá sinh một lần mỗi phiên (dùng chung cho report, conftest và GUI); `slot` khác cho khoá khác."""
    return generate_keypair(bits)


def sample_image() -> bytes:
    path = ROOT / "sample" / "images" / "logo.png"
    return path.read_bytes() if path.is_file() else bytes(range(256)) * 400


# ---- 1. Ví dụ tính tay trong slide ----------------------------------------------------------------------
def check_tiny_slide() -> list[CheckRow]:
    g, src = "Tiny / Slide", "Slide"
    pub, priv = keypair_from_primes(17, 11, 7)
    tiny = TinyRSA(17, 11, 7)
    s = tiny.sign(88)
    return [
        _row(g, "egcd(4864, 3458)", egcd(4864, 3458), (38, 32, -45), src),
        _row(g, "mod_inverse(25, 101)", mod_inverse(25, 101), 97, src),
        _row(g, "mod_inverse(173, 1024)", mod_inverse(173, 1024), 805, src),
        _row(g, "mod_pow(7, 560, 561)", mod_pow(7, 560, 561), 1, src),
        _row(g, "mod_pow(88, 7, 187) (mã hoá slide RSA)", mod_pow(88, 7, 187), 11, src),
        _row(g, "mod_pow(11, 23, 187)", mod_pow(11, 23, 187), 88, src),
        _row(g, "crt([5, 6], [7, 11])", crt([5, 6], [7, 11]), 61, src),
        _row(g, "mod_pow(17, 8, 77)", mod_pow(17, 8, 77), 37, src),
        _row(g, "keypair_from_primes(17, 11, 7): n, φ, d", (pub.n, (17 - 1) * (11 - 1), priv.d), (187, 160, 23), src),
        _row(g, "Tiny: ký h = 88 (p=17, q=11, e=7)", f"s = {s}", "s = 11", src),
        _row(g, "Tiny: kiểm tra 11^7 mod 187 = 88", tiny.verify(88, s), True, src),
        _row(g, "mod_pow ngẫu nhiên 2048 bít vs pow()", *_pow_pair(), "Python pow"),
    ]


def _pow_pair() -> tuple[int, int]:
    a, b, n = (int.from_bytes(os.urandom(256), "big") | 1 for _ in range(3))
    return mod_pow(a, b, n), pow(a, b, n)


# ---- 2. SHA-256 -----------------------------------------------------------------------------------------
def load_sha256_vectors() -> dict:
    return json.loads((VECTORS / "sha256_nist.json").read_bytes().decode("utf-8"))


def check_sha256_nist(include_slow: bool = False) -> list[CheckRow]:
    data = load_sha256_vectors()
    rows = [_row("SHA-256", v["name"], sha256(v["input_utf8"].encode()).hex(), v["digest"], "NIST FIPS 180-4")
            for v in data["vectors"]]
    for n in (55, 56, 63, 64, 65, 1000):
        msg = os.urandom(n)
        rows.append(_row("SHA-256", f"Ngẫu nhiên {n} byte (biên khối)", sha256(msg).hex(),
                         hashlib.sha256(msg).hexdigest(), "hashlib"))
    if include_slow:
        m = data["million_a"]
        rows.append(_row("SHA-256", m["name"], sha256(m["repeat"].encode() * m["count"]).hex(), m["digest"],
                         "NIST FIPS 180-4"))
    return rows


# ---- 3. Ca tự viết --------------------------------------------------------------------------------------
def check_signature_cases(pub: RSAPublicKey, priv: RSAPrivateKey,
                          wrong_pub: RSAPublicKey | None = None) -> list[CheckRow]:
    g, src = "Chữ ký (tự viết)", "Tự viết"
    vi = "Hợp đồng mua bán: Bên A giao 100 máy tính, tổng 2 tỷ đồng. Chữ ký số RSA – ổn định, đúng chuẩn.".encode()
    img = sample_image()
    wrong_pub = wrong_pub or shared_keypair(pub.n.bit_length(), slot=1)[0]
    sig_vi = sg.sign(vi, priv)
    flipped_msg = bytearray(vi)
    flipped_msg[0] ^= 0x01
    flipped_sig = bytearray(sig_vi)
    flipped_sig[len(flipped_sig) // 2] ^= 0x80
    pss_vi = sg.sign(vi, priv, "pss")
    results = [
        sg.verify(b"", sg.sign(b"", priv), pub),
        sg.verify(vi, sig_vi, pub),
        sg.verify(img, sg.sign(img, priv), pub),
        sg.verify(b"", sg.sign(b"", priv, "pss"), pub, "pss"),
        sg.verify(vi, pss_vi, pub, "pss"),
        sg.verify(img, sg.sign(img, priv, "pss"), pub, "pss"),
        sg.verify(bytes(flipped_msg), sig_vi, pub),
        sg.verify(vi, bytes(flipped_sig), pub),
        sg.verify(vi, sig_vi, wrong_pub),
        sg.verify(bytes(flipped_msg), pss_vi, pub, "pss"),
        sg.sign(vi, priv, use_crt=True) == sg.sign(vi, priv, use_crt=False),
    ]
    expected = [True] * 6 + [False] * 4 + [True]
    return [_row(g, c, ok, exp, src) for c, ok, exp in zip(SIGNATURE_CASES, results, expected)]


# ---- 4. RFC 8017 và thư viện cryptography ---------------------------------------------------------------
def load_rsa_vectors() -> dict:
    return json.loads((VECTORS / "rsa_pkcs1_rfc8017.json").read_bytes().decode("utf-8"))


def check_rfc8017_vectors() -> list[CheckRow]:
    data = load_rsa_vectors()
    k = data["key"]
    p, q, e = int(k["p"], 16), int(k["q"], 16), int(k["e"], 16)
    pub, priv = keypair_from_primes(p, q, e)
    rows = [_row("PKCS#1 v1.5", "DigestInfo SHA-256", pkcs1_v15.DIGEST_INFO_SHA256.hex(),
                 data["digest_info_sha256"]["hex"], "RFC 8017")]
    for c in data["cases"]:
        msg = c["message_utf8"].encode("utf-8")
        rows.append(_row("PKCS#1 v1.5", f"Vector cố định: '{c['message_utf8'][:20]}'", sg.sign(msg, priv).hex(),
                         c["signature_hex"], "RFC 8017 (vector lưu sẵn)"))
    return rows


def _crypto_key(priv: RSAPrivateKey):
    from cryptography.hazmat.primitives.asymmetric import rsa
    return rsa.RSAPrivateNumbers(priv.p, priv.q, priv.d, priv.dP, priv.dQ, priv.qInv,
                                 rsa.RSAPublicNumbers(priv.e, priv.n)).private_key()


def check_cross_library(pub: RSAPublicKey, priv: RSAPrivateKey) -> list[CheckRow]:
    g, src = "Đối chiếu thư viện", "cryptography"
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
    except ImportError:
        return [CheckRow(g, "Thư viện cryptography", "-", "chưa cài (pip install cryptography)", src, False)]
    key = _crypto_key(priv)
    pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)

    def lib_verifies(sig: bytes, msg: bytes, pad) -> bool:
        try:
            key.public_key().verify(sig, msg, pad, hashes.SHA256())
            return True
        except InvalidSignature:
            return False

    contract = (ROOT / "sample" / "messages" / "contract.txt")
    msg = contract.read_bytes() if contract.is_file() else "Hợp đồng mẫu".encode()
    bits = pub.n.bit_length()
    ours = sg.sign(msg, priv)
    theirs = key.sign(msg, padding.PKCS1v15(), hashes.SHA256())
    ours_pss = sg.sign(msg, priv, "pss")
    theirs_pss = key.sign(msg, pss, hashes.SHA256())
    return [
        _row(g, f"SHA-256 contract.txt", sha256(msg).hex(), hashlib.sha256(msg).hexdigest(), "hashlib"),
        _row(g, f"PKCS#1 v1.5 ký contract.txt ({bits}-bit): trùng từng byte", ours.hex(), theirs.hex(), src),
        _row(g, "PKCS#1 v1.5: cryptography kiểm tra chữ ký của nhóm", lib_verifies(ours, msg, padding.PKCS1v15()),
             True, src),
        _row(g, "PKCS#1 v1.5: nhóm kiểm tra chữ ký của cryptography", sg.verify(msg, theirs, pub), True, src),
        _row(g, "PSS: cryptography kiểm tra chữ ký của nhóm", lib_verifies(ours_pss, msg, pss), True, src),
        _row(g, "PSS: nhóm kiểm tra chữ ký của cryptography", sg.verify(msg, theirs_pss, pub, "pss"), True, src),
        _row(g, "PSS: hai lần ký cho hai chữ ký khác nhau (salt ngẫu nhiên)",
             ours_pss != sg.sign(msg, priv, "pss"), True, "RFC 8017"),
    ]


# ---- Tổng hợp -------------------------------------------------------------------------------------------
def build_report(include_slow: bool = False, bits: int = 2048) -> list[CheckRow]:
    pub, priv = shared_keypair(bits)
    return (check_tiny_slide() + check_sha256_nist(include_slow) + check_signature_cases(pub, priv)
            + check_rfc8017_vectors() + check_cross_library(pub, priv))


def summary(rows: list[CheckRow]) -> str:
    return f"{sum(r.match for r in rows)}/{len(rows)} ca khớp"


def to_markdown(rows: list[CheckRow]) -> str:
    lines = [
        "# Kết quả kiểm thử đối chiếu",
        "",
        f"Sinh tự động bởi `python -m test.report` lúc {time.strftime('%Y-%m-%d %H:%M:%S')}. {summary(rows)}.",
        "",
        "| Nhóm | Ca kiểm thử | Ours | Reference | Nguồn | Khớp |",
        "|---|---|---|---|---|---|",
    ]
    esc = lambda s: s.replace("|", "\\|")
    for r in rows:
        lines.append(f"| {esc(r.group)} | {esc(r.case)} | `{esc(r.ours)}` | `{esc(r.reference)}` | {r.source} | "
                     f"{'✅' if r.match else '❌'} |")
    return "\n".join(lines) + "\n"


def to_console(rows: list[CheckRow]) -> str:
    head = ("Nhóm", "Ca kiểm thử", "Ours", "Reference", "Nguồn", "Khớp")
    cells = [head] + [(r.group, r.case, r.ours, r.reference, r.source, "OK" if r.match else "LỆCH") for r in rows]
    widths = [min(max(len(c[i]) for c in cells), 48) for i in range(len(head))]
    fit = lambda s, w: s if len(s) <= w else s[:w - 1] + "…"
    lines = [" | ".join(fit(c, w).ljust(w) for c, w in zip(row, widths)) for row in cells]
    lines.insert(1, "-+-".join("-" * w for w in widths))
    return "\n".join(lines) + f"\n\n{summary(rows)}\n"


def write_markdown(rows: list[CheckRow], out: Path) -> Path:
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(to_markdown(rows).encode("utf-8"))
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Bảng đối chiếu kết quả kiểm thử")
    ap.add_argument("--out", type=Path, help="ghi Markdown, ví dụ docs/report/test_results.md")
    ap.add_argument("--slow", action="store_true", help="gồm ca chậm (SHA-256 của 1 000 000 ký tự 'a')")
    args = ap.parse_args(argv)
    rows = build_report(include_slow=args.slow)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    print(to_console(rows))
    if args.out:
        print(f"Đã ghi {write_markdown(rows, args.out)}")
    return 0 if all(r.match for r in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
