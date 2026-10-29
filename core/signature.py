from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Literal

from core.hash.sha256 import sha256, sha256_file
from core.padding import pkcs1_v15
from core.rsa_keygen import RSAPrivateKey, RSAPublicKey
from core.rsa_primitives import rsasp1, rsavp1
from core.step_logger import StepLogger
from core.utils import byte_len, constant_time_eq, from_hex, i2osp, os2ip, short_hex

# textbook: ký thẳng giá trị băm theo slide, y = h(x)^a mod n; pkcs1v15: đệm EM theo RFC 8017 rồi mới lũy thừa
Scheme = Literal["textbook", "pkcs1v15"]
SCHEMES: tuple[str, ...] = ("textbook", "pkcs1v15")
SCHEME_LABELS = {"textbook": "Textbook", "pkcs1v15": "PKCS1v15"}


class SignatureError(Exception):
    """Không ký được (khoá quá ngắn, lược đồ không hỗ trợ…)."""


@dataclass
class VerifyResult:
    valid: bool
    reason: str
    computed_hash: bytes | None = None
    recovered_em: bytes | None = None

    def __bool__(self) -> bool:
        return self.valid


@dataclass
class SignatureBundle:
    """Nội dung tệp *.sig.json (đọc/ghi bằng core.key_io)."""
    scheme: str
    message_file: str
    message_hash_hex: str
    signature_hex: str
    signer_certificate: dict | None = None
    timestamp_token: dict | None = None
    version: int = 1
    algorithm: str = "RSA"
    hash: str = "SHA-256"
    extra: dict = field(default_factory=dict)

    @property
    def signature(self) -> bytes:
        return from_hex(self.signature_hex)

    def to_dict(self) -> dict:
        d = {
            "version": self.version,
            "algorithm": self.algorithm,
            "scheme": SCHEME_LABELS.get(self.scheme, self.scheme),
            "hash": self.hash,
            "message_file": self.message_file,
            "message_hash_hex": self.message_hash_hex,
            "signature_hex": self.signature_hex,
            "signer_certificate": self.signer_certificate,
            "timestamp_token": self.timestamp_token,
        }
        d.update(self.extra)
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "SignatureBundle":
        if d.get("algorithm", "RSA") != "RSA" or d.get("hash", "SHA-256") != "SHA-256":
            raise ValueError("Chỉ hỗ trợ RSA + SHA-256")
        scheme = {label: key for key, label in SCHEME_LABELS.items()}.get(d["scheme"], d["scheme"])
        if scheme not in SCHEMES:
            raise ValueError(f"Lược đồ không hỗ trợ: {d['scheme']}")
        known = {"version", "algorithm", "scheme", "hash", "message_file", "message_hash_hex", "signature_hex",
                 "signer_certificate", "timestamp_token"}
        return cls(scheme=scheme, message_file=d.get("message_file", ""), message_hash_hex=d["message_hash_hex"],
                   signature_hex=d["signature_hex"], signer_certificate=d.get("signer_certificate"),
                   timestamp_token=d.get("timestamp_token"), version=d.get("version", 1),
                   extra={k: v for k, v in d.items() if k not in known})


def _check_scheme(scheme: str) -> None:
    if scheme not in SCHEMES:
        raise SignatureError(f"scheme phải thuộc {SCHEMES}")


def _encode(message_hash: bytes, n: int, scheme: str) -> bytes:
    if scheme == "textbook":
        # h(x) phải nhỏ hơn n thì y^b mod n mới khôi phục đúng h(x)
        if os2ip(message_hash) >= n:
            raise SignatureError("Khoá quá ngắn: cần n > h(x) (n dài hơn 256 bít)")
        return message_hash
    try:
        return pkcs1_v15.encode(message_hash, byte_len(n))
    except ValueError as err:
        raise SignatureError(str(err)) from err


def sign_hash(message_hash: bytes, priv: RSAPrivateKey, scheme: Scheme = "pkcs1v15", *,
              logger: StepLogger | None = None) -> bytes:
    """Ký trên giá trị băm SHA-256 có sẵn (dùng khi băm tệp lớn theo khối). Trả S dài đúng k byte."""
    _check_scheme(scheme)
    k = byte_len(priv.n)
    em = _encode(message_hash, priv.n, scheme)
    m = os2ip(em)
    s = rsasp1(priv, m)
    sig = i2osp(s, k)
    if logger is not None:
        if scheme == "textbook":
            logger.log("Số đưa vào lũy thừa (theo slide)", "m = OS2IP(h(x))", em.hex())
        else:
            logger.log("Mã hoá EM (PKCS#1 v1.5)", "EM = 00 | 01 | PS | 00 | DigestInfo | h(x)", em.hex())
            logger.log("Số đại diện", f"m = OS2IP(EM)", short_hex(m))
        logger.log("Ký", f"y = m^a mod n", short_hex(s))
        logger.ok(f"Chữ ký y ({k} byte)", sig.hex())
    return sig


def sign(message: bytes, priv: RSAPrivateKey, scheme: Scheme = "pkcs1v15", *,
         logger: StepLogger | None = None) -> bytes:
    """Ký thông điệp: y = RSASP1(a, OS2IP(Encode(SHA256(x)))); textbook bỏ bước Encode."""
    h = sha256(message)
    if logger is not None:
        logger.log("Băm thông điệp", "h(x) = SHA-256(x)", h.hex())
    return sign_hash(h, priv, scheme, logger=logger)


def verify_hash(message_hash: bytes, signature: bytes, pub: RSAPublicKey, scheme: Scheme = "pkcs1v15",
                logger: StepLogger | None = None) -> VerifyResult:
    """Kiểm tra chữ ký trên giá trị băm có sẵn, trả kết quả kèm lý do."""
    _check_scheme(scheme)
    k = byte_len(pub.n)
    if len(signature) != k:
        return VerifyResult(False, f"độ dài chữ ký sai ({len(signature)} byte, cần {k})", message_hash)
    s = os2ip(signature)
    if s >= pub.n:
        return VerifyResult(False, "chữ ký nằm ngoài [0, n)", message_hash)
    m = rsavp1(pub, s)
    em = i2osp(m, k)
    if scheme == "textbook":
        if logger is not None:
            logger.log("Tính y^b mod n", "m' = y^b mod n", short_hex(m))
        if m == os2ip(message_hash):
            result = VerifyResult(True, "hợp lệ: y^b mod n = h(x)", message_hash, em)
        else:
            result = VerifyResult(False, "y^b mod n ≠ h(x) (thông điệp bị sửa, sai khoá hoặc chữ ký bị sửa)",
                                  message_hash, em)
    else:
        if logger is not None:
            logger.log("Khôi phục EM", "EM' = I2OSP(y^b mod n, k)", em.hex())
        if pkcs1_v15.verify_strict(em, message_hash):
            result = VerifyResult(True, "hợp lệ: EM' khớp toàn bộ Encode(SHA256(M))", message_hash, em)
        elif len(em) > 32 and pkcs1_v15.verify_strict(em, em[-32:]):
            result = VerifyResult(False, "hash không khớp (thông điệp bị sửa hoặc ký cho thông điệp khác)",
                                  message_hash, em)
        else:
            result = VerifyResult(False, "EM' sai cấu trúc (sai khoá công khai hoặc chữ ký bị sửa)",
                                  message_hash, em)
    if logger is not None:
        (logger.ok if result.valid else logger.bad)("Kết luận", result.reason)
    return result


def verify_detailed(message: bytes, signature: bytes, pub: RSAPublicKey, scheme: Scheme = "pkcs1v15",
                    logger: StepLogger | None = None) -> VerifyResult:
    h = sha256(message)
    if logger is not None:
        logger.log("Băm thông điệp nhận được", "h(x) = SHA-256(x)", h.hex())
    return verify_hash(h, signature, pub, scheme, logger)


def verify(message: bytes, signature: bytes, pub: RSAPublicKey, scheme: Scheme = "pkcs1v15") -> bool:
    """True khi và chỉ khi S là chữ ký hợp lệ của M dưới khoá công khai pub."""
    return verify_detailed(message, signature, pub, scheme).valid


def sign_file(path: Path, priv: RSAPrivateKey, scheme: Scheme = "pkcs1v15",
              progress: Callable[[int, int], None] | None = None) -> SignatureBundle:
    """Băm tệp theo khối 64 KB rồi ký; trả SignatureBundle để lưu thành *.sig.json."""
    path = Path(path)
    h = sha256_file(path, progress)
    sig = sign_hash(h, priv, scheme)
    return SignatureBundle(scheme=scheme, message_file=path.name, message_hash_hex=h.hex(), signature_hex=sig.hex())


def verify_file(path: Path, bundle: SignatureBundle, pub: RSAPublicKey,
                progress: Callable[[int, int], None] | None = None) -> VerifyResult:
    """Kiểm tra tệp với chữ ký trong bundle (băm lại tệp, không tin message_hash_hex trong bundle)."""
    h = sha256_file(Path(path), progress)
    result = verify_hash(h, bundle.signature, pub, bundle.scheme)
    if result.valid and not constant_time_eq(h, from_hex(bundle.message_hash_hex)):
        return VerifyResult(False, "hash của tệp khác message_hash_hex ghi trong .sig.json", h, result.recovered_em)
    return result


def sign_raw_no_hash(m: int, priv: RSAPrivateKey) -> int:
    """⚠ Ký trực tiếp số m, KHÔNG băm, KHÔNG đệm: s = m^d mod n. CHỈ dùng cho attacks/a1_no_hash_forgery.py."""
    return rsasp1(priv, m)
