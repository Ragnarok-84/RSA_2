from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Literal

from core.hash.sha256 import sha256, sha256_file
from core.padding import pkcs1_v15, pss
from core.rsa_keygen import RSAPrivateKey, RSAPublicKey
from core.rsa_primitives import rsasp1, rsavp1
from core.step_logger import StepLogger
from core.utils import byte_len, constant_time_eq, from_hex, i2osp, os2ip, short_hex

Scheme = Literal["pkcs1v15", "pss"]
SCHEMES: tuple[str, ...] = ("pkcs1v15", "pss")
SCHEME_LABELS = {"pkcs1v15": "PKCS1v15", "pss": "PSS"}
PSS_SALT_LEN = 32


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
        scheme = {"PKCS1v15": "pkcs1v15", "PSS": "pss"}.get(d["scheme"], d["scheme"])
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


def _encode(message_hash: bytes, n: int, scheme: str, salt: bytes | None) -> bytes:
    try:
        if scheme == "pkcs1v15":
            return pkcs1_v15.encode(message_hash, byte_len(n))
        return pss.encode(message_hash, n.bit_length() - 1, PSS_SALT_LEN, salt)
    except ValueError as err:
        raise SignatureError(str(err)) from err


def sign_hash(message_hash: bytes, priv: RSAPrivateKey, scheme: Scheme = "pkcs1v15", *, use_crt: bool = True,
              salt: bytes | None = None, logger: StepLogger | None = None) -> bytes:
    """Ký trên giá trị băm SHA-256 có sẵn (dùng khi băm tệp lớn theo khối). Trả S dài đúng k byte."""
    _check_scheme(scheme)
    k = byte_len(priv.n)
    em = _encode(message_hash, priv.n, scheme, salt)
    m = os2ip(em)
    s = rsasp1(priv, m, use_crt=use_crt)
    sig = i2osp(s, k)
    if logger is not None:
        if scheme == "pkcs1v15":
            logger.log("Mã hoá EM (PKCS#1 v1.5)", r"EM = 00 \| 01 \| PS \| 00 \| DigestInfo \| h", em.hex())
        else:
            logger.log("Mã hoá EM (PSS, salt ngẫu nhiên)", r"EM = maskedDB \| H \| \mathrm{BC}", em.hex())
        logger.log("Số đại diện", r"m = \mathrm{OS2IP}(EM)", short_hex(m))
        logger.log("Ký" + (" (CRT)" if use_crt else ""), r"s = m^{d} \mathrm{mod}\ n", short_hex(s))
        logger.ok(f"Chữ ký S ({k} byte)", sig.hex())
    return sig


def sign(message: bytes, priv: RSAPrivateKey, scheme: Scheme = "pkcs1v15", *, use_crt: bool = True,
         logger: StepLogger | None = None) -> bytes:
    """Ký thông điệp: S = RSASP1(d, OS2IP(Encode(SHA256(M), k)))."""
    h = sha256(message)
    if logger is not None:
        logger.log("Băm thông điệp", r"h = \mathrm{SHA256}(M)", h.hex())
    return sign_hash(h, priv, scheme, use_crt=use_crt, logger=logger)


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
    if scheme == "pkcs1v15":
        em = i2osp(m, k)
        if logger is not None:
            logger.log("Khôi phục EM", r"EM' = \mathrm{I2OSP}(s^{e} \mathrm{mod}\ n, k)", em.hex())
        if pkcs1_v15.verify_strict(em, message_hash):
            result = VerifyResult(True, "hợp lệ: EM' khớp toàn bộ Encode(SHA256(M))", message_hash, em)
        elif len(em) > 32 and pkcs1_v15.verify_strict(em, em[-32:]):
            result = VerifyResult(False, "hash không khớp (thông điệp bị sửa hoặc ký cho thông điệp khác)",
                                  message_hash, em)
        else:
            result = VerifyResult(False, "EM' sai cấu trúc (sai khoá công khai hoặc chữ ký bị sửa)", message_hash, em)
    else:
        em_bits = pub.n.bit_length() - 1
        if m.bit_length() > em_bits:
            return VerifyResult(False, "EM' dài hơn emBits (sai khoá hoặc chữ ký bị sửa)", message_hash)
        em = i2osp(m, (em_bits + 7) // 8)
        if logger is not None:
            logger.log("Khôi phục EM (PSS)", r"EM' = \mathrm{I2OSP}(s^{e} \mathrm{mod}\ n, emLen)", em.hex())
        ok = pss.verify(message_hash, em, em_bits, PSS_SALT_LEN)
        result = VerifyResult(ok, "hợp lệ: EMSA-PSS-VERIFY nhất quán" if ok else
                              "EMSA-PSS-VERIFY thất bại (hash không khớp, sai khoá hoặc chữ ký bị sửa)", message_hash, em)
    if logger is not None:
        (logger.ok if result.valid else logger.bad)("Kết luận", result.reason)
    return result


def verify_detailed(message: bytes, signature: bytes, pub: RSAPublicKey, scheme: Scheme = "pkcs1v15",
                    logger: StepLogger | None = None) -> VerifyResult:
    h = sha256(message)
    if logger is not None:
        logger.log("Băm thông điệp nhận được", r"h = \mathrm{SHA256}(M)", h.hex())
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
    return rsasp1(priv, m, use_crt=False)
