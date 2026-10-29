"""Lưu / đọc khoá RSA và tệp chữ ký *.sig.json dạng JSON (số nguyên ghi dạng hex).

⚠ Khoá riêng được ghi KHÔNG mã hoá — chỉ dùng cho demo, không dùng cho khoá thật.
Đọc/ghi tệp ở chế độ nhị phân, mã UTF-8, để chạy giống nhau trên Windows và macOS.
"""
from __future__ import annotations

import json
from pathlib import Path

from core.rsa_keygen import RSAPrivateKey, RSAPublicKey
from core.signature import SignatureBundle

PRIVATE_FIELDS = ("n", "e", "d", "p", "q", "dP", "dQ", "qInv")
DEMO_WARNING = "KHOÁ DEMO cho bài tập — KHÔNG dùng thật, tệp không được mã hoá"


def _hex(x: int) -> str:
    return format(x, "x")


def write_json(path: Path, obj: object) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes((json.dumps(obj, indent=2, ensure_ascii=False) + "\n").encode("utf-8"))


def read_json(path: Path) -> dict:
    return json.loads(Path(path).read_bytes().decode("utf-8"))


def public_key_to_dict(pub: RSAPublicKey) -> dict:
    return {"kty": "RSA", "type": "public", "n": _hex(pub.n), "e": _hex(pub.e)}


def public_key_from_dict(d: dict) -> RSAPublicKey:
    return RSAPublicKey(int(d["n"], 16), int(d["e"], 16))


def private_key_to_dict(priv: RSAPrivateKey, owner: str = "") -> dict:
    d = {"kty": "RSA", "type": "private", "warning": DEMO_WARNING}
    if owner:
        d["owner"] = owner
    d.update({f: _hex(getattr(priv, f)) for f in PRIVATE_FIELDS})
    return d


def private_key_from_dict(d: dict) -> RSAPrivateKey:
    if d.get("type") != "private":
        raise ValueError("Tệp không chứa khoá riêng")
    priv = RSAPrivateKey(**{f: int(d[f], 16) for f in PRIVATE_FIELDS})
    if priv.p * priv.q != priv.n:
        raise ValueError("Khoá hỏng: p·q ≠ n")
    return priv


def save_private_key(priv: RSAPrivateKey, path: Path, owner: str = "") -> None:
    write_json(path, private_key_to_dict(priv, owner))


def save_public_key(pub: RSAPublicKey, path: Path) -> None:
    write_json(path, public_key_to_dict(pub))


def load_private_key(path: Path) -> RSAPrivateKey:
    return private_key_from_dict(read_json(path))


def load_public_key(path: Path) -> RSAPublicKey:
    """Đọc khoá công khai; tệp khoá riêng cũng được chấp nhận (lấy phần (n, e))."""
    d = read_json(path)
    return public_key_from_dict(d)


def load_key(path: Path) -> RSAPublicKey | RSAPrivateKey:
    d = read_json(path)
    return private_key_from_dict(d) if d.get("type") == "private" else public_key_from_dict(d)


def save_signature(bundle: SignatureBundle, path: Path) -> None:
    write_json(path, bundle.to_dict())


def load_signature(path: Path) -> SignatureBundle:
    return SignatureBundle.from_dict(read_json(path))
