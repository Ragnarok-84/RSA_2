import json

import pytest

from core import key_io
from core.signature import SignatureBundle, sign, verify


def test_private_key_roundtrip(tmp_path, small_keypair):
    pub, priv = small_keypair
    path = tmp_path / "keys" / "trang_sign.json"
    key_io.save_private_key(priv, path, owner="trang")
    data = json.loads(path.read_bytes())
    assert data["type"] == "private" and "KHÔNG" in data["warning"] and data["owner"] == "trang"
    assert key_io.load_private_key(path) == priv
    assert key_io.load_public_key(path) == pub
    assert key_io.load_key(path) == priv


def test_public_key_roundtrip(tmp_path, small_keypair):
    pub, _ = small_keypair
    path = tmp_path / "trang.pub.json"
    key_io.save_public_key(pub, path)
    assert key_io.load_key(path) == pub
    with pytest.raises(ValueError):
        key_io.load_private_key(path)


def test_broken_private_key(tmp_path, small_keypair):
    _, priv = small_keypair
    d = key_io.private_key_to_dict(priv)
    d["p"] = format(priv.p + 2, "x")
    with pytest.raises(ValueError):
        key_io.private_key_from_dict(d)


def test_signature_bundle_roundtrip(tmp_path, small_keypair):
    pub, priv = small_keypair
    sig = sign(b"abc", priv)
    b = SignatureBundle("pkcs1v15", "abc.txt", "00" * 32, sig.hex(), {"subject": "trang"}, None)
    key_io.save_signature(b, tmp_path / "abc.sig.json")
    raw = json.loads((tmp_path / "abc.sig.json").read_bytes())
    assert raw["scheme"] == "PKCS1v15" and raw["hash"] == "SHA-256" and raw["version"] == 1
    back = key_io.load_signature(tmp_path / "abc.sig.json")
    assert back.scheme == "pkcs1v15" and back.signer_certificate == {"subject": "trang"}
    assert verify(b"abc", back.signature, pub, back.scheme)
