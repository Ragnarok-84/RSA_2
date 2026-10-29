import json

import pytest

from core import key_io
from core.signature import SignatureBundle, sign, verify


def test_private_key_roundtrip(tmp_path, small_keypair):
    pub, priv = small_keypair
    path = tmp_path / "keys" / "alice_sign.json"
    key_io.save_private_key(priv, path, owner="Alice")
    data = json.loads(path.read_bytes())
    assert data["type"] == "private" and "KHÔNG" in data["warning"] and data["owner"] == "Alice"
    assert key_io.load_private_key(path) == priv
    assert key_io.load_public_key(path) == pub
    assert key_io.load_key(path) == priv


def test_public_key_roundtrip(tmp_path, small_keypair):
    pub, _ = small_keypair
    path = tmp_path / "alice.pub.json"
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
    sig = sign(b"abc", priv, "pss")
    b = SignatureBundle("pss", "abc.txt", "00" * 32, sig.hex(), {"subject": "Alice"}, None)
    key_io.save_signature(b, tmp_path / "abc.sig.json")
    raw = json.loads((tmp_path / "abc.sig.json").read_bytes())
    assert raw["scheme"] == "PSS" and raw["hash"] == "SHA-256" and raw["version"] == 1
    back = key_io.load_signature(tmp_path / "abc.sig.json")
    assert back.scheme == "pss" and back.signer_certificate == {"subject": "Alice"}
    assert verify(b"abc", back.signature, pub, back.scheme)
