import hashlib
import os

import pytest

from core.hash.sha256 import H0, _compress, big_sigma0, ch, compress_reference, maj, pad, rotr
from core.padding import pkcs1_v15, pss


def test_sha256_helpers():
    assert rotr(1, 1) == 0x80000000
    assert ch(0xFFFFFFFF, 1, 2) == 1 and ch(0, 1, 2) == 2
    assert maj(1, 1, 0) == 1 and maj(1, 0, 0) == 0
    assert big_sigma0(0) == 0
    for n in (0, 55, 56, 64):
        assert (n + len(pad(n))) % 64 == 0


def test_compress_fast_equals_reference():
    block = os.urandom(64)
    H = list(H0)
    ref = compress_reference(H, block)
    _compress(H, block)
    assert H == ref


def test_pkcs1_encode_structure():
    h = hashlib.sha256(b"abc").digest()
    em = pkcs1_v15.encode(h, 256)
    assert len(em) == 256 and em[:2] == b"\x00\x01"
    ps_end = em.index(b"\x00", 2)
    assert set(em[2:ps_end]) == {0xFF} and ps_end - 2 >= 8
    assert em[ps_end + 1:] == pkcs1_v15.DIGEST_INFO_SHA256 + h


def test_pkcs1_too_short():
    with pytest.raises(ValueError):
        pkcs1_v15.encode(bytes(32), 61)
    pkcs1_v15.encode(bytes(32), 62)


def test_strict_vs_sloppy():
    h = hashlib.sha256(b"x").digest()
    em = pkcs1_v15.encode(h, 128)
    assert pkcs1_v15.verify_strict(em, h) and pkcs1_v15.verify_sloppy(em, h)
    # PS ngắn + rác ở cuối: kiểu EM Bleichenbacher dựng ra
    forged = b"\x00\x01\xff\x00" + pkcs1_v15.DIGEST_INFO_SHA256 + h
    forged += os.urandom(128 - len(forged))
    assert pkcs1_v15.verify_sloppy(forged, h)
    assert not pkcs1_v15.verify_strict(forged, h)


def _mgf1_ref(seed: bytes, n: int) -> bytes:
    out = b""
    c = 0
    while len(out) < n:
        out += hashlib.sha256(seed + c.to_bytes(4, "big")).digest()
        c += 1
    return out[:n]


@pytest.mark.parametrize("n", [0, 1, 32, 33, 223])
def test_mgf1(n):
    seed = os.urandom(32)
    assert pss.mgf1(seed, n) == _mgf1_ref(seed, n)


@pytest.mark.parametrize("em_bits", [1023, 1024, 2047])
def test_pss_roundtrip(em_bits):
    h = hashlib.sha256(b"pss").digest()
    salt = bytes(range(32))
    em = pss.encode(h, em_bits, salt=salt)
    assert em == pss.encode(h, em_bits, salt=salt)                 # salt cố định → tất định
    assert em[-1] == 0xBC and pss.verify(h, em, em_bits)
    assert not pss.verify(hashlib.sha256(b"khac").digest(), em, em_bits)
    bad = bytearray(em)
    bad[5] ^= 1
    assert not pss.verify(h, bytes(bad), em_bits)


def test_pss_random_salt_differs():
    h = hashlib.sha256(b"a").digest()
    assert pss.encode(h, 2047) != pss.encode(h, 2047)
