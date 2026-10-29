import os
import secrets

import pytest

from core.number_theory import crt, egcd, gcd, iroot, isqrt, mod_inverse, mod_pow
from core.step_logger import StepLogger
from core.utils import Timer, byte_len, constant_time_eq, from_hex, i2osp, os2ip


def rand(bits: int) -> int:
    return secrets.randbits(bits) | 1


def test_gcd():
    assert gcd(0, 5) == 5 and gcd(12, 18) == 6 and gcd(-12, 18) == 6 and gcd(17, 11) == 1


@pytest.mark.parametrize("_", range(20))
def test_egcd_identity(_):
    a, b = rand(300), rand(200)
    d, x, y = egcd(a, b)
    assert a * x + b * y == d == gcd(a, b)


def test_mod_inverse_random_and_error():
    n = rand(512)
    a = rand(500)
    while gcd(a, n) != 1:
        a += 2
    assert (a * mod_inverse(a, n)) % n == 1
    assert mod_inverse(a, n) == pow(a, -1, n)
    with pytest.raises(ValueError):
        mod_inverse(6, 9)


@pytest.mark.parametrize("_", range(20))
def test_mod_pow_matches_builtin(_):
    a, e, n = rand(1024), rand(1024), rand(1024)
    assert mod_pow(a, e, n) == pow(a, e, n)


def test_mod_pow_edges():
    assert mod_pow(5, 0, 7) == 1 and mod_pow(5, 3, 1) == 0 and mod_pow(0, 5, 7) == 0
    with pytest.raises(ValueError):
        mod_pow(2, -1, 7)
    with pytest.raises(ValueError):
        mod_pow(2, 3, 0)


def test_mod_pow_logger_table_matches_slide():
    log = StepLogger()
    assert mod_pow(88, 23, 187, log) == 11
    headers, rows = log.steps[-1].table
    assert headers == ("i", "b_i", "c", "f")
    assert [r[2] for r in rows] == [1, 2, 5, 11, 23]                  # c tăng dần tới số mũ
    assert rows[-1][3] == 11


def test_crt_random():
    moduli = [101, 103, 107]
    x = secrets.randbelow(101 * 103 * 107)
    assert crt([x % m for m in moduli], moduli) == x
    with pytest.raises(ValueError):
        crt([1], [2, 3])


@pytest.mark.parametrize("k", [2, 3, 5])
def test_iroot(k):
    r = rand(400)
    assert iroot(r ** k, k) == (r, True)
    root, exact = iroot(r ** k + 1, k)
    assert root == r and not exact
    assert isqrt(99) == 9


def test_utils():
    assert i2osp(1, 3) == b"\x00\x00\x01" and os2ip(b"\x01\x00") == 256
    with pytest.raises(ValueError):
        i2osp(256, 1)
    assert byte_len(255) == 1 and byte_len(256) == 2
    assert from_hex("0x0a 0b\n") == b"\x0a\x0b"
    b = os.urandom(32)
    assert constant_time_eq(b, b) and not constant_time_eq(b, b[:-1] + bytes([b[-1] ^ 1]))
    with Timer() as t:
        pass
    assert t.elapsed >= 0
