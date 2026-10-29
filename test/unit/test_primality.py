import pytest

from core.primality import SMALL_PRIMES, generate_prime, is_probable_prime, miller_rabin
from core.rsa_keygen import generate_keypair, keypair_from_primes

KNOWN_PRIMES = [2, 3, 5, 997, 7919, 2 ** 61 - 1, 2 ** 127 - 1]
COMPOSITES = [0, 1, 4, 561, 1105, 1729, 2465, 3215031751, (2 ** 61 - 1) * (2 ** 31 - 1)]


@pytest.mark.parametrize("p", KNOWN_PRIMES)
def test_primes(p):
    assert is_probable_prime(p)


@pytest.mark.parametrize("n", COMPOSITES)
def test_composites_including_carmichael(n):
    assert not is_probable_prime(n)
    if n > 3:
        assert not miller_rabin(n)


def test_small_primes_table():
    assert SMALL_PRIMES[:5] == (2, 3, 5, 7, 11) and SMALL_PRIMES[-1] == 997 and len(SMALL_PRIMES) == 168


@pytest.mark.parametrize("bits", [16, 64, 256])
def test_generate_prime_bits(bits):
    p = generate_prime(bits)
    assert p.bit_length() == bits and p % 2 == 1 and is_probable_prime(p)
    assert generate_prime(bits, top_bits=2) >> (bits - 2) == 0b11


@pytest.mark.parametrize("bits", [512, 1024])
def test_generate_keypair(bits):
    pub, priv = generate_keypair(bits)
    assert pub.n.bit_length() == bits and priv.p != priv.q
    assert (priv.e * priv.d) % ((priv.p - 1) * (priv.q - 1)) == 1
    assert priv.p * priv.q == pub.n
    m = 123456789
    assert pow(pow(m, priv.d, pub.n), pub.e, pub.n) == m


def test_keypair_from_primes_errors():
    with pytest.raises(ValueError):
        keypair_from_primes(17, 17, 7)
    with pytest.raises(ValueError):
        keypair_from_primes(15, 11, 7)
    with pytest.raises(ValueError):
        keypair_from_primes(17, 11, 5)          # gcd(5, 160) = 5
