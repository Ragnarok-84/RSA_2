"""R2 — Đáp ứng yêu cầu: test vector chuẩn cho SHA-256 (NIST FIPS 180-4, dữ liệu ở test/vectors/sha256_nist.json)
và đối chiếu với hashlib ở các độ dài biên 55, 56, 63, 64, 65 byte.
"""
import hashlib
import os

import pytest

from core.hash.sha256 import SHA256, sha256
from test.report import check_sha256_nist, load_sha256_vectors

ROWS = check_sha256_nist(include_slow=False)


@pytest.mark.parametrize("row", ROWS, ids=[r.case for r in ROWS])
def test_sha256_vector(row):
    assert row.match, f"{row.case}: ours = {row.ours}, ref = {row.reference}"


@pytest.mark.parametrize("n", [55, 56, 63, 64, 65, 119, 120, 128])
def test_streaming_equals_one_shot(n):
    data = os.urandom(n)
    h = SHA256()
    for i in range(0, n, 7):
        h.update(data[i:i + 7])
    assert h.digest() == sha256(data) == hashlib.sha256(data).digest()


@pytest.mark.slow
def test_million_a():
    m = load_sha256_vectors()["million_a"]
    assert sha256(m["repeat"].encode() * m["count"]).hex() == m["digest"]
