"""Fixture dùng chung: khoá sinh 1 lần / phiên, dữ liệu mẫu. GUI chạy không cần màn hình (offscreen)."""
from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from test.report import shared_keypair  # noqa: E402


@pytest.fixture(scope="session")
def keypair():
    """Khoá 2048 bít của nhóm (pub, priv)."""
    return shared_keypair(2048)


@pytest.fixture(scope="session")
def other_keypair():
    """Một khoá 2048 bít khác (dùng cho ca 'sai khoá công khai')."""
    return shared_keypair(2048, slot=1)


@pytest.fixture(scope="session")
def small_keypair():
    """Khoá 1024 bít cho test nhanh."""
    return shared_keypair(1024)


@pytest.fixture
def vietnamese_text() -> bytes:
    return "Chữ ký số RSA: ký trên giá trị băm, kiểm tra, chứng thực và chống chối bỏ.".encode("utf-8")
