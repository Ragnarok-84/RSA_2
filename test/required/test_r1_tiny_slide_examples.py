"""R1 — Đáp ứng yêu cầu: kiểm thử bằng các ví dụ tính tay trong slide.

Euclid mở rộng, nghịch đảo modulo, bình phương và nhân, CRT, sinh khoá p = 17, q = 11, e = 7 và
ký Tiny h = 88 → s = 11. Dữ liệu và hàm kiểm tra nằm trong test/report.py (dùng chung với GUI và báo cáo).
"""
import pytest

from core.step_logger import StepLogger
from core.tiny_rsa import TinyRSA
from test.report import check_tiny_slide

ROWS = check_tiny_slide()


@pytest.mark.parametrize("row", ROWS, ids=[r.case for r in ROWS])
def test_slide_example(row):
    assert row.match, f"{row.case}: ours = {row.ours}, slide = {row.reference}"


def test_tiny_logs_every_step():
    """Logger phải ghi đủ: n, φ(n), gcd, bảng Euclid, h, bảng bình phương và nhân khi ký và khi kiểm tra, kết luận."""
    log = StepLogger()
    tiny = TinyRSA()
    s = tiny.sign(88, log)
    assert s == 11 and tiny.verify(88, s, log)
    text = log.to_text()
    for needle in ("n = 17 · 11 = 187", "φ(n) = 16 · 10 = 160", "gcd(7, 160) = 1", "Euclid mở rộng",
                   "d = 23", "h = 88", "88^23 mod 187 = 11", "11^7 mod 187 = 88", "HỢP LỆ"):
        assert needle in text, needle
    assert len(log.tables()) == 3          # Euclid + bình phương và nhân (ký) + bình phương và nhân (kiểm tra)
