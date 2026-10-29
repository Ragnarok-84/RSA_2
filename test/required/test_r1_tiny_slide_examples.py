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
    """Logger phải ghi đủ: n, φ(n), gcd, bảng Euclid, h(x), bảng bình phương và nhân khi ký và khi kiểm tra, kết luận."""
    log = StepLogger()
    tiny = TinyRSA()
    y = tiny.sign(88, log)
    assert y == 11 and tiny.verify(88, y, log)
    text = log.to_text()
    for needle in ("17*11 = 187", "16*10 = 160", "gcd(7, 160) = 1", "Euclid mở rộng",
                   "mod 160 = 23", "h(x) = x = 88", "88^23 mod 187 = 11", "11^7 mod 187 = 88", "HỢP LỆ"):
        assert needle in text, needle
    assert len(log.tables()) == 3          # Euclid + bình phương và nhân (ký) + bình phương và nhân (kiểm tra)


def test_tiny_sign_then_encrypt_logs_tables():
    """Ký rồi mã hoá bản thu nhỏ: z = e_B(x, y) và (x, y) = d_B(z) đều có bảng tính tay."""
    from core.tiny_rsa import decrypt_pair, encrypt_pair
    trang, thuy = TinyRSA(17, 11, 7), TinyRSA(23, 13, 5)
    log = StepLogger()
    y = trang.sign(88, log, with_keygen=False)
    z = encrypt_pair(thuy, 88, y, log)
    x2, y2 = decrypt_pair(thuy, z, False, log)
    assert (z, x2, y2) == ([264, 189], 88, 11) and trang.verify(x2, y2)
    assert [s.title.split()[0] for s in log.tables()] == ["Bình", "Mã", "Giải"]
    with pytest.raises(ValueError):                 # n_B = 143 < y: không mã hoá được chữ ký
        encrypt_pair(TinyRSA(13, 11, 7), 88, 150)
