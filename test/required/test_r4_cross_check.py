"""R4 — Đáp ứng yêu cầu: đối chiếu với thư viện chuẩn và in kết quả đối chiếu.

- PKCS#1 v1.5: dùng cùng khóa do `cryptography` sinh để ký bằng cả hai cài đặt → chữ ký giống hệt từng byte;
  mỗi cài đặt kiểm tra được chữ ký của bên kia.
- PSS (salt 32, MGF1-SHA256): kiểm tra chéo hai chiều.
- Vector PKCS#1 v1.5 lưu sẵn (test/vectors/rsa_pkcs1_rfc8017.json) và DigestInfo theo RFC 8017.
Bảng đầy đủ: python -m test.report (hoặc tab "Kiểm thử" trên GUI).
"""
import pytest

from test.report import check_cross_library, check_rfc8017_vectors

RFC_ROWS = check_rfc8017_vectors()


@pytest.mark.parametrize("row", RFC_ROWS, ids=[r.case for r in RFC_ROWS])
def test_rfc8017_vector(row):
    assert row.match, f"{row.case}: ours = {row.ours}, ref = {row.reference}"


@pytest.fixture(scope="module")
def cross_rows(keypair):
    pytest.importorskip("cryptography")
    return check_cross_library(keypair[0].n.bit_length())


def test_cross_library_all_match(cross_rows):
    bad = [r for r in cross_rows if not r.match]
    assert not bad, "\n".join(f"{r.case}: ours = {r.ours}, ref = {r.reference}" for r in bad)


def test_pkcs1_v15_byte_identical(cross_rows):
    row = next(r for r in cross_rows if "trùng từng byte" in r.case)
    assert row.match


@pytest.mark.parametrize("message", [b"", b"abc", "Tiếng Việt có dấu".encode(), bytes(range(256)) * 10])
def test_pkcs1_byte_identical_many_messages(keypair, message):
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    from core.rsa_keygen import RSAPrivateKey
    from core.signature import sign
    pub, _ = keypair
    key = rsa.generate_private_key(public_exponent=65537, key_size=pub.n.bit_length())
    numbers = key.private_numbers()
    reference = RSAPrivateKey(numbers.public_numbers.n, numbers.public_numbers.e, numbers.d, numbers.p, numbers.q)
    assert sign(message, reference) == key.sign(message, padding.PKCS1v15(), hashes.SHA256())
