"""R3 — Đáp ứng yêu cầu: ít nhất 3 ca kiểm thử tự viết.

Thông điệp rỗng, văn bản tiếng Việt UTF-8, tệp ảnh nhị phân (sample/images/logo.png) với PKCS#1 v1.5;
sửa 1 bít thông điệp / 1 bít chữ ký / dùng sai khoá công khai → verify == False.
"""
import pytest

from core import signature as sg
from core.key_io import load_signature, save_signature
from test.report import SIGNATURE_CASES, check_signature_cases


@pytest.fixture(scope="module")
def rows(keypair, other_keypair):
    pub, priv = keypair
    return {r.case: r for r in check_signature_cases(pub, priv, other_keypair[0])}


@pytest.mark.parametrize("case", SIGNATURE_CASES)
def test_signature_case(rows, case):
    row = rows[case]
    assert row.match, f"{case}: ours = {row.ours}, kỳ vọng = {row.reference}"


def test_sign_and_verify_file_roundtrip(tmp_path, keypair):
    """Ký tệp → lưu .sig.json → đọc lại → kiểm tra; sửa 1 byte tệp → FAIL kèm lý do."""
    pub, priv = keypair
    f = tmp_path / "hop_dong.txt"
    f.write_bytes("Hợp đồng: 2.000.000.000 VNĐ".encode())
    save_signature(sg.sign_file(f, priv), tmp_path / "hop_dong.txt.sig.json")
    bundle = load_signature(tmp_path / "hop_dong.txt.sig.json")
    assert sg.verify_file(f, bundle, pub).valid
    f.write_bytes("Hợp đồng: 9.000.000.000 VNĐ".encode())
    res = sg.verify_file(f, bundle, pub)
    assert not res.valid and "hash" in res.reason
