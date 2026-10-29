# Kiểm thử

Cả hai thư mục đều được push lên repo.

| Thư mục | Mục đích | Ai chạy | Lệnh |
| --- | --- | --- | --- |
| `required/` | Đáp ứng yêu cầu của giảng viên: ≥ 3 ca tự viết, test vector chuẩn (NIST, RFC), đối chiếu thư viện chuẩn, in kết quả đối chiếu | Giảng viên, khi demo, khi viết báo cáo | `python -m pytest test/required -v` |
| `unit/` | Bắt lỗi trong lúc phát triển (toán, padding, PKI, kịch bản, tấn công, ràng buộc kiến trúc, GUI) | Cả nhóm, sau mỗi lần sửa code | `python -m pytest -m "not slow"` |

* `report.py`: dữ liệu và hàm kiểm tra dùng chung. Các file `required/test_r*.py` gọi `check_*()` rồi
  `assert row.match`; GUI (tab Kiểm thử) và CLI (`python -m test.report`) hiển thị cùng kết quả, nên logic chỉ
  viết một lần.
* `vectors/sha256_nist.json`: test vector NIST FIPS 180-4.
* `vectors/rsa_pkcs1_rfc8017.json`: DigestInfo SHA-256 (RFC 8017 §9.2) và chữ ký PKCS#1 v1.5 mẫu với khoá cố định
  (sinh một lần bằng `cryptography`, lưu lại để kiểm tra hồi quy không cần cài thư viện).
* `conftest.py`: khoá 2048 bít sinh 1 lần / phiên; GUI chạy offscreen.
* Test chậm (khoá 3072 bít, 1 000 000 ký tự `a`) đánh dấu `@pytest.mark.slow`.

Đây là nơi **duy nhất** được import `hashlib`, `hmac`, `cryptography` và dùng `pow` built-in — để đối chiếu.
Luôn chạy từ thư mục gốc repo (`python -m pytest`): tên `test` trùng package `test` của thư viện chuẩn;
`pyproject.toml` đặt `pythonpath = ["."]` để package của repo được ưu tiên.
