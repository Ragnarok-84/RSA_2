# Sử dụng công cụ AI

Theo quy định của môn học, nhóm ghi rõ việc sử dụng công cụ AI trong đề tài.

| Công cụ | Phần việc AI hỗ trợ | Nhóm đã làm gì để kiểm chứng |
| --- | --- | --- |
| Claude Code (Anthropic) | Dựng lại cấu trúc repo theo tài liệu thiết kế `RSA_SIGNATURE_REPO_DESIGN.md` của nhóm: tách `core/` thành các module, viết `pki/`, kịch bản s1–s6, tấn công a1–a8, bộ test `test/required` + `test/unit`, `test/report.py`, GUI 6 tab (giữ bảng màu và cách hiển thị của nhóm), CLI, tài liệu | *(nhóm điền: đọc lại từng module, chạy `pytest`, đối chiếu ví dụ slide, tự giải thích được mã khi bảo vệ)* |
| | | |

## Ghi chú cho nhóm

* Mọi thành viên phải giải thích được toàn bộ mã nguồn khi bảo vệ, đặc biệt: SHA-256, Euclid mở rộng,
  bình phương và nhân, EMSA-PKCS1-v1_5, kiểm tra chuỗi chứng chỉ.
* Bổ sung phần việc cụ thể của từng thành viên vào bảng phân công trong `README.md`.
