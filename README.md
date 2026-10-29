# Hệ chữ ký điện tử RSA — Nhóm 11

Đồ án môn **An toàn và bảo mật thông tin (CNTT1168)**.

Chương trình minh họa cách dùng RSA để ký thông điệp, kiểm tra chữ ký và phát hiện dữ liệu bị sửa. Có giao diện để thao tác và xem từng bước tính toán.

Thành viên: **Thu Trang, Thu Thủy, Mai Phương, Tuyết Linh**.

## 1. Cài đặt và chạy

Cần cài **Python 3.11 trở lên**. Chạy các lệnh bên dưới từ thư mục gốc của dự án.

### Cách nhanh

- **Windows:** nhấp đúp `run_demo.bat`.
- **macOS / Linux:** mở terminal và chạy `bash run_demo.sh`.

Script sẽ tạo môi trường `.venv`, cài các thư viện cần thiết rồi mở ứng dụng. Lần đầu cần kết nối Internet để tải thư viện.

### Cài thủ công trên Windows

Mở PowerShell tại thư mục dự án:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m demo.gui
```

Những lần sau chỉ cần chạy lệnh cuối để mở ứng dụng.

### Cài thủ công trên macOS / Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m demo.gui
```

Trên Ubuntu/Debian, nếu thiếu môi trường ảo hoặc thư viện Qt, cài thêm:

```bash
sudo apt install python3-venv libxcb-cursor0
```

## 2. Các tab trong ứng dụng

| Tab | Dùng để làm gì? |
| --- | --- |
| **1. Tiny RSA** | Tính RSA với số nhỏ; xem từng bước sinh khóa, ký và kiểm tra. Có thêm luồng ký rồi mã hóa. |
| **2. Ký & Kiểm tra** | Ký văn bản hoặc tệp, kiểm tra chữ ký và thử sửa 1 bit dữ liệu hoặc chữ ký. |
| **3. Ký rồi mã hoá** | Ký thông điệp, mã hóa cho người nhận, sau đó giải mã và kiểm tra chữ ký. |
| **4. PKI & Chống chối bỏ** | Minh họa chứng chỉ, cơ quan cấp chứng chỉ (CA), thu hồi chứng chỉ và dấu thời gian. |
| **5. Phân tích an toàn** | Chạy các kịch bản và mô phỏng tấn công, so sánh khi bật hoặc tắt biện pháp phòng chống. |
| **6. Hiệu năng** | Đo thời gian sinh khóa, ký, kiểm tra chữ ký và băm dữ liệu. |
| **7. Kiểm thử** | Xem kết quả kiểm thử và đối chiếu với thư viện tham chiếu. |

Hai lựa chọn lược đồ ký trong tab 2 và tab 3:

- **Mặc định:** ký trực tiếp giá trị băm bằng công thức `y = h(x)^a mod n`.
- **PKCS#1 v1.5:** thêm phần đệm theo chuẩn trước khi ký.

`x` là thông điệp, `h(x)` là giá trị băm, `y` là chữ ký; `a` là số mũ bí mật và `n` là mô-đun RSA.

## 3. Thử nhanh

### Xem RSA từng bước

1. Mở tab **Tiny RSA**, bấm **Nạp ví dụ**.
2. Giữ chế độ **Không băm (VD)** với `x = 88`, rồi bấm **Ký**.
3. Chương trình cho chữ ký `y = 11`. Bấm **Kiểm tra** để xem kết quả hợp lệ.
4. Chọn **Có băm**, nhập thông điệp rồi ký lại để xem SHA-256 và giá trị băm thu nhỏ trong các ô riêng.

Ví dụ mặc định dùng `p = 17`, `q = 11`, `e = 7`; từ đó tính được `n = 187`, `φ(n) = 160`, `a = d = 23`.

### Ký và phát hiện dữ liệu bị sửa

1. Mở tab **Ký & Kiểm tra**. Dùng khóa mẫu được nạp sẵn hoặc bấm **Sinh khoá mới**.
2. Nhập văn bản hoặc chọn tệp, chọn lược đồ rồi bấm **Ký**.
3. Bấm **Dùng thông điệp + chữ ký vừa ký**, sau đó bấm **Kiểm tra**.
4. Bấm **Phương lật 1 bit thông điệp** hoặc **Phương lật 1 bit chữ ký**, rồi kiểm tra lại để thấy chữ ký không còn hợp lệ.

Có thể lưu chữ ký ra tệp `*.sig.json` và mở lại để kiểm tra cùng thông điệp gốc.

### Ký rồi mã hóa

1. Chuẩn bị khóa ký của Trang tại tab **Ký & Kiểm tra**.
2. Chuyển sang tab **Ký rồi mã hoá**, dùng khóa mẫu của Thủy hoặc sinh/mở khóa Thủy.
3. Nhập thông điệp, bấm **Ký rồi mã hoá** → **Giải mã z** → **Kiểm tra chữ ký**.

Trang ký bằng khóa bí mật của mình và mã hóa bằng khóa công khai của Thủy. Thủy giải mã bằng khóa bí mật của mình rồi kiểm tra chữ ký bằng khóa công khai của Trang.

Bản mã có thể lưu/mở dưới dạng `*.enc.json`. Nếu sinh khóa Thủy mới, hãy lưu khóa để có thể giải mã lại sau này.

Tab này dùng RSA-OAEP/SHA-256 chia khối, giới hạn thông điệp **16 KiB**. Đây là định dạng phục vụ demo của dự án. Với tệp lớn hơn, dùng tab **Ký & Kiểm tra** để ký tệp.

## 4. Chạy bằng dòng lệnh

Các lệnh dưới đây dùng khi đã kích hoạt môi trường `.venv`. Trên Windows, có thể thay `python` bằng `.\.venv\Scripts\python.exe`.

```bash
# Mở menu dòng lệnh
python -m demo.cli

# Xem ví dụ Tiny RSA
python -m demo.cli tiny --h 88

# Chạy tất cả mô phỏng tấn công
python -m demo.run_all_attacks

# Chạy tất cả kịch bản
python -m demo.cli scenario all

# Đo hiệu năng nhanh
python -m demo.benchmark --quick
```

Xem thêm các lệnh và tham số bằng `python -m demo.cli --help`.

## 5. Kiểm thử

```bash
# Các kiểm thử theo yêu cầu đề tài
python -m pytest test/required -v

# Toàn bộ kiểm thử
python -m pytest

# In bảng đối chiếu kết quả
python -m test.report
```

Bộ kiểm thử gồm ví dụ RSA số nhỏ, SHA-256, ký và kiểm tra chữ ký, mã hóa/giải mã, các trường hợp dữ liệu bị sửa và đối chiếu với thư viện `cryptography`.

## 6. Mã nguồn nằm ở đâu?

| Đường dẫn | Nội dung |
| --- | --- |
| `core/` | Các phép toán, SHA-256, sinh khóa RSA, ký, kiểm tra và mã hóa/giải mã. |
| `demo/gui/` | Giao diện ứng dụng. |
| `demo/cli.py` | Giao diện dòng lệnh. |
| `pki/` | Chứng chỉ, CA, thu hồi chứng chỉ và dấu thời gian. |
| `attacks/` | Các mô phỏng tấn công A1–A8. |
| `scenarios/` | Các kịch bản S1–S6. |
| `test/` | Bộ kiểm thử và dữ liệu đối chiếu. |
| `sample/` | Khóa, thông điệp, ảnh, chứng chỉ và chữ ký mẫu. |
| `docs/` | Báo cáo, sơ đồ và tài liệu của nhóm. |

Một số file thường cần chỉnh:

- **Bố cục và giá trị mặc định của Tiny RSA:** `demo/gui/tabs/tiny_tab.py` (`CLASS_EXAMPLE`).
- **Phép tính Tiny RSA:** `core/tiny_rsa.py`.
- **Hiển thị từng bước và các ô băm:** `demo/gui/widgets/step_view.py`.
- **Nội dung ghi lại từng bước:** `core/step_logger.py`.
- **Tên và thứ tự các tab:** `demo/gui/main_window.py`.
- **Tab ký và kiểm tra:** `demo/gui/tabs/sign_verify_tab.py`.
- **Tab ký rồi mã hóa:** `demo/gui/tabs/sign_encrypt_tab.py`.

## 7. Phạm vi của đồ án

Nhóm tự cài đặt phần tính toán RSA, SHA-256, PKCS#1 v1.5 và RSA-OAEP bằng Python. `PySide6` dùng để tạo giao diện; `pytest` và `pytest-qt` dùng để kiểm thử. Thư viện `cryptography` dùng để đối chiếu trong kiểm thử và thực hiện AES-GCM trong kịch bản S6.

Dự án phục vụ học tập và minh họa. Khóa mẫu trong `sample/keys/` là khóa demo; khóa bí mật lưu ở dạng không mã hóa, không dùng cho dữ liệu thực tế.

Tài liệu về việc sử dụng AI: [docs/ai_usage.md](docs/ai_usage.md).
