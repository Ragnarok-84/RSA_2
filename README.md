# Hệ chữ ký điện tử RSA: ký trên giá trị băm, chứng thực, chống chối bỏ và bảo mật

Bài tập nhóm môn **An toàn và bảo mật thông tin**, đề tài Nhóm C: *Hệ chữ ký điện tử RSA*.

Toàn bộ phần lõi do nhóm tự cài, gồm SHA-256, HMAC, PBKDF2, Euclid mở rộng, thuật toán bình phương và nhân,
Miller–Rabin, sinh khoá, đệm PKCS#1 v1.5 / PSS / OAEP, chữ ký RSA, CA/CRL/TSA và mã hoá lai.
Các thư mục `core/`, `pki/`, `attacks/`, `scenarios/`, `demo/` **không import** `hashlib`, `hmac`,
`cryptography` hay `openssl`. Test `TestNoForbiddenLibraries` tự động kiểm tra điều này. Thư viện chuẩn chỉ
được dùng trong `tests/` để đối chiếu kết quả.

## Cài đặt

Yêu cầu: Python **3.9 trở lên**. Phần chính (CLI, GUI, kịch bản, bộ test) **không cần cài thư viện nào**.
Thư viện `cryptography` là tuỳ chọn, chỉ dùng để đối chiếu kết quả với thư viện chuẩn và chứng thư X.509 thật.

### Windows

1. Cài Python từ <https://www.python.org/downloads/>. Khi cài, **tích ô "Add python.exe to PATH"**.
   Bộ cài này đã có sẵn Tkinter cho giao diện đồ hoạ.
2. Mở **PowerShell** hoặc **Command Prompt** trong thư mục dự án và kiểm tra:

   ```powershell
   python --version
   python -c "import tkinter; print('Tkinter OK')"
   ```

3. (Tuỳ chọn) Tạo môi trường ảo và cài `cryptography`:

   ```powershell
   python -m venv .venv
   .venv\Scripts\activate
   pip install cryptography
   ```

   Nếu PowerShell báo lỗi "running scripts is disabled", chạy lệnh
   `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` một lần, rồi kích hoạt lại.

### macOS

1. Cài Python bằng **một trong hai** cách sau:
   * **Bộ cài chính thức** từ <https://www.python.org/downloads/macos/> (khuyến nghị). Bộ cài này có sẵn
     Tkinter. Sau khi cài, mở thư mục `/Applications/Python 3.x` và chạy `Install Certificates.command` một lần.
   * **Homebrew**: `brew install python python-tk`. Gói `python-tk` bắt buộc phải có thì GUI mới chạy được.

   Không nên dùng `/usr/bin/python3` đi kèm Xcode Command Line Tools: bản này dùng Tk 8.5 đã cũ nên GUI
   có thể hiển thị sai.
2. Mở **Terminal**, chuyển vào thư mục dự án và kiểm tra. Trên macOS lệnh là `python3`, không phải `python`:

   ```bash
   cd ~/Downloads/NH-M-11-ATBMTT        # đường dẫn tới thư mục dự án của bạn
   python3 --version
   python3 -c "import tkinter; print('Tkinter OK', tkinter.TkVersion)"
   ```

3. (Tuỳ chọn) Tạo môi trường ảo và cài `cryptography`:

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install cryptography
   ```

   Sau khi kích hoạt môi trường ảo, gõ `python` hay `python3` đều được.

### Linux (Ubuntu/Debian)

```bash
sudo apt install python3 python3-tk python3-venv
python3 -m venv .venv && source .venv/bin/activate
pip install cryptography        # tuỳ chọn
```

## Chạy chương trình (luôn chạy từ thư mục gốc dự án)

Các lệnh bên dưới viết `python`. Trên **macOS/Linux**, thay bằng **`python3`** nếu chưa kích hoạt môi trường
ảo, ví dụ `python3 demo/gui.py`.

| Lệnh | Chức năng |
|---|---|
| `python demo/gui.py` | **Giao diện đồ hoạ** (Tkinter có sẵn trong Python, 6 tab) |
| `python demo/cli.py` | Menu demo dạng dòng lệnh (23 chức năng) |
| `python core/rsa_mini.py` | Ví dụ tính tay p=17, q=11, e=7, M=88, in từng bước |
| `python scenarios/run_all.py` | Chạy kịch bản S1–S6 và in bảng tổng kết (thêm `--real` để dùng khoá 2048 bit) |
| `python -m unittest discover -s tests -v` | Bộ kiểm thử 85 ca (xem cách bật khoá 2048 bit bên dưới) |
| `python tests/doi_chieu.py` | Đối chiếu với test vector NIST/RFC và thư viện chuẩn |
| `python demo/benchmark.py` | Đo thời gian theo kích thước khoá và kích thước dữ liệu |
| `python demo/avalanche.py` | Hiệu ứng thác lũ: lý do ký trên giá trị băm |
| `python demo/file_signer.py demo` | Ký, ký rồi mã hoá, rồi giải mã tệp ảnh mẫu |

Chạy bộ test với khoá thực tế 2048 bit (chậm hơn, khoảng 2–3 phút):

```bash
# macOS / Linux
REAL=1 python3 -m unittest discover -s tests -v
```

```powershell
# Windows PowerShell
$env:REAL = "1"; python -m unittest discover -s tests -v; Remove-Item Env:REAL
```

### Làm việc với tệp thật bằng dòng lệnh

```bash
python demo/file_signer.py keygen --name alice --bits 2048                      # khoá KÝ của Alice
python demo/file_signer.py keygen --name bob --bits 2048 --usage encryption     # khoá MÃ HOÁ của Bob
python demo/file_signer.py keygen --name carol --bits 2048 --password           # khoá riêng có mật khẩu

python demo/file_signer.py sign   samples/hop_dong.txt --key alice.private.json
python demo/file_signer.py verify samples/hop_dong.txt --pub alice.public.json

python demo/file_signer.py seal samples/anh_mau.png --key alice.private.json --to bob.public.json
python demo/file_signer.py open samples/anh_mau.png.enc.json --key bob.private.json --sender alice.public.json --out nhan/
```

## Cấu trúc mã nguồn và ánh xạ với báo cáo

Các tệp đánh dấu *(bổ sung)* không có trong thiết kế ban đầu. Nhóm thêm chúng để đáp ứng nhận xét của
giảng viên về tính bảo mật, và các yêu cầu của đề về dữ liệu thật và đối chiếu chuẩn.

| Thư mục | File | Chương / mục báo cáo |
|---|---|---|
| `core/` | `rsa_math.py` | 2.6 (số học nền tảng), 3.2 (sinh khoá) |
| `core/` | `sha256.py` | 3.3 (SHA-256), 2.5 |
| `core/` | `padding.py` | 3.4 (PKCS#1 v1.5, PSS); OAEP cho phần bảo mật |
| `core/` | `rsa_full.py` | 2.2 (bộ năm P, A, K, S, V), 3.2 (sinh khoá, ký, kiểm tra); mã hoá OAEP |
| `core/` | `rsa_mini.py` | 3.5 (ví dụ tính tay), kèm ví dụ ký rồi mã hoá |
| `core/` | `hmac_utils.py` *(bổ sung)* | 4.3 (đối chiếu HMAC trong S2), mã hoá lai, PBKDF2 |
| `core/` | `secure_message.py` *(bổ sung)* | Tính bảo mật: ký rồi mã hoá theo kiểu mã hoá lai |
| `pki/` | `cert.py` | 4.2 (chứng thực), 4.3 (không chối bỏ) |
| `pki/` | `crl.py` | 4.4 (khoá bị lộ, thu hồi) |
| `pki/` | `timestamp.py` | 4.4 (dấu thời gian), 4.5 (nonce) |
| `attacks/` | `forgery_no_padding.py`: giả mạo khi không có đệm | 3.6 (an toàn), 6.4 (tấn công minh hoạ) |
| `attacks/` | `small_n.py`: phân tích n nhỏ | 3.6, 6.4 |
| `attacks/` | `bleichenbacher_e3.py`: kiểu Bleichenbacher (e = 3) | 3.6, 6.4 |
| `attacks/` | `confidentiality.py` *(bổ sung)* | Tính bảo mật: từ điển, ký song song mã hoá, Håstad, dùng chung khoá |
| `scenarios/` | `s1_authentication.py` | 4.2, 4.7, 6.5 |
| `scenarios/` | `s2_nonrepudiation.py` (gồm đối chiếu HMAC) | 4.3, 4.7, 6.5 |
| `scenarios/` | `s3_revocation.py` (CRL, khoá bị lộ, hết hạn, TSA) | 4.4, 4.7, 6.5 |
| `scenarios/` | `s4_replay.py` | 4.5, 4.7, 6.5 |
| `scenarios/` | `s5_key_substitution.py` | 4.2, 4.7, 6.5 |
| `scenarios/` | `s6_confidentiality.py` *(bổ sung)* | Tính bảo mật, 4.7, 6.5 |
| `scenarios/` | `run_all.py` | 4.7, 6.5 |
| `demo/` | `cli.py`, `gui.py` | 6.1 (kịch bản demo), 6.2 (dữ liệu thật) |
| `demo/` | `benchmark.py` | 6.3 (đo thời gian) |
| `demo/` | `avalanche.py` | 2.5 (lý do ký trên giá trị băm) |
| `demo/` | `file_signer.py` *(bổ sung)* | 6.2 (ký và mã hoá tệp ảnh / văn bản thật) |
| `tests/` | `test_sha256.py` | 5.4 (bộ kiểm thử), 3.3 |
| `tests/` | `test_rsa_math.py` | 5.4, 2.6 |
| `tests/` | `test_padding.py` | 5.4, 3.4 |
| `tests/` | `test_rsa_full.py` | 5.4, 3.2 |
| `tests/` | `test_pki.py` | 5.4, 4.4 |
| `tests/` | `test_attacks.py`, `test_scenarios.py`, `test_confidentiality.py`, `test_gui.py` *(bổ sung)* | 5.4, 6.1, 6.4, 6.5 |
| `tests/` | `doi_chieu.py`, `doi_chieu_x509.py` *(bổ sung)* | 5.4 (đối chiếu NIST/RFC/thư viện chuẩn) |

Thư mục khác: `samples/` chứa tệp mẫu cho demo (hợp đồng `.txt`, ảnh `.png`). `docs/PHAN_TICH_BAO_MAT.md`
là tư liệu phân tích độ an toàn để đưa vào báo cáo.

### Giao diện đồ hoạ (`demo/gui.py`)

| Tab | Nội dung |
|---|---|
| 1. Khoá | Sinh khoá cho Alice (người ký), Bob (người nhận), Eve (kẻ tấn công), Charlie; chọn độ dài hoặc tự nhập p, q, e; lưu/nạp khoá JSON (có thể đặt mật khẩu) |
| 2. Ký & Kiểm tra | Ký văn bản hoặc tệp bằng PKCS#1 v1.5 / PSS, hiện SHA-256, khối đệm EM, chữ ký S. Bên nhận sửa nội dung, sửa chữ ký, đổi 1 bit tệp hoặc thử khoá của Eve rồi kiểm tra (kết quả hiện màu xanh/đỏ) |
| 3. Bảo mật | So sánh chỉ ký với ký rồi mã hoá; xem gói tin Eve nhìn thấy; Bob mở; Eve mở, sửa bản mã, giả thư; Bob chuyển tiếp lén cho Charlie; lưu tệp đã giải mã |
| 4. Tính tay | Nhập p, q, e, M, in từng bước Euclid mở rộng và bình phương-và-nhân; ví dụ trên lớp đầy đủ |
| 5. Kịch bản & Tấn công | Chạy S1–S6, chạy tất cả, 7 tấn công minh hoạ |
| 6. Kiểm thử & Đánh giá | Đối chiếu chuẩn, hiệu ứng thác lũ, benchmark, bộ test |

Các tác vụ nặng chạy ở luồng nền nên giao diện không bị đơ. Giao diện chỉ gọi các module thuật toán, không
chứa thuật toán.

### Menu demo (`demo/cli.py`)

| Nhóm | Mục |
|---|---|
| Thuật toán và dữ liệu thật | 1. RSA thu nhỏ tính tay · 2. Tự nhập thông điệp và khoá để ký/kiểm tra (PKCS#1 v1.5 hoặc PSS) · 3. Hiệu ứng thác lũ · 4. Ký tệp · 5. Ký rồi mã hoá một thông điệp · 6. Ký rồi mã hoá tệp |
| Kịch bản | 7. S1 · 8. S2 · 9. S3 · 10. S4 · 11. S5 · 12. S6 · 13. Chạy tất cả |
| Tấn công vào chữ ký | 14. N nhỏ · 15. Không đệm · 16. Bleichenbacher e=3 |
| Tấn công vào tính bảo mật | 17. Từ điển · 18. Ký song song mã hoá · 19. Håstad · 20. Dùng chung khoá |
| Kiểm thử | 21. Đối chiếu · 22. Benchmark · 23. Bộ test |

## Đối chiếu với yêu cầu của đề

| Yêu cầu | Nơi đáp ứng |
|---|---|
| Phiên bản thu nhỏ khớp ví dụ trên lớp, in bước trung gian | `core/rsa_mini.py`, menu 1–2; `tests/test_rsa_full.py::TestRsaMini` |
| Có đủ ký và kiểm tra chữ ký | `core/rsa_full.py` (PKCS#1 v1.5 và PSS) |
| Ít nhất 3 ca kiểm thử tự viết + test vector chuẩn | `tests/` (85 ca), `tests/doi_chieu.py` (NIST, RFC 4231, thư viện) |
| Demo trên dữ liệu thật | menu 4 và 6, `demo/file_signer.py`, `samples/` |
| Đo thời gian theo kích thước dữ liệu | `demo/benchmark.py` |
| Minh hoạ tấn công | `attacks/`, menu 14–20 |
| Phân tích tính chứng thực, chống chối bỏ | S1–S5 |
| **Phân tích tính bảo mật** (theo nhận xét của thầy) | S6, `core/secure_message.py`, OAEP, menu 5/6/12/17–20, `docs/PHAN_TICH_BAO_MAT.md` |

## Xử lý lỗi thường gặp

| Hiện tượng | Hệ điều hành | Cách xử lý |
|---|---|---|
| `python: command not found` | macOS / Linux | Dùng `python3` thay cho `python` |
| `'python' is not recognized...` | Windows | Cài lại Python và tích "Add python.exe to PATH", hoặc dùng lệnh `py` thay cho `python` |
| `ModuleNotFoundError: No module named '_tkinter'` | macOS (Homebrew) | `brew install python-tk` |
| `ModuleNotFoundError: No module named '_tkinter'` | Linux | `sudo apt install python3-tk` |
| Cửa sổ GUI trống hoặc lỗi giao diện, có cảnh báo "Tk 8.5 deprecated" | macOS | Đang dùng Python của hệ thống; cài Python từ python.org hoặc Homebrew như hướng dẫn ở trên |
| `ModuleNotFoundError: No module named 'core'` | Mọi hệ điều hành | Phải chạy lệnh từ **thư mục gốc** của dự án (thư mục chứa `README.md`) |
| Chữ tiếng Việt bị lỗi trong cửa sổ dòng lệnh | Windows | Dùng Windows Terminal, hoặc chạy `chcp 65001` trước |
| 3 ca test báo `skipped` | Mọi hệ điều hành | Bình thường: các ca này chỉ chạy khi đã cài `cryptography` |

## Sử dụng công cụ AI

Theo quy định của môn học, nhóm ghi rõ: đã dùng Claude Code (Anthropic) để sắp xếp mã nguồn theo thiết kế
của nhóm, bổ sung phần tính bảo mật (OAEP, mã hoá lai, kịch bản S6, các tấn công trong
`attacks/confidentiality.py`), cài PSS, viết bộ test và tài liệu phân tích.
*(Nhóm cần rà soát lại, bổ sung phần việc cụ thể của từng thành viên, và đảm bảo mọi thành viên giải thích
được toàn bộ mã nguồn khi bảo vệ.)*
