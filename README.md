# Hệ chữ ký điện tử RSA

**Đề tài:** Hệ chữ ký điện tử RSA — ký trên giá trị băm của thông điệp, kiểm tra chữ ký, phân tích tính chứng
thực và tính không chối bỏ.
**Môn:** An toàn và bảo mật thông tin (CNTT1168) — Nhóm 11.

Toàn bộ phần lõi (`core/`, `pki/`, `attacks/`, `scenarios/`) do nhóm **tự cài đặt bằng thư viện chuẩn Python**:
SHA-256 (FIPS 180-4), Euclid mở rộng, bình phương và nhân, CRT, Miller–Rabin, sinh khoá RSA, EMSA-PKCS1-v1_5
(RFC 8017), chứng chỉ, CA, CRL, dấu thời gian. Lõi **không** import `hashlib`, `hmac`, `cryptography`,
`pycryptodome`, `gmpy2` và không dùng `pow(a, b, n)` built-in; test `test/unit/test_constraints.py` tự kiểm tra
điều này.

Phép ký RSA dùng công thức cơ bản $s = m^d \bmod n$. CRT còn trong `number_theory.py` như một phép toán riêng
cho ví dụ số học; các tham số CRT không nằm trong khóa hay quy trình ký.

* Ngoại lệ duy nhất: `scenarios/s6_sign_then_encrypt.py` dùng AES-GCM của thư viện `cryptography` (phần ngoài
  lõi; RSA-OAEP, MGF1, SHA-256 và chữ ký trong kịch bản này vẫn là code tự viết).
* `test/` là nơi duy nhất dùng `hashlib`, `cryptography`, `pow` built-in để **đối chiếu** kết quả.

Có hai phiên bản: **Tiny** (số nhỏ, in từng bước, tái hiện đúng ví dụ slide $p=17,\ q=11,\ n=187,\ \varphi(n)=160,\ e=7,\ d=23$,
ký $h=88 \Rightarrow s=11$) và **Full** (RSA 2048-bit + SHA-256 + PKCS#1 v1.5).

## Cài đặt

Yêu cầu Python **3.11 trở lên**.

| Thư viện | Dùng để |
| --- | --- |
| `PySide6` | Giao diện đồ hoạ `demo/gui/` (chỉ vẽ giao diện) |
| `pytest`, `pytest-qt` | Bộ kiểm thử |
| `cryptography` | Chỉ trong `test/` (đối chiếu) và AES-GCM của kịch bản S6 |

### Cách nhanh nhất

* **Windows:** nhấp đúp `run_demo.bat`.
* **macOS / Linux:** `./run_demo.sh`.

Script tự tạo `.venv` nếu chưa có, cài `requirements.txt` rồi mở GUI.

### Cài thủ công

**Windows (PowerShell):**

```powershell
py -3 -m venv .venv            # hoặc: python -m venv .venv
.venv\Scripts\Activate.ps1     # cmd: .venv\Scripts\activate.bat
python -m pip install -r requirements.txt
```

Nếu PowerShell báo "running scripts is disabled", chạy một lần
`Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` rồi kích hoạt lại.

**macOS:** cài Python từ <https://www.python.org/downloads/macos/> (khuyến nghị) hoặc `brew install python`.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

**Linux (Ubuntu/Debian):** cần thêm thư viện hệ thống Qt 6: `sudo apt install python3-venv libxcb-cursor0`.

`.venv/` nằm trong `.gitignore`, không chép sang máy khác.

## Chạy chương trình

**Luôn chạy từ thư mục gốc repo** bằng `python -m …`. Thư mục `test/` trùng tên với package `test` của thư viện
chuẩn Python; chạy từ thư mục gốc thì package của repo được ưu tiên.

| Việc | Lệnh |
| --- | --- |
| GUI (demo chính) | `python -m demo.gui` |
| CLI menu số (dự phòng, không cần Qt) | `python -m demo.cli` |
| Tiny RSA từng bước | `python -m demo.cli tiny --h 88` |
| Sinh khoá | `python -m demo.cli keygen --bits 2048 --out sample/keys/my_key.json` |
| Ký tệp | `python -m demo.cli sign --key sample/keys/trang_sign.json --in sample/messages/contract.txt` |
| Kiểm tra chữ ký | `python -m demo.cli verify --in sample/messages/contract.txt --sig sample/signatures/contract.txt.sig.json` |
| Một tấn công / tất cả | `python -m demo.cli attack a4_small_e_attack [--defended]`, `python -m demo.run_all_attacks` |
| Một kịch bản / tất cả | `python -m demo.cli scenario s3_non_repudiation_contract`, `python -m demo.cli scenario all` |
| Benchmark | `python -m demo.benchmark [--quick]` (in kết quả ra màn hình) |
| Sinh lại dữ liệu mẫu | `python -m demo.cli gen-samples` |

### GUI

| Tab | Nội dung |
| --- | --- |
| 1. Tiny RSA | Nhập $p, q, e$ và $h$ hoặc thông điệp; Ký / Kiểm tra; công thức hiển thị bằng Unicode; bảng Euclid mở rộng và bảng bình phương và nhân ($i, b_i, c, f$); có thể hiện từng bước để thuyết trình |
| 2. Ký / Kiểm tra | Sinh khoá 1024/2048/3072 hoặc mở từ `sample/keys`; ký văn bản / tệp (xem trước ảnh) bằng PKCS#1 v1.5; hiện $h$, EM, chữ ký, thời gian; lưu / mở `*.sig.json`; Phương (Attacker) có thể lật 1 bít; kéo-thả tệp |
| 3. PKI | Cây Root CA → Intermediate CA → Trang (Sender) / Thủy (Receiver) (+ TSA); cấp, thu hồi, xem chứng chỉ; Trang ký hợp đồng có dấu thời gian, Linh (Third Party) kiểm tra |
| 4. Tấn công & Kịch bản | Danh sách S1–S6 và A1–A8; ô **Bật biện pháp phòng chống**; kết quả từng bước |
| 5. Benchmark | Chạy các phép đo sinh khoá / ký / kiểm tra theo kích thước khoá và băm theo kích thước tệp; xem kết quả trong bảng |
| 6. Kiểm thử | Chạy các ca kiểm thử và xem kết quả đối chiếu trực tiếp trong bảng |

Tác vụ chậm chạy trong `QThreadPool` nên giao diện không bị treo. Giao diện dùng style Fusion + `style.qss`
(nền kính mờ hồng – vàng), hiển thị giống nhau trên Windows và macOS (tự co giãn theo DPI / Retina).

Trong tab 2, có thể bật **Mã hoá cho Thủy sau khi ký** để minh hoạ
`z = E_public_Thuy(thông điệp + chữ ký)`. Mặc định tuỳ chọn này tắt.
Khoá ký của Trang và khoá mã hoá của Thủy độc lập; demo tự nạp
`sample/keys/thuy_enc.json`. Có thể sinh, mở hoặc lưu khoá Thủy ngay trong tab.
Nếu sinh khoá mới, lưu khoá trước khi đóng ứng dụng để giải mã lại các bản mã đã lưu.

Luồng thao tác: nhập thông điệp → bật mã hoá → **Ký** → **Giải mã z** → **Kiểm tra**.
**Lưu z / Mở z** dùng tệp `*.enc.json`, chứa bản mã của cả thông điệp và chữ ký;
người nhận vẫn cần khoá riêng của Thủy để giải mã và khoá công khai của Trang để kiểm tra.
Sau giải mã, các nút lật bít vẫn minh hoạ việc chữ ký phát hiện sửa đổi dữ liệu.

Phần mã hoá tự cài đặt RSA-OAEP/SHA-256 theo
[RFC 8017, mục 7.1](https://www.rfc-editor.org/rfc/rfc8017.html#section-7.1),
dùng lại SHA-256, MGF1 và bình phương và nhân của dự án, không thêm thư viện chạy.
Thông điệp tối đa **16 KiB**; gói dữ liệu được chia khối OAEP với nhãn ràng buộc mã gói,
thứ tự và số lượng khối. Đây là định dạng nhiều khối riêng phục vụ demo, không phải
định dạng trao đổi chuẩn. Tệp lớn hơn vẫn dùng luồng ký thông thường khi bỏ chọn mã hoá.

Đóng gói thành ứng dụng (tuỳ chọn):
`pyinstaller --windowed -n RSASignatureDemo demo/gui/__main__.py`.

## Kiểm thử cho giảng viên

```bash
python -m pytest test/required -v
```

| File | Đáp ứng yêu cầu |
| --- | --- |
| `test_r1_tiny_slide_examples.py` | Ví dụ tính tay trong slide: `egcd(4864, 3458)`, nghịch đảo modulo, bình phương và nhân, CRT, Tiny $h=88 \Rightarrow s=11$ |
| `test_r2_sha256_nist.py` | Test vector NIST FIPS 180-4 + đối chiếu `hashlib` ở các độ dài biên 55, 56, 63, 64, 65 byte |
| `test_r3_signature_cases.py` | Ca tự viết: thông điệp rỗng, tiếng Việt UTF-8, ảnh `logo.png`; sửa 1 bít thông điệp / chữ ký / sai khoá → FAIL |
| `test_r4_cross_check.py` | Chữ ký PKCS#1 v1.5 **trùng từng byte** với `cryptography`, kiểm tra chéo hai chiều |

Bảng kết quả đối chiếu: tab **6. Kiểm thử** trên GUI, hoặc

```bash
python -m test.report                                      # thêm --slow cho ca 1 000 000 ký tự 'a'
```

Cho nhóm: `python -m pytest -m "not slow"` sau mỗi lần sửa code; `python -m pytest` chạy toàn bộ.

## Người tham gia

- **Trang (Sender):** tạo và gửi thông điệp, ký bằng khoá riêng.
- **Thủy (Receiver):** nhận thông điệp, kiểm tra chữ ký bằng khoá công khai của Trang.
- **Phương (Attacker):** mô phỏng sửa thông điệp, giả mạo hoặc chuyển tiếp trái phép.
- **Linh (Third Party):** người nhận thay thế trong kịch bản chuyển tiếp và bên thứ ba trong ví dụ.

## Cấu trúc thư mục

```text
core/          lõi tự cài: number_theory, primality, rsa_keygen, rsa_primitives, hash/ (sha256, toy_hash),
               padding/ (pkcs1_v15, mgf1), signature, tiny_rsa, key_io, step_logger, utils
pki/           certificate, ca, chain_verify, revocation (CRL), timestamp (TSA)
scenarios/     s1…s6: chứng minh thuộc tính an toàn khi dùng đúng (kỳ vọng valid == True)
attacks/       a1…a8: hệ thống bị phá khi bỏ một thành phần (success == True khi yếu, False khi phòng chống)
test/          required/ (giảng viên chấm), unit/ (test lúc code), vectors/, report.py
demo/          cli.py, benchmark.py, run_all_attacks.py, gui/ (PySide6)
sample/        messages/, images/, keys/ (KHOÁ DEMO), certs/, signatures/
docs/          report/, slides/, diagrams/ (Mermaid), ai_usage.md
```

### Kịch bản ↔ tấn công

| Kịch bản (dùng đúng) | Tấn công tương ứng (bỏ một thành phần) | Thành phần bị bỏ |
| --- | --- | --- |
| `s1_authentication` | `a6_key_substitution_mitm` | PKI / chứng chỉ |
| `s2_integrity_tamper` | `a1_no_hash_forgery`, `a2_existential_forgery`, `a3_hash_collision`, `a4_small_e_attack` | Hash an toàn, padding chuẩn, kiểm tra chặt |
| `s3_non_repudiation_contract` | `a7_replay_attack` | Timestamp / nonce trong phần được ký |
| `s4_key_compromise` | `a5_factorization` | Khoá đủ lớn, thu hồi chứng chỉ và dấu thời gian |
| `s5_hmac_vs_signature` | — | (so sánh với cơ chế khoá đối xứng) |
| `s6_sign_then_encrypt` | `a8_surreptitious_forwarding` | Danh tính người nhận trong phần được ký |

## Định dạng tệp

* **Khoá** (`sample/keys/*.json`): JSON, số nguyên ghi hex. ⚠ **Khoá demo, KHÔNG dùng thật** — khoá riêng lưu
  không mã hoá.
* **Chữ ký** (`*.sig.json`): `version`, `algorithm` = RSA, `scheme` = PKCS1v15, `hash` = SHA-256,
  `message_file`, `message_hash_hex`, `signature_hex`, `signer_certificate`, `timestamp_token`.
* Mọi cấu trúc được ký (chứng chỉ, CRL, phần được ký trong S6, A7) đều serialize chuẩn tắc:
  `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")`.
* So sánh giá trị băm / khối EM dùng `core.utils.constant_time_eq` (thời gian hằng, chống timing attack).

## Phân công

| Thành viên | Phần việc |
| --- | --- |
| Thu Trang | |
| Thu Thủy | |
| Mai Phương | |
| Tuyết Linh | |

## Tham khảo

* NIST FIPS 180-4, *Secure Hash Standard (SHS)*, 2015.
* RFC 8017, *PKCS #1: RSA Cryptography Specifications Version 2.2*, 2016.
* RFC 2104, *HMAC: Keyed-Hashing for Message Authentication*; RFC 4231 (test vector HMAC-SHA-256).
* RFC 3161, *Time-Stamp Protocol (TSP)*; RFC 5280, *X.509 PKI Certificate and CRL Profile*.
* D. Boneh, R. DeMillo, R. Lipton, *On the Importance of Checking Cryptographic Protocols for Faults*, EUROCRYPT 1997.
* D. Bleichenbacher, *Forging some RSA signatures with pencil and paper*, CRYPTO 2006 rump session.
* D. Davis, *Defective Sign & Encrypt in S/MIME, PKCS#7, MOSS, PEM, PGP, and XML*, USENIX 2001.
* NIST SP 800-57 Part 1 Rev. 5, *Recommendation for Key Management*.

## Sử dụng AI

Xem [`docs/ai_usage.md`](docs/ai_usage.md).
