# Hệ chữ ký điện tử RSA: ký trên giá trị băm, chứng thực, chống chối bỏ và bảo mật

Bài tập nhóm môn **An toàn và bảo mật thông tin**, đề tài Nhóm C: *Hệ chữ ký điện tử RSA*.

Toàn bộ phần lõi do nhóm tự cài, gồm SHA-256, HMAC, PBKDF2, Euclid mở rộng, thuật toán bình phương và nhân,
Miller–Rabin, sinh khoá, đệm PKCS#1 v1.5 / PSS / OAEP, chữ ký RSA, CA/CRL/TSA và mã hoá lai.
Các thư mục `core/`, `pki/`, `attacks/`, `scenarios/`, `demo/` **không import** `hashlib`, `hmac`,
`cryptography` hay `openssl`. Test `TestNoForbiddenLibraries` tự động kiểm tra điều này. Thư viện chuẩn chỉ
được dùng trong `tests/` để đối chiếu kết quả.

## Cài đặt

Yêu cầu: Python **3.9 trở lên** (đã thử trên 3.12 và 3.13).

### Thư viện sử dụng

Toàn bộ thuật toán (RSA, SHA-256, HMAC, đệm, CA/CRL/TSA, mã hoá lai) chỉ dùng **thư viện chuẩn của Python**
(`secrets`, `json`, `os`, `datetime`…). Bộ test chỉ dùng `unittest` có sẵn.

Môi trường ảo chỉ cài thêm **một thư viện giao diện**, liệt kê trong `requirements-gui.txt`:

| Thư viện | Dùng để | Không cài thì sao |
| --- | --- | --- |
| `PySide6-Essentials` (Qt 6) | Vẽ giao diện đồ hoạ `demo/gui/`: cửa sổ, tab, nút, ảnh nền | Không mở được GUI; CLI, kịch bản, tấn công và bộ test vẫn chạy đủ |

PySide6 không tham gia vào bất kỳ phép tính mật mã nào; giao diện chỉ gọi các hàm trong `core/`, `pki/`,
`scenarios/`, `attacks/`. Nhóm dùng Qt để giao diện hiển thị giống nhau trên Windows và macOS (tự xử lý DPI,
màn hình Retina, nền bán trong suốt).

Thư viện `cryptography` **không nằm trong môi trường mặc định**. Nó chỉ được dùng trong
`tests/cross_check.py` và `tests/cross_check_x509.py` để so sánh kết quả của nhóm với một thư viện chuẩn. Khi chưa
cài, 3 ca test đối chiếu sẽ báo `skipped`. Muốn chạy phần đối chiếu thì cài riêng: `pip install cryptography`.

### Windows

1. Cài Python từ <https://www.python.org/downloads/>. Khi cài, **tích ô "Add python.exe to PATH"**.
2. Mở **PowerShell** trong thư mục dự án, tạo môi trường ảo và cài thư viện:

   ```powershell
   python -m venv .venv
   .venv\Scripts\Activate.ps1
   python -m pip install --upgrade pip
   pip install -r requirements-gui.txt
   ```

   Nếu PowerShell báo lỗi "running scripts is disabled", chạy lệnh sau một lần rồi kích hoạt lại:
   `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`. Nếu dùng **Command Prompt** (cmd) thì lệnh
   kích hoạt là `.venv\Scripts\activate.bat`.

   Nếu lệnh `python` không có, thay bằng `py`, ví dụ `py -m venv .venv`.
3. Kiểm tra:

   ```powershell
   python -c "import PySide6; print('PySide6', PySide6.__version__)"
   ```

### macOS

1. Cài Python bằng **một trong hai** cách sau:
   * **Bộ cài chính thức** từ <https://www.python.org/downloads/macos/> (khuyến nghị). Sau khi cài, mở thư mục
     `/Applications/Python 3.x` và chạy `Install Certificates.command` một lần.
   * **Homebrew**: `brew install python`.
2. Mở **Terminal** trong thư mục dự án, tạo môi trường ảo và cài thư viện. Trên macOS lệnh là `python3`:

   ```bash
   cd ~/Downloads/NH-M-11-ATBMTT        # đường dẫn tới thư mục dự án của bạn
   python3 -m venv .venv
   source .venv/bin/activate
   python -m pip install --upgrade pip
   pip install -r requirements-gui.txt
   ```

3. Kiểm tra:

   ```bash
   python -c "import PySide6; print('PySide6', PySide6.__version__)"
   ```

### Linux (Ubuntu/Debian)

```bash
sudo apt install python3 python3-venv libxcb-cursor0     # libxcb-cursor0: thư viện hệ thống Qt 6 cần
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-gui.txt
```

### Dùng môi trường ảo

* Mỗi lần mở terminal mới, kích hoạt lại: `.venv\Scripts\Activate.ps1` (Windows) hoặc
  `source .venv/bin/activate` (macOS/Linux). Đầu dòng lệnh sẽ hiện `(.venv)`.
* Thoát môi trường ảo: `deactivate`.
* Không muốn kích hoạt thì gọi thẳng Python trong môi trường ảo, ví dụ
  `.venv\Scripts\python demo/gui/run.py` (Windows) hoặc `.venv/bin/python demo/gui/run.py` (macOS/Linux).
* Thư mục `.venv/` đã nằm trong `.gitignore`. Khi nộp bài hoặc chép sang máy khác, **không chép `.venv/`**;
  máy mới tự tạo lại theo các bước trên.

## Chạy chương trình (luôn chạy từ thư mục gốc dự án)

Các lệnh bên dưới viết `python`. Trên **macOS/Linux**, thay bằng **`python3`** nếu chưa kích hoạt môi trường
ảo, ví dụ `python3 demo/gui/run.py`.

| Lệnh | Chức năng |
| --- | --- |
| `python demo/gui/run.py` | **Giao diện đồ hoạ** (PySide6 / Qt 6, 6 tab; cần kích hoạt `.venv`) |
| `python demo/cli.py` | Menu demo dạng dòng lệnh (30 chức năng) |
| `python core/rsa_mini.py` | Ví dụ tính tay p=17, q=11, e=7, M=88, in từng bước |
| `python scenarios/run_all.py` | Chạy kịch bản S1–S6 và in bảng tổng kết (thêm `--real` để dùng khoá 2048 bit) |
| `python attacks/run_all.py` | Chạy 13 tấn công A1–A13 và in bảng tổng kết (thêm `-q` để chỉ in bảng) |
| `python -m unittest discover -s tests -v` | Bộ kiểm thử 96 ca (xem cách bật khoá 2048 bit bên dưới) |
| `python tests/cross_check.py` | Đối chiếu với test vector NIST/RFC và thư viện chuẩn |
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
python demo/file_signer.py keygen --name thutrang --bits 2048                      # khoá KÝ của Thu Trang
python demo/file_signer.py keygen --name thuthuy --bits 2048 --usage encryption     # khoá MÃ HOÁ của Thu Thủy
python demo/file_signer.py keygen --name carol --bits 2048 --password           # khoá riêng có mật khẩu

python demo/file_signer.py sign   samples/hop_dong.txt --key thutrang.private.json
python demo/file_signer.py verify samples/hop_dong.txt --pub thutrang.public.json

python demo/file_signer.py seal samples/anh_mau.png --key thutrang.private.json --to thuthuy.public.json
python demo/file_signer.py open samples/anh_mau.png.enc.json --key thuthuy.private.json --sender thutrang.public.json --out nhan/
```

## Cấu trúc mã nguồn và ánh xạ với báo cáo

Các tệp đánh dấu *(bổ sung)* không có trong thiết kế ban đầu. Nhóm thêm chúng để đáp ứng nhận xét của
giảng viên về tính bảo mật, và các yêu cầu của đề về dữ liệu thật và đối chiếu chuẩn.

| Thư mục | File | Chương / mục báo cáo |
| --- | --- | --- |
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
| `attacks/` | `forgery_no_padding.py`: giả mạo tồn tại và giả mạo nhân tính khi không có đệm | 3.6 (an toàn), 6.4 (tấn công minh hoạ) |
| `attacks/` | `small_n.py`: phân tích n nhỏ | 3.6, 6.4 |
| `attacks/` | `bleichenbacher_e3.py`: kiểu Bleichenbacher (e = 3) | 3.6, 6.4 |
| `attacks/` | `hash_collision.py` *(bổ sung)*: va chạm băm theo nghịch lý ngày sinh | 2.5, 3.6.2, 6.4 |
| `attacks/` | `weak_keys.py` *(bổ sung)*: Fermat (p ≈ q), chung thừa số (gcd), dùng chung modulus | 3.6.2, 6.4 |
| `attacks/` | `crt_fault.py` *(bổ sung)*: lỗi phần cứng khi ký bằng CRT | 3.6.2, 6.4 |
| `attacks/` | `confidentiality.py` *(bổ sung)* | Tính bảo mật: từ điển, ký song song mã hoá, Håstad, dùng chung khoá |
| `attacks/` | `run_all.py` *(bổ sung)* | 6.4 (bảng tổng kết 13 tấn công) |
| `scenarios/` | `s1_authentication.py` | 4.2, 4.7, 6.5 |
| `scenarios/` | `s2_nonrepudiation.py` (gồm đối chiếu HMAC) | 4.3, 4.7, 6.5 |
| `scenarios/` | `s3_revocation.py` (CRL, khoá bị lộ, hết hạn, TSA, ký lùi ngày, khoảng lộ khoá) | 4.4, 4.7, 6.5 |
| `scenarios/` | `s4_replay.py` | 4.5, 4.7, 6.5 |
| `scenarios/` | `s5_key_substitution.py` | 4.2, 4.7, 6.5 |
| `scenarios/` | `s6_confidentiality.py` *(bổ sung)* | Tính bảo mật, 4.7, 6.5 |
| `scenarios/` | `run_all.py` | 4.7, 6.5 |
| `demo/` | `cli.py`, `gui/` | 6.1 (kịch bản demo), 6.2 (dữ liệu thật) |
| `demo/` | `benchmark.py` | 6.3 (đo thời gian) |
| `demo/` | `avalanche.py` | 2.5 (lý do ký trên giá trị băm) |
| `demo/` | `file_signer.py` *(bổ sung)* | 6.2 (ký và mã hoá tệp ảnh / văn bản thật) |
| `tests/` | `test_sha256.py` | 5.4 (bộ kiểm thử), 3.3 |
| `tests/` | `test_rsa_math.py` | 5.4, 2.6 |
| `tests/` | `test_padding.py` | 5.4, 3.4 |
| `tests/` | `test_rsa_full.py` | 5.4, 3.2 |
| `tests/` | `test_pki.py` | 5.4, 4.4 |
| `tests/` | `test_attacks.py`, `test_scenarios.py`, `test_confidentiality.py`, `test_gui.py` *(bổ sung)* | 5.4, 6.1, 6.4, 6.5 |
| `tests/` | `cross_check.py`, `cross_check_x509.py` *(bổ sung)* | 5.4 (đối chiếu NIST/RFC/thư viện chuẩn) |

Thư mục khác: `samples/` chứa tệp mẫu cho demo (hợp đồng `.txt`, ảnh `.png`). `docs/PHAN_TICH_BAO_MAT.md`
là tư liệu phân tích độ an toàn để đưa vào báo cáo.

## Mô tả chi tiết từng tệp

### `core/`: lõi thuật toán

**`rsa_math.py`**: các thuật toán số học của RSA, tự cài đặt, không dùng thư viện mật mã.

* Euclid, Euclid mở rộng, nghịch đảo modulo.
* Lũy thừa modulo bằng thuật toán bình phương và nhân (có thể in từng bước).
* Kiểm tra số nguyên tố Miller–Rabin, sinh số nguyên tố, sinh cặp khoá RSA.
* So sánh thời gian hằng, chuyển số nguyên ↔ byte (I2OSP/OS2IP), căn bậc ba nguyên.

Nguồn ngẫu nhiên là module `secrets` (CSPRNG của hệ điều hành). Không dùng `random`, vì Mersenne Twister
đoán trước được, dẫn tới lộ p, q.

**`sha256.py`**: hàm băm SHA-256 theo FIPS 180-4.

* `hash_sha256(message)`: băm cả thông điệp một lần, trả về chuỗi hex.
* `SHA256()`: băm theo từng phần (gọi `update` nhiều lần), dùng cho tệp lớn.
* `sha256_bytes(message)`: trả về 32 byte thô, dùng cho HMAC, MGF1, OAEP.

**`padding.py`**: các lược đồ đệm theo RFC 8017, đều dùng SHA-256.

| Lược đồ | Dùng cho | Mục RFC 8017 |
| --- | --- | --- |
| EMSA-PKCS1-v1_5 | chữ ký, tất định | 9.2 |
| EMSA-PSS | chữ ký, ngẫu nhiên hoá; có chứng minh an toàn chặt (Bellare–Rogaway 1996) | 9.1 |
| EME-OAEP | mã hoá, ngẫu nhiên hoá (phần tính bảo mật) | 7.1 |
| MGF1 | hàm sinh mặt nạ | phụ lục B.2.1 |

Lý do cần đệm: RSA thô S = M^d có tính đồng cấu (S1·S2 là chữ ký của M1·M2) và tất định. Đệm biến giá trị
băm thành một khối có cấu trúc cố định, chiếm gần hết N bit, nên phá được các tính chất đó.

**`rsa_full.py`**: hệ chữ ký RSA bản đầy đủ (khoá ≥ 2048 bit), ký trên giá trị băm SHA-256.

| Thành phần | Định nghĩa |
| --- | --- |
| P | tập thông điệp: chuỗi byte bất kỳ, độ dài tuỳ ý (vì ký trên SHA-256(M)) |
| A | tập chữ ký = Z_N |
| K | tập khoá = {(N, e, d) : N = p·q, e·d ≡ 1 mod φ(N)}, sinh bởi `generate_keypair` |
| S | Sig_d(M) = Pad(SHA256(M))^d mod N |
| V | Ver_e(M, S) = True ⇔ S^e mod N là khối đệm hợp lệ của SHA256(M) |

Hỗ trợ hai lược đồ đệm: `pkcs1v15` (mặc định, tất định) và `pss` (ngẫu nhiên hoá). Có thêm mã hoá / giải mã
RSA-OAEP cho tính bảo mật, vì bản thân chữ ký không che giấu nội dung.

**`rsa_mini.py`**: bản thu nhỏ để tính tay, dùng bộ số trên lớp p = 17, q = 11, e = 7, M = 88.

* Phần 1: sinh khoá, mã hoá / giải mã, ký / kiểm tra trực tiếp trên M (RSA sách giáo khoa).
* Phần 2: ký trên giá trị băm h = SHA256(M) mod N.
* Phần 3: tính bảo mật. Thu Trang ký rồi mã hoá gửi Thu Thủy (khoá của Thu Thủy: p = 23, q = 29, e = 3).

Mỗi phép lũy thừa đều in các bước bình phương và nhân để đối chiếu với bài tính tay.

**`hmac_utils.py`**: HMAC-SHA256, dùng để đối chiếu trong kịch bản S2 và trong mã hoá lai; PBKDF2.

**`secure_message.py`**: kết hợp chữ ký số với mã hoá theo kiểu "ký rồi mã hoá" (sign-then-encrypt), mô hình
mã hoá lai.

| Người gửi (Thu Trang) | Người nhận (Thu Thủy) |
| --- | --- |
| 1. meta = {from, to, tên tệp, SHA256(M), time}; S = Sign_dA(meta) | |
| 2. inner = meta ‖ S ‖ M | |
| 3. K ngẫu nhiên 32 byte (khoá phiên) | |
| ct = inner XOR KeyStream(K_enc, nonce) | 4. K = OAEP-Decrypt_dB(ek) (chỉ Thu Thủy làm được) |
| tag = HMAC(K_mac, nonce ‖ ct) | 5. Kiểm tra tag (phát hiện sửa bản mã) |
| ek = OAEP-Encrypt_eB(K) | 6. Giải mã ct → inner, kiểm tra meta.to = Thu Thủy |
| | 7. Verify_eA(meta, S) và SHA256(M) = meta.sha256 |

Cách làm này đạt cả 4 tính chất:

* **Bảo mật**: chỉ người giữ dB mới lấy được K để đọc M; kẻ nghe lén chỉ thấy bản mã.
* **Toàn vẹn**: HMAC trên bản mã, và SHA-256 của M nằm trong phần được ký.
* **Chứng thực**: chữ ký RSA của Thu Trang, khoá công khai lấy từ chứng thư CA.
* **Chống chối bỏ**: Thu Thủy giữ (meta, S) làm bằng chứng; chỉ Thu Trang có dA để tạo S.

Vì sao chọn "ký rồi mã hoá":

* *Mã hoá rồi ký*: chữ ký nằm ngoài, Mai Phương gỡ chữ ký của Thu Trang rồi ký lại bằng khoá của mình, Thu
  Thủy tưởng thư là của Mai Phương. Trọng tài cũng không xem được nội dung đã ký.
* *Ký song song với mã hoá* (Enc(M) ‖ Sign(M)): chữ ký làm lộ SHA256(M), Mai Phương đoán được M nếu M thuộc
  một tập nhỏ.
* *Ký rồi mã hoá kiểu ngây thơ* (không ghi người nhận vào phần ký): Thu Thủy giải mã rồi mã hoá lại gửi Tuyết
  Linh, Tuyết Linh tưởng Thu Trang viết cho mình (surreptitious forwarding, Davis 2001). Vì vậy trường `to`
  phải nằm trong phần được ký như ở bước 1.

Phần mã hoá đối xứng sinh dòng khoá bằng SHA-256 ở chế độ đếm (giống CTR):
block_i = SHA256(K_enc ‖ nonce ‖ i), ct = pt XOR (block_0 ‖ block_1 ‖ …), kết hợp HMAC-SHA256 theo kiểu
Encrypt-then-MAC. Hệ thống thực tế dùng AES-GCM; nhóm tự cài bằng SHA-256 để không phụ thuộc thư viện và vì
đề tài tập trung vào RSA.

### `pki/`: hạ tầng khoá công khai

**`cert.py`**: chứng thư số và tổ chức chứng thực (CA), xây trên `core/rsa_full.py`.

* `CertificateAuthority`: cấp chứng thư (gắn danh tính với khoá công khai) và thu hồi chứng thư.
* `verify_certificate`: kiểm tra bên cấp, chữ ký CA, thời hạn, danh sách thu hồi, mục đích sử dụng khoá.

Chứng thư có trường `key_usage` (`signature` hoặc `encryption`): mỗi cặp khoá chỉ dùng cho một mục đích. Nếu
dùng chung khoá ký và khoá giải mã, việc "nhờ ký" một bản mã chính là giải mã hộ kẻ tấn công (xem
`attacks/confidentiality.py`).

**`crl.py`**: danh sách chứng thư bị thu hồi (CRL).

* Mỗi mục ghi số serial, thời điểm thu hồi và lý do.
* Ghi thời điểm để phân biệt chữ ký tạo *trước* khi lộ khoá (vẫn có giá trị nếu có dấu thời gian) với chữ ký
  tạo *sau* khi lộ khoá (bị từ chối).
* CA ký lên bản CRL công bố, để kẻ tấn công không xoá được mục thu hồi trên đường truyền.

**`timestamp.py`**: dấu thời gian và nonce.

* `TimestampAuthority`: TSA ký lên cặp (SHA256(chữ ký), thời điểm), làm bằng chứng chữ ký đã tồn tại tại thời
  điểm đó. Nhờ vậy chữ ký vẫn có giá trị sau khi chứng thư hết hạn hoặc bị thu hồi, nếu được tạo trước thời
  điểm thu hồi.
* `NonceRegistry`: phát nonce ngẫu nhiên, dùng một lần, có hạn dùng; gói tin đã ký bị phát lại sẽ bị từ chối.

### `attacks/`: tấn công minh hoạ

| Tệp | Nội dung | Biện pháp chặn |
| --- | --- | --- |
| `small_n.py` | Phân tích thừa số N nhỏ. Biết p, q thì tính lại φ(N) và d, ký giả được mọi văn bản | Khoá ≥ 2048 bit |
| `forgery_no_padding.py` | Không có đệm: giả mạo nhân tính (S1·S2 là chữ ký của M1·M2) và giả mạo tồn tại (chọn S, tính M = S^e mod N) | Đệm PKCS#1 v1.5 / PSS |
| `bleichenbacher_e3.py` | Kiểu Bleichenbacher 2006 với e = 3: bộ kiểm tra lỏng chỉ đọc `00 01 FF.. 00 DigestInfo H` rồi bỏ qua phần sau. Kẻ tấn công dựng `00 01 FF 00 DigestInfo H ‖ rác` và lấy căn bậc ba nguyên s; vì s³ < N nên phần đầu giữ nguyên | Kiểm tra đệm chặt (`parse_em_strict`) |
| `hash_collision.py` | Va chạm băm (Yuval 1979): Mai Phương soạn bản hợp đồng thật và bản gian, mỗi bản nhiều biến thể (1 hay 2 dấu cách). Với hàm băm k bit, nghịch lý ngày sinh cho va chạm sau khoảng 2^(k/2) biến thể. Mô phỏng bằng SHA-256 cắt còn k bit | SHA-256 đủ 256 bit (cần ~2^128 phép băm) |
| `weak_keys.py` | Khoá sinh kém: Fermat (p, q quá gần, N = a² − b²); chung thừa số (gcd(N1, N2) = p, theo Lenstra và Heninger 2012); dùng chung N (biết (e, d) của mình thì phân tích được N) | Sinh p, q độc lập, đủ xa, mỗi người một N |
| `crt_fault.py` | Lỗi phần cứng khi ký bằng CRT (Boneh–DeMillo–Lipton 1997, biến thể Lenstra): nếu s_q bị sai, gcd(S'^e − EM, N) = p. Chỉ một chữ ký lỗi là đủ phân tích N | Tự kiểm tra chữ ký trước khi trả về |
| `confidentiality.py` | (1) Từ điển vào RSA tất định; (2) ký song song mã hoá làm lộ băm; (3) Håstad broadcast (e = 3, cùng bản rõ gửi 3 người); (4) dùng chung khoá ký và giải mã | OAEP; ký rồi mã hoá; tách khoá theo `key_usage` |
| `run_all.py` | Chạy mỗi tấn công hai lần: trên cấu hình yếu (phải phá được) và cấu hình đúng của hệ thống (phải bị chặn), rồi in bảng tổng kết | |

### `scenarios/`: kịch bản tính chất an toàn

| Tệp | Nội dung |
| --- | --- |
| `s1_authentication.py` | Xác thực bằng thách – đáp: server gửi nonce ngẫu nhiên, Thu Trang ký nonce, server kiểm tra bằng khoá trong chứng thư |
| `s2_nonrepudiation.py` | Chống chối bỏ = chữ ký số + chứng thư CA + dấu thời gian TSA. Đối chiếu với HMAC: khoá bí mật dùng chung nên cả hai bên đều tạo được thẻ, không chống chối bỏ được |
| `s3_revocation.py` | A: thu hồi khoá bị mất. B: khoá bị lộ + TSA, chữ ký trước lúc thu hồi vẫn hợp lệ, sửa ngày trong dấu thời gian bị phát hiện. C: chứng thư hết hạn. D: ký lùi ngày, không có TSA thì lọt, có TSA thì bị chặn. E: giới hạn của PKI, chữ ký tạo giữa lúc lộ khoá và lúc thu hồi vẫn được chấp nhận |
| `s4_replay.py` | Chữ ký chỉ chứng minh "đã ký nội dung này", không chứng minh "muốn thực hiện lần này". A: chỉ kiểm tra chữ ký, lệnh bị thực hiện 3 lần. B: lệnh chứa nonce do ngân hàng cấp và thời điểm, lần phát lại bị từ chối; sửa nonce thì chữ ký hỏng |
| `s5_key_substitution.py` | Thay thế khoá công khai (man-in-the-middle): không có chứng thư thì Thu Thủy bị lừa, có chứng thư thì phát hiện |
| `s6_confidentiality.py` | Chữ ký không giữ bí mật nội dung. A: chỉ ký, đọc được toàn bộ. B: ký rồi mã hoá. C: sửa bản mã, HMAC phát hiện. D: giả thư nhân danh Thu Trang, chữ ký chặn. E: chuyển tiếp lén, trường `to` chặn. F: dùng khoá ký để mã hoá, `key_usage` từ chối. Cuối cùng in bảng so sánh chỉ ký / chỉ mã hoá / ký rồi mã hoá |
| `run_all.py` | Chạy lần lượt mọi kịch bản và in bảng tổng kết (`--real` để dùng khoá 2048 bit) |

### `demo/`

* **`avalanche.py`**: vì sao ký trên SHA-256(M) thay vì ký trực tiếp M. (1) Hiệu ứng thác lũ: đổi 1 bit của M
  thì khoảng 50% bit của băm đổi theo. (2) RSA chỉ ký được số < N; ký trực tiếp tệp 88 KB phải chia hàng trăm
  khối, còn ký trên băm chỉ cần 1 phép lũy thừa. (3) Ký từng khối rời cho phép đổi chỗ, xoá, ghép khối.
  (4) Tính đồng cấu của RSA thô bị phá.
* **`benchmark.py`**: đo thời gian theo kích thước khoá và dữ liệu. Mặc định khoá 512/1024 bit, dữ liệu tới
  64 KB; `--real` dùng khoá tới 3072 bit, dữ liệu tới 256 KB.
* **`file_signer.py`**: làm việc với tệp thật. Lưu / nạp khoá dạng JSON; khoá riêng có thể mã hoá bằng mật khẩu
  (PBKDF2 + HMAC). Ký tệp ra `<tệp>.sig.json`; ký rồi mã hoá ra `<tệp>.enc.json`. Cách dùng ở mục
  *Làm việc với tệp thật bằng dòng lệnh*.
* **`cli.py`**, **`gui/`**: chỉ gọi các module trong `core/`, `pki/`, `scenarios/`, `attacks/`, không chứa
  thuật toán. Chi tiết ở hai mục bên dưới.

### `tests/`

* `test_*.py`: bộ kiểm thử `unittest`.
* `cross_check.py`: đối chiếu kết quả với test vector chuẩn (NIST, RFC 4231) và thư viện chuẩn. Các thư viện
  `hashlib`, `hmac`, `cryptography` chỉ được dùng ở đây để so sánh, không dùng trong phần lõi.
* `cross_check_x509.py`: mô phỏng lại tình huống khoá bị lộ và chứng thư hết hạn bằng chứng thư X.509 thật của
  thư viện `cryptography`.

### Giao diện đồ hoạ (`demo/gui/`)

| Tab | Nội dung |
| --- | --- |
| 1. Khoá | Sinh khoá cho Thu Trang (người ký), Thu Thủy (người nhận), Mai Phương (kẻ tấn công), Tuyết Linh; chọn độ dài hoặc tự nhập p, q, e; lưu/nạp khoá JSON (có thể đặt mật khẩu) |
| 2. Ký & Kiểm tra | Ký văn bản hoặc tệp bằng PKCS#1 v1.5 / PSS, hiện SHA-256, khối đệm EM, chữ ký S. Bên nhận sửa nội dung, sửa chữ ký, đổi 1 bit tệp hoặc thử khoá của Mai Phương rồi kiểm tra (kết quả hiện màu xanh/đỏ) |
| 3. Bảo mật | So sánh chỉ ký với ký rồi mã hoá; xem gói tin Mai Phương nhìn thấy; Thu Thủy mở; Mai Phương mở, sửa bản mã, giả thư; Thu Thủy chuyển tiếp lén cho Tuyết Linh; lưu tệp đã giải mã |
| 4. Tính tay | Nhập p, q, e, M, in từng bước Euclid mở rộng và bình phương-và-nhân; ví dụ trên lớp đầy đủ |
| 5. Kịch bản & Tấn công | Chạy S1–S6, chạy tất cả, 13 tấn công minh hoạ và bảng tổng kết |
| 6. Kiểm thử & Đánh giá | Đối chiếu chuẩn, hiệu ứng thác lũ, benchmark, bộ test |

Các tác vụ nặng chạy ở luồng nền nên giao diện không bị đơ. Giao diện chỉ gọi các module thuật toán, không
chứa thuật toán.

Giao diện viết bằng PySide6 (Qt 6), dùng style `Fusion` trên mọi hệ điều hành để Windows và macOS hiển thị
giống nhau. Cỡ chữ tính theo pixel độc lập thiết bị, Qt tự co giãn theo DPI (Windows 125–150%, màn hình
Retina). Ảnh nền phủ toàn cửa sổ; các khung tab, nhóm, bảng và ô nhập có nền bán trong suốt kiểu kính mờ nên
ảnh nền lộ qua. Muốn đổi độ trong suốt hay màu thì sửa `resources/style.qss`, không cần sửa mã Python.

Mã nguồn giao diện trong `demo/gui/`:

| Tệp | Nội dung |
| --- | --- |
| `run.py` | Điểm vào (tạo `QApplication`, đặt style `Fusion`, nạp `style.qss`) và cửa sổ chính: vẽ ảnh nền, 6 tab, thanh trạng thái, chạy tác vụ ở luồng nền |
| `widgets.py` | Hằng số, phông chữ, hộp thoại, hàm tiện ích, ô kết quả tô màu (`OutputBox`), khung chọn văn bản/tệp (`DataSource`) |
| `tabs.py` | 6 tab, mỗi tab một class: `KeyTab`, `SignTab`, `ConfidentialityTab`, `MiniTab`, `ScenarioTab`, `ToolsTab` |
| `resources/style.qss` | Toàn bộ màu sắc, bo góc, độ trong suốt |
| `resources/background.png` | Ảnh nền |

### Menu demo (`demo/cli.py`)

| Nhóm | Mục |
| --- | --- |
| Thuật toán và dữ liệu thật | 1. RSA thu nhỏ tính tay · 2. Tự nhập thông điệp và khoá để ký/kiểm tra (PKCS#1 v1.5 hoặc PSS) · 3. Hiệu ứng thác lũ · 4. Ký tệp · 5. Ký rồi mã hoá một thông điệp · 6. Ký rồi mã hoá tệp |
| Kịch bản | 7. S1 · 8. S2 · 9. S3 · 10. S4 · 11. S5 · 12. S6 · 13. Chạy tất cả |
| Tấn công vào lược đồ ký và hàm băm | 14. N nhỏ · 15. Giả mạo tồn tại · 16. Giả mạo nhân tính · 17. Bleichenbacher e=3 · 18. Va chạm băm |
| Tấn công vào sinh khoá, quản lý khoá, thiết bị ký | 19. Fermat · 20. Chung thừa số · 21. Dùng chung N · 22. Lỗi CRT |
| Tấn công vào tính bảo mật | 23. Từ điển · 24. Ký song song mã hoá · 25. Håstad · 26. Dùng chung khoá · 27. Chạy toàn bộ 13 tấn công |
| Kiểm thử | 28. Đối chiếu · 29. Benchmark · 30. Bộ test |

## Đối chiếu với yêu cầu của đề

| Yêu cầu | Nơi đáp ứng |
| --- | --- |
| Phiên bản thu nhỏ khớp ví dụ trên lớp, in bước trung gian | `core/rsa_mini.py`, menu 1–2; `tests/test_rsa_full.py::TestRsaMini` |
| Có đủ ký và kiểm tra chữ ký | `core/rsa_full.py` (PKCS#1 v1.5 và PSS) |
| Ít nhất 3 ca kiểm thử tự viết + test vector chuẩn | `tests/` (96 ca), `tests/cross_check.py` (NIST, RFC 4231, thư viện) |
| Demo trên dữ liệu thật | menu 4 và 6, `demo/file_signer.py`, `samples/` |
| Đo thời gian theo kích thước dữ liệu | `demo/benchmark.py` |
| Minh hoạ tấn công | `attacks/`, menu 14–27, `python attacks/run_all.py` |
| Phân tích tính chứng thực, chống chối bỏ | S1–S5 |
| **Phân tích tính bảo mật** (theo nhận xét của thầy) | S6, `core/secure_message.py`, OAEP, menu 5/6/12/17–20, `docs/PHAN_TICH_BAO_MAT.md` |

## Xử lý lỗi thường gặp

| Hiện tượng | Hệ điều hành | Cách xử lý |
| --- | --- | --- |
| `python: command not found` | macOS / Linux | Dùng `python3` thay cho `python` |
| `'python' is not recognized...` | Windows | Cài lại Python và tích "Add python.exe to PATH", hoặc dùng lệnh `py` thay cho `python` |
| `ModuleNotFoundError: No module named 'PySide6'` | Mọi hệ điều hành | Chưa kích hoạt `.venv` hoặc chưa cài: `pip install -r requirements-gui.txt` |
| `Could not load the Qt platform plugin "xcb"` | Linux | `sudo apt install libxcb-cursor0` |
| `ModuleNotFoundError: No module named 'core'` | Mọi hệ điều hành | Phải chạy lệnh từ **thư mục gốc** của dự án (thư mục chứa `README.md`) |
| Chữ tiếng Việt bị lỗi trong cửa sổ dòng lệnh | Windows | Dùng Windows Terminal, hoặc chạy `chcp 65001` trước |
| 3 ca test báo `skipped` | Mọi hệ điều hành | Bình thường: các ca này chỉ chạy khi đã cài `cryptography` (test GUI cũng tự bỏ qua nếu chưa cài PySide6) |

## Sử dụng công cụ AI

Theo quy định của môn học, nhóm ghi rõ: đã dùng Claude Code (Anthropic) để sắp xếp mã nguồn theo thiết kế
của nhóm, bổ sung phần tính bảo mật (OAEP, mã hoá lai, kịch bản S6, các tấn công trong
`attacks/confidentiality.py`), cài PSS, viết bộ test và tài liệu phân tích.
*(Nhóm cần rà soát lại, bổ sung phần việc cụ thể của từng thành viên, và đảm bảo mọi thành viên giải thích
được toàn bộ mã nguồn khi bảo vệ.)*
