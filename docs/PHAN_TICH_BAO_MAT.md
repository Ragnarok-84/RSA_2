# Phân tích tính bảo mật của hệ chữ ký điện tử RSA

> Tài liệu bổ sung cho báo cáo, chương "Phân tích thuật toán" và "Kết quả demo và đánh giá".
> Mọi con số trong tài liệu này đều chạy lại được bằng chương trình (mục nào có ghi tên tệp hoặc mục menu).

---

## 1. Bốn tính chất an toàn và cơ chế đảm bảo

| Tính chất | Ý nghĩa | Cơ chế trong hệ thống | Kịch bản minh hoạ |
|---|---|---|---|
| **Bảo mật** (Confidentiality) | Chỉ người nhận đọc được nội dung | Mã hoá RSA-OAEP bằng khoá công khai **của người nhận** + mã hoá lai | S6, menu 5, 6, 12 |
| **Toàn vẹn** (Integrity) | Phát hiện mọi sửa đổi | SHA-256 của thông điệp nằm trong phần được ký; HMAC trên bản mã | S2, S6-C, menu 4 |
| **Chứng thực** (Authentication) | Xác định đúng người gửi | Chữ ký RSA bằng khoá riêng của người gửi + chứng thư CA | S1, S5, S6-D |
| **Chống chối bỏ** (Non-repudiation) | Người ký không thể chối | Chỉ người ký có `d`; CA gắn danh tính với khoá; TSA gắn thời điểm | S2, S3 |

**Điểm mấu chốt: chữ ký số không đảm bảo tính bảo mật.**
Khi kiểm tra chữ ký, bên nhận dùng khoá *công khai* của người ký. Ai cũng có khoá đó, nên ai cũng
"mở" được chữ ký. Thông điệp lại được gửi kèm ở dạng rõ. Kịch bản S6-A cho thấy Mai Phương đọc được toàn bộ
nội dung **và** còn tự kiểm tra được chữ ký là hợp lệ.

| | Chỉ ký | Chỉ mã hoá | Ký rồi mã hoá |
|---|---|---|---|
| Bảo mật | Không | Có | Có |
| Toàn vẹn | Có | Có* | Có |
| Chứng thực | Có | **Không** | Có |
| Chống chối bỏ | Có | Không | Có |

\* Mã hoá chỉ dùng khoá công khai của Thu Thủy, nên **bất kỳ ai** cũng tạo được một thư mã hoá hợp lệ gửi Thu Thủy
(S6-D: Mai Phương tạo thư giả nhân danh Thu Trang). Mã hoá phát hiện được thư bị sửa, nhưng không chứng minh được
thư do ai viết.

---

## 2. Mã hoá RSA và các điểm yếu của RSA "sách giáo khoa"

Với RSA thuần, ta mã hoá `C = M^e mod N` và giải mã `M = C^d mod N`. Cách này có bốn điểm yếu đã được
chứng minh bằng chương trình (`attacks/forgery_no_padding.py`, `attacks/confidentiality.py`):

| # | Điểm yếu | Tấn công | Kết quả demo | Cách khắc phục |
|---|---|---|---|---|
| 1 | **Tất định**: cùng M luôn cho cùng C | Từ điển: Mai Phương mã hoá thử từng ứng viên bằng khoá công khai (menu 17) | Phiếu bầu "KHONG DONG Y" bị đoán ra chỉ sau 3 lần thử | Đệm ngẫu nhiên OAEP |
| 2 | **Đồng cấu**: `C1·C2 = (M1·M2)^e` | Sửa bản mã có chủ đích, tạo chữ ký giả (menu 15) | Từ chữ ký của 2 và 50.000.000, Mai Phương tạo được chữ ký cho 100.000.000 | Đệm (OAEP/PKCS#1) |
| 3 | **e nhỏ, cùng M gửi nhiều người** | Håstad: ghép bằng định lý số dư Trung Hoa rồi lấy căn bậc ba (menu 19) | Khôi phục bí mật 49 byte từ 3 bản mã, không cần khoá riêng nào | OAEP: mỗi bản rõ được đệm ngẫu nhiên khác nhau |
| 4 | **Một khoá dùng cho cả ký lẫn giải mã** | "Làm mù" bản mã rồi nhờ chủ khoá ký (menu 20) | Chữ ký thô của Thu Trang chính là bản giải mã của C' → Mai Phương lấy được mã OTP | Tách khoá ký / khoá mã hoá (`key_usage`) |

### 2.1. RSAES-OAEP (RFC 8017, mục 7.1): cài đặt trong `core/padding.py` (mã hoá khối) và `core/rsa_full.py`

```
                 lHash = SHA256(label)
DB  = lHash ‖ 00…00 ‖ 01 ‖ M                    (k − hLen − 1 byte)
seed ← 32 byte ngẫu nhiên (CSPRNG)
maskedDB   = DB   ⊕ MGF1(seed, k − hLen − 1)
maskedSeed = seed ⊕ MGF1(maskedDB, hLen)
EM = 00 ‖ maskedSeed ‖ maskedDB   →   C = EM^e mod N
```

* **Ngẫu nhiên hoá**: mỗi lần mã hoá có seed mới, nên cùng M cho C khác nhau. Tấn công từ điển và Håstad
  thất bại (demo trả về `None`).
* **Chống sửa bản mã**: mọi thay đổi trên C đều làm hỏng `lHash` hoặc byte `01` sau khi gỡ mặt nạ.
  Theo Bellare–Rogaway (1994) và Fujisaki và cộng sự (2001), OAEP đạt mức an toàn IND-CCA2 trong mô hình
  tiên tri ngẫu nhiên.
* **Chống tấn công Manger (2001)**: mọi lỗi giải mã đều trả về **cùng một** ngoại lệ `DecryptionError`.
  Kẻ tấn công vì vậy không biết bước kiểm tra nào đã sai.
* **Nhãn (label) = tên người nhận**: một khoá phiên bọc cho Thu Thủy không thể bị mang sang dùng với nhãn khác.
* Giới hạn: một khối chỉ chứa được tối đa `k − 66` byte (190 byte với khoá 2048 bit). Vì vậy dữ liệu dài
  phải dùng **mã hoá lai** (mục 4).

**Đối chiếu** (`tests/doi_chieu.py`): bản mã do nhóm tạo được thư viện `cryptography` giải đúng, và ngược lại
bản mã do thư viện tạo được chương trình của nhóm giải đúng. Như vậy cài đặt OAEP khớp chuẩn.

---

## 3. Kết hợp chữ ký và mã hoá: thứ tự nào là đúng?

| Cách làm | Gửi đi | Lỗ hổng | Demo |
|---|---|---|---|
| Ký song song mã hoá | `Enc_B(M) ‖ Sign_A(M)` | Chữ ký nằm ngoài, ở dạng rõ. Mai Phương kiểm tra chữ ký với từng ứng viên M và đoán ra M | menu 18 |
| Mã hoá rồi ký | `C = Enc_B(M)`, `Sign_A(C)` | Mai Phương gỡ chữ ký của Thu Trang rồi ký lại bằng khoá của Mai Phương, khiến Thu Thủy tưởng thư của Mai Phương. Trọng tài cũng không biết Thu Trang đã ký nội dung gì | lý thuyết |
| Ký rồi mã hoá **ngây thơ** | `Enc_B(M ‖ Sign_A(M))` | **Chuyển tiếp lén** (Davis, 2001): Thu Thủy giải mã rồi mã hoá lại gửi Tuyết Linh, và Tuyết Linh tưởng Thu Trang viết cho mình | S6-E (Tuyết Linh bị lừa) |
| **Ký rồi mã hoá có ghi người nhận** *(hệ thống dùng cách này)* | `Enc_B(meta ‖ Sign_A(meta) ‖ M)`, trong đó `meta = {from, to, SHA256(M), time}` | Không có lỗ hổng nào ở trên: tên người nhận được ký, nên Tuyết Linh phát hiện thư không gửi cho mình | S6-E (bị chặn) |

---

## 4. Mã hoá lai: cài đặt trong `core/secure_message.py`

RSA chậm (giải mã 2048 bit mất khoảng 36 ms, xem bảng benchmark) và mỗi khối chỉ chứa 190 byte.
Vì thế hệ thống làm giống TLS, PGP và S/MIME: **RSA chỉ dùng để bọc khoá phiên**, còn dữ liệu được mã
bằng thuật toán đối xứng.

```
Thu Trang                                                       Thu Thủy
1. meta = {from:Thu Trang, to:Thu Thủy, sha256(M), time, filename}
   S = Sign_dA(meta)                     (RSASSA-PKCS1-v1_5)
2. inner = meta ‖ S ‖ M
3. K ← 32 byte ngẫu nhiên; K_enc, K_mac = HMAC(K,"encryption"), HMAC(K,"authentication")
   ct  = inner ⊕ SHA256(K_enc ‖ nonce ‖ i)…    ─────►  4. K = OAEP-Dec_dB(ek)      ← chỉ Thu Thủy làm được
   tag = HMAC(K_mac, header ‖ nonce ‖ ct)      ─────►  5. kiểm tra tag            ← phát hiện sửa bản mã
   ek  = OAEP-Enc_eB(K, label="Thu Thủy")           ─────►  6. giải mã ct → kiểm tra meta.to == Thu Thủy
                                                       7. Verify_eA(meta, S), SHA256(M) == meta.sha256
```

* **Encrypt-then-MAC**: bản mã được kiểm tra HMAC *trước* khi giải mã, nên bản mã bị sửa bị loại ngay.
  Bộ test sửa từng trường `ct`, `tag`, `nonce`, `ek`, và cả bốn đều bị phát hiện.
* **Giấu cả danh tính người gửi**: tên người gửi và chữ ký nằm bên trong bản mã. Mai Phương chỉ thấy `to: Thu Thủy`.
* **Hạn chế cần nêu trong báo cáo**: dòng khoá SHA-256 ở chế độ đếm là cấu trúc tự cài phục vụ học tập,
  chưa được chuẩn hoá. Hệ thống thực tế nên dùng AES-256-GCM hoặc ChaCha20-Poly1305.

**Demo trên dữ liệu thật** (menu 6): mã hoá ảnh `samples/anh_mau.png` (87.825 byte) mất khoảng 1,9 giây,
giải mã khoảng 1,6 giây. Tệp khôi phục **giống hệt từng byte** tệp gốc, còn Mai Phương dùng khoá của mình thì không
mở được khoá phiên.

---

## 5. Bảo vệ khoá riêng và nguồn ngẫu nhiên

| Vấn đề | Trước khi sửa | Sau khi sửa |
|---|---|---|
| Sinh p, q | `random.getrandbits` (Mersenne Twister): quan sát 624 giá trị đầu ra là đoán được toàn bộ trạng thái | `secrets` (CSPRNG của hệ điều hành) |
| Miller–Rabin | 5–20 vòng | 40 vòng, xác suất nhận nhầm ≤ 4⁻⁴⁰ |
| p, q gần nhau | Không kiểm tra | Yêu cầu \|p − q\| đủ lớn, chống phân tích Fermat |
| Lưu khoá riêng | `d` ghi dạng rõ trong JSON | Tuỳ chọn mã hoá `d` bằng khoá sinh từ mật khẩu (PBKDF2-HMAC-SHA256, có salt) + HMAC |
| So sánh băm | `==` (thời gian phụ thuộc vị trí byte khác đầu tiên) | So sánh thời gian hằng `compare_hashes` |
| Kiểm tra đệm chữ ký | Tìm byte `00` rồi lấy phần đuôi (lỏng) | So khớp **toàn bộ** khối EM; chặn Bleichenbacher e=3 (menu 16) |
| Miền chữ ký | Không kiểm tra | Bắt buộc `0 < S < N` (chặn S + N, S = 0) |

---

## 6. Độ an toàn theo kích thước khoá

| Khoá RSA | Mức an toàn tương đương | Trạng thái (NIST SP 800-57 phần 1, bản sửa đổi 5) |
|---|---|---|
| 512 bit | ~56 bit | Đã bị phân tích từ năm 1999 (RSA-155) |
| 1024 bit | ~80 bit | Không được dùng để tạo chữ ký mới |
| **2048 bit** | **112 bit** | Tối thiểu hiện nay |
| 3072 bit | 128 bit | Khuyến nghị cho dữ liệu cần bảo vệ lâu dài |

* Kỷ lục phân tích thừa số công khai: RSA-250 (829 bit), năm 2020, tốn khoảng 2.700 năm-lõi CPU.
* Máy tính lượng tử chạy thuật toán Shor sẽ phá được RSA với mọi kích thước khoá. NIST đã chuẩn hoá các
  thuật toán hậu lượng tử: ML-DSA (chữ ký, FIPS 204) và ML-KEM (trao đổi khoá, FIPS 203), năm 2024.
  Dự thảo NIST IR 8547 đề xuất ngừng khuyến nghị RSA 2048 bit sau năm 2030 và cấm hẳn RSA sau năm 2035.
* Trong chương trình, menu 14 cho thấy N = 3233 bị phân tích ngay lập tức và lộ d = 2753. Với N 2048 bit,
  phép chia thử cần khoảng 2¹⁰²⁴ phép tính, nên không khả thi.

---

## 7. Ví dụ tính tay về tính bảo mật (khớp với `core/rsa_mini.py`, menu 1)

**Khoá của Thu Trang** (dùng để ký): p = 17, q = 11, e = 7.
Từ đó N_A = 187, φ = 160, d_A = 23.

**Khoá của Thu Thủy** (dùng để mã hoá): p = 23, q = 29, e = 3.
Từ đó N_B = 667, φ = 616.
Euclid mở rộng: 616 = 205·3 + 1, nên d_B = 616 − 205 = **411**. Kiểm tra: 3·411 = 1233 = 2·616 + 1.

| Bước | Phép tính | Kết quả |
|---|---|---|
| Thu Trang ký M = 88 | S = 88²³ mod 187 | **11** |
| Thu Trang mã hoá M | C1 = 88³ mod 667 | **465** |
| Thu Trang mã hoá S | C2 = 11³ mod 667 | **664** |
| Thu Thủy giải mã | M = 465⁴¹¹ mod 667 | **88** |
| Thu Thủy giải mã | S = 664⁴¹¹ mod 667 | **11** |
| Thu Thủy kiểm tra chữ ký | 11⁷ mod 187 | **88 = M** (đúng) |
| Mai Phương tấn công từ điển | thử M' = 0…186, tính M'³ mod 667 | M' = 88 khớp C1, **lộ bản rõ** |

**Lưu ý:** phải có N_A < N_B thì S (luôn < N_A) mới mã hoá được bằng khoá của Thu Thủy. Ở bản đầy đủ, vấn đề
này không còn, vì chữ ký được đặt vào bên trong dữ liệu mã hoá đối xứng.

---

## 8. Kết quả kiểm thử và đánh giá

* `python -m unittest discover -s tests`: 82 ca kiểm thử, gồm cả ca nhóm tự viết và ca đối chiếu chuẩn. Tất cả đều đạt.
  Khi chưa cài `cryptography` thì 3 ca đối chiếu với thư viện được bỏ qua.
* `python tests/doi_chieu.py`: 29/29 khớp. Trong đó có test vector NIST cho SHA-256, RFC 4231 cho HMAC,
  PBKDF2 so với `hashlib`, **chữ ký PKCS#1 v1.5 trùng từng bit với `cryptography`**, còn chữ ký PSS và OAEP
  tương thích hai chiều.
* `python demo/benchmark.py`: kết quả đo trên máy của nhóm, Python 3.12:

| Khoá | Sinh khoá | Ký | Kiểm tra | OAEP mã hoá | OAEP giải mã |
|---|---|---|---|---|---|
| 1024 | 0,13 s | 5,4 ms | 0,2 ms | 1,1 ms | 5,7 ms |
| 2048 | 1,07 s | 35,8 ms | 0,4 ms | 2,8 ms | 36,5 ms |

Kiểm tra chữ ký và mã hoá nhanh hơn ký và giải mã gần 100 lần. Lý do là e = 65537 chỉ có 17 bit, còn d
dài khoảng bằng N.

## 9. Hạn chế và hướng phát triển

1. Python thuần không chạy trong thời gian hằng, nên vẫn có nguy cơ tấn công kênh kề (đo thời gian, đo
   điện năng). Thư viện thực tế dùng kỹ thuật làm mù (blinding) cho phép tính với d.
2. Chưa dùng định lý số dư Trung Hoa (CRT) khi ký. Dùng CRT sẽ nhanh hơn khoảng 4 lần, nhưng phải phòng
   tấn công lỗi (Boneh–DeMillo–Lipton) bằng cách kiểm tra lại chữ ký trước khi gửi.
3. Đã cài RSASSA-PSS (đệm ngẫu nhiên, có chứng minh an toàn chặt) nhưng mặc định vẫn dùng PKCS#1 v1.5 để
   chữ ký đối chiếu được từng bit. Dòng khoá tự cài nên thay bằng AES-GCM.
4. PKI mới ở mức mô phỏng: chưa có chuỗi CA trung gian và chưa có OCSP. Bản đối chiếu dùng chứng thư
   X.509 thật nằm ở `tests/doi_chieu_x509.py`.

## Tài liệu tham khảo

1. K. Moriarty và cộng sự, *RFC 8017: PKCS #1: RSA Cryptography Specifications Version 2.2*, 2016.
2. NIST, *FIPS 180-4: Secure Hash Standard*, 2015. *FIPS 186-5: Digital Signature Standard*, 2023.
3. H. Krawczyk, M. Bellare, R. Canetti, *RFC 2104: HMAC*, 1997. M. Nystrom, *RFC 4231*, 2005.
4. K. Moriarty, B. Kaliski, A. Rusch, *RFC 8018: PKCS #5 v2.1 (PBKDF2)*, 2017.
5. M. Bellare, P. Rogaway, "Optimal Asymmetric Encryption", *EUROCRYPT 1994*.
6. D. Davis, "Defective Sign & Encrypt in S/MIME, PKCS#7, MOSS, PEM, PGP, and XML", *USENIX ATC 2001*.
7. J. Håstad, "Solving Simultaneous Modular Equations of Low Degree", *SIAM J. Computing*, 1988.
8. D. Bleichenbacher, "Forging RSA signatures with e=3", CRYPTO 2006 rump session.
9. J. Manger, "A Chosen Ciphertext Attack on RSA OAEP", *CRYPTO 2001*.
10. D. Boneh, "Twenty Years of Attacks on the RSA Cryptosystem", *Notices of the AMS*, 1999.
11. NIST SP 800-57 Part 1 Rev. 5, *Recommendation for Key Management*, 2020. NIST IR 8547 (dự thảo), 2024.
