# Kết quả kiểm thử đối chiếu

Sinh tự động bởi `python -m test.report` lúc 2026-10-29 19:23:07. 37/37 ca khớp.

| Nhóm | Ca kiểm thử | Ours | Reference | Nguồn | Khớp |
|---|---|---|---|---|---|
| Tiny / Slide | egcd(4864, 3458) | `(38, 32, -45)` | `(38, 32, -45)` | Slide | ✅ |
| Tiny / Slide | mod_inverse(25, 101) | `97` | `97` | Slide | ✅ |
| Tiny / Slide | mod_inverse(173, 1024) | `805` | `805` | Slide | ✅ |
| Tiny / Slide | mod_pow(7, 560, 561) | `1` | `1` | Slide | ✅ |
| Tiny / Slide | mod_pow(88, 7, 187) (mã hoá slide RSA) | `11` | `11` | Slide | ✅ |
| Tiny / Slide | mod_pow(11, 23, 187) | `88` | `88` | Slide | ✅ |
| Tiny / Slide | crt([5, 6], [7, 11]) | `61` | `61` | Slide | ✅ |
| Tiny / Slide | mod_pow(17, 8, 77) | `37` | `37` | Slide | ✅ |
| Tiny / Slide | keypair_from_primes(17, 11, 7): n, φ, d | `(187, 160, 23)` | `(187, 160, 23)` | Slide | ✅ |
| Tiny / Slide | Tiny: ký h = 88 (p=17, q=11, e=7) | `s = 11` | `s = 11` | Slide | ✅ |
| Tiny / Slide | Tiny: kiểm tra 11^7 mod 187 = 88 | `True` | `True` | Slide | ✅ |
| Tiny / Slide | mod_pow ngẫu nhiên 2048 bít vs pow() | `9642405886386123260…` | `9642405886386123260…` | Python pow | ✅ |
| SHA-256 | Chuỗi rỗng | `e3b0c44298fc1c149af…` | `e3b0c44298fc1c149af…` | NIST FIPS 180-4 | ✅ |
| SHA-256 | "abc" (1 khối) | `ba7816bf8f01cfea414…` | `ba7816bf8f01cfea414…` | NIST FIPS 180-4 | ✅ |
| SHA-256 | 448 bít (2 khối) | `248d6a61d20638b8e5c…` | `248d6a61d20638b8e5c…` | NIST FIPS 180-4 | ✅ |
| SHA-256 | 896 bít | `cf5b16a778af8380036…` | `cf5b16a778af8380036…` | NIST FIPS 180-4 | ✅ |
| SHA-256 | Ngẫu nhiên 55 byte (biên khối) | `1c879b5c8ec30cb4de2…` | `1c879b5c8ec30cb4de2…` | hashlib | ✅ |
| SHA-256 | Ngẫu nhiên 56 byte (biên khối) | `bdde2b4fe52e9cefb87…` | `bdde2b4fe52e9cefb87…` | hashlib | ✅ |
| SHA-256 | Ngẫu nhiên 63 byte (biên khối) | `dd36d6f273f7ccf83bc…` | `dd36d6f273f7ccf83bc…` | hashlib | ✅ |
| SHA-256 | Ngẫu nhiên 64 byte (biên khối) | `d4a0b538473cef74e4b…` | `d4a0b538473cef74e4b…` | hashlib | ✅ |
| SHA-256 | Ngẫu nhiên 65 byte (biên khối) | `90570fc23d3a7acd665…` | `90570fc23d3a7acd665…` | hashlib | ✅ |
| SHA-256 | Ngẫu nhiên 1000 byte (biên khối) | `0ed6e6b31958d23232e…` | `0ed6e6b31958d23232e…` | hashlib | ✅ |
| Chữ ký (tự viết) | PKCS#1: thông điệp rỗng | `True` | `True` | Tự viết | ✅ |
| Chữ ký (tự viết) | PKCS#1: văn bản tiếng Việt UTF-8 | `True` | `True` | Tự viết | ✅ |
| Chữ ký (tự viết) | PKCS#1: tệp ảnh nhị phân logo.png | `True` | `True` | Tự viết | ✅ |
| Chữ ký (tự viết) | Sửa 1 bít thông điệp → từ chối | `False` | `False` | Tự viết | ✅ |
| Chữ ký (tự viết) | Sửa 1 bít chữ ký → từ chối | `False` | `False` | Tự viết | ✅ |
| Chữ ký (tự viết) | Dùng sai khoá công khai → từ chối | `False` | `False` | Tự viết | ✅ |
| Chữ ký (tự viết) | Ký CRT = ký không CRT | `True` | `True` | Tự viết | ✅ |
| PKCS#1 v1.5 | DigestInfo SHA-256 | `3031300d06096086480…` | `3031300d06096086480…` | RFC 8017 | ✅ |
| PKCS#1 v1.5 | Vector cố định: '' | `abfcd72c4519cf0eeea…` | `abfcd72c4519cf0eeea…` | RFC 8017 (vector lưu sẵn) | ✅ |
| PKCS#1 v1.5 | Vector cố định: 'abc' | `79c01d29ba71dfeb865…` | `79c01d29ba71dfeb865…` | RFC 8017 (vector lưu sẵn) | ✅ |
| PKCS#1 v1.5 | Vector cố định: 'Hợp đồng số 01/2026 ' | `32ba4848aea93cd7dc4…` | `32ba4848aea93cd7dc4…` | RFC 8017 (vector lưu sẵn) | ✅ |
| Đối chiếu thư viện | SHA-256 contract.txt | `1177d24caa7c185914e…` | `1177d24caa7c185914e…` | hashlib | ✅ |
| Đối chiếu thư viện | PKCS#1 v1.5 ký contract.txt (2048-bit): trùng từng byte | `79509e15a9da022aee4…` | `79509e15a9da022aee4…` | cryptography | ✅ |
| Đối chiếu thư viện | PKCS#1 v1.5: cryptography kiểm tra chữ ký của nhóm | `True` | `True` | cryptography | ✅ |
| Đối chiếu thư viện | PKCS#1 v1.5: nhóm kiểm tra chữ ký của cryptography | `True` | `True` | cryptography | ✅ |
