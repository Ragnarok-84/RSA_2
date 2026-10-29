"""Lõi mật mã tự cài đặt: số học, Miller–Rabin, sinh khoá RSA, SHA-256, PKCS#1 v1.5, PSS, chữ ký.

Chỉ dùng thư viện chuẩn Python (secrets, json, pathlib, …), không dùng thư viện mật mã bên ngoài;
không dùng pow(a, b, n) built-in (mọi lũy thừa modulo đi qua core.number_theory.mod_pow).
test/unit/test_constraints.py kiểm tra tự động các ràng buộc này.
"""
