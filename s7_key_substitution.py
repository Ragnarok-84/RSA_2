"""
scenarios/s7_key_substitution.py
Kịch bản S7: Tấn công thay thế khóa công khai (Key Substitution / Man-in-the-Middle).
Minh họa vai trò của chứng thư CA: không có chứng thư thì Bob bị lừa; có chứng thư thì phát hiện.
"""
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from keygen import generate_keypair
from math_utils import mod_exp
from pki_ca import CertificateAuthority, verify_certificate


def run_scenario_s7(keysize=1024, verbose=True):
    say = print if verbose else (lambda *a, **k: None)
    say("\n=======================================================")
    say("KỊCH BẢN S7: TẤN CÔNG THAY THẾ KHÓA CÔNG KHAI (KEY SUBSTITUTION)")
    say("=======================================================")

    alice_priv, alice_pub = generate_keypair(keysize=keysize)
    eve_priv, eve_pub = generate_keypair(keysize=keysize)
    secret = int.from_bytes("MAT-KHAU-123".encode(), "big")   # bí mật Bob muốn gửi Alice

    say("[1] Alice công bố khóa công khai thật; Eve chặn đường truyền và tráo bằng khóa của Eve.")

    # ---------- Trường hợp A: không có chứng thư ----------
    say("\n--- TRƯỜNG HỢP A: KHÔNG DÙNG CHỨNG THƯ CA ---")
    received_key = eve_pub                      # Bob nhận phải khóa đã bị tráo, không có cách phát hiện
    cipher = mod_exp(secret, received_key[0], received_key[1])
    eve_reads = mod_exp(cipher, eve_priv[0], eve_priv[1]) == secret
    alice_reads = mod_exp(cipher, alice_priv[0], alice_priv[1]) == secret
    say("    Bob mã hóa bí mật bằng khóa nhận được (thực ra là của Eve).")
    say(f"    Eve giải mã được: {eve_reads} | Alice giải mã được: {alice_reads}")
    case_a_attack_works = eve_reads and not alice_reads
    if case_a_attack_works:
        say("    [!] Thảm họa: Eve đọc trộm thành công, Alice không đọc được gì.")

    # ---------- Trường hợp B: có chứng thư ----------
    say("\n--- TRƯỜNG HỢP B: CÓ CHỨNG THƯ CA (PKI) ---")
    ca = CertificateAuthority("CA Goc ATBMTT", keysize=keysize)
    alice_cert = ca.issue_certificate("Alice", alice_pub)

    ok, msg = verify_certificate(alice_cert, ca.certificate, ca.crl)
    say(f"    Chứng thư thật của Alice: {msg}")

    forged = dict(alice_cert)
    forged["public_key"] = list(eve_pub)         # Eve sửa khóa công khai trong chứng thư
    ok_forged, msg_forged = verify_certificate(forged, ca.certificate, ca.crl)
    say(f"    Eve sửa khóa trong chứng thư   -> {msg_forged}")

    eve_ca = CertificateAuthority("CA Goc ATBMTT", keysize=keysize)   # CA giả mang tên giống
    eve_cert = eve_ca.issue_certificate("Alice", eve_pub)
    ok_fake_ca, msg_fake_ca = verify_certificate(eve_cert, ca.certificate, ca.crl)
    say(f"    Eve nhờ CA giả cấp chứng thư    -> {msg_fake_ca}")

    case_b_blocked = ok and not ok_forged and not ok_fake_ca
    if case_b_blocked:
        say("    -> Bob phát hiện ngay và ngắt kết nối. Tấn công Thay thế Khóa THẤT BẠI ✅")

    return case_a_attack_works and case_b_blocked


if __name__ == "__main__":
    run_scenario_s7()
