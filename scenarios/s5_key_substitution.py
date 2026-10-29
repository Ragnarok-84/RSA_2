"""Kịch bản S5: tấn công thay thế khóa công khai."""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.rsa_math import generate_keypair, mod_exp
from pki.cert import CertificateAuthority, verify_certificate


def run_scenario_s5(keysize=1024, verbose=True):
    say = print if verbose else (lambda *a, **k: None)
    say("\n=======================================================")
    say("KỊCH BẢN S5: TẤN CÔNG THAY THẾ KHÓA CÔNG KHAI (KEY SUBSTITUTION)")
    say("=======================================================")

    alice_priv, alice_pub = generate_keypair(keysize=keysize)
    eve_priv, eve_pub = generate_keypair(keysize=keysize)
    secret = int.from_bytes("MAT-KHAU-123".encode(), "big")   # bí mật Thu Thủy muốn gửi Thu Trang

    say("[1] Thu Trang công bố khóa công khai thật; Mai Phương chặn đường truyền và tráo bằng khóa của Mai Phương.")

    # Trường hợp A: không có chứng thư
    say("\n--- TRƯỜNG HỢP A: KHÔNG DÙNG CHỨNG THƯ CA ---")
    received_key = eve_pub                      # Thu Thủy nhận phải khóa đã bị tráo, không có cách phát hiện
    cipher = mod_exp(secret, received_key[0], received_key[1])
    eve_reads = mod_exp(cipher, eve_priv[0], eve_priv[1]) == secret
    alice_reads = mod_exp(cipher, alice_priv[0], alice_priv[1]) == secret
    say("    Thu Thủy mã hóa bí mật bằng khóa nhận được (thực ra là của Mai Phương).")
    say(f"    Mai Phương giải mã được: {eve_reads} | Thu Trang giải mã được: {alice_reads}")
    case_a_attack_works = eve_reads and not alice_reads
    if case_a_attack_works:
        say("    [!] Thảm họa: Mai Phương đọc trộm thành công, Thu Trang không đọc được gì.")

    # Trường hợp B: có chứng thư
    say("\n--- TRƯỜNG HỢP B: CÓ CHỨNG THƯ CA (PKI) ---")
    ca = CertificateAuthority("CA Goc ATBMTT", keysize=keysize)
    alice_cert = ca.issue_certificate("Thu Trang", alice_pub)

    ok, msg = verify_certificate(alice_cert, ca.certificate, ca.crl)
    say(f"    Chứng thư thật của Thu Trang: {msg}")

    forged = dict(alice_cert)
    forged["public_key"] = list(eve_pub)         # Mai Phương sửa khóa công khai trong chứng thư
    ok_forged, msg_forged = verify_certificate(forged, ca.certificate, ca.crl)
    say(f"    Mai Phương sửa khóa trong chứng thư   -> {msg_forged}")

    eve_ca = CertificateAuthority("CA Goc ATBMTT", keysize=keysize)   # CA giả mang tên giống
    eve_cert = eve_ca.issue_certificate("Thu Trang", eve_pub)
    ok_fake_ca, msg_fake_ca = verify_certificate(eve_cert, ca.certificate, ca.crl)
    say(f"    Mai Phương nhờ CA giả cấp chứng thư    -> {msg_fake_ca}")

    case_b_blocked = ok and not ok_forged and not ok_fake_ca
    if case_b_blocked:
        say("    -> Thu Thủy phát hiện ngay và ngắt kết nối. Tấn công Thay thế Khóa THẤT BẠI")

    return case_a_attack_works and case_b_blocked


if __name__ == "__main__":
    run_scenario_s5()
