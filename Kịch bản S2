"""
scenarios/s2_nonrepudiation.py
Kịch bản S2: Chống chối bỏ giao dịch (Non-Repudiation) = chữ ký số + chứng thư CA + dấu thời gian TSA.
"""
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from keygen import generate_keypair
from rsa_core import sign_message, verify_message
from pki_ca import CertificateAuthority, TimestampAuthority, verify_certificate


def run_scenario_s2(keysize=1024, verbose=True):
    say = print if verbose else (lambda *a, **k: None)
    say("\n=======================================================")
    say("KỊCH BẢN S2: CHỐNG CHỐI BỎ GIAO DỊCH (NON-REPUDIATION)")
    say("=======================================================")

    ca = CertificateAuthority("CA Goc ATBMTT", keysize=keysize)
    tsa = TimestampAuthority(keysize=keysize)
    alice_priv, alice_pub = generate_keypair(keysize=keysize)
    alice_cert = ca.issue_certificate("Alice", alice_pub)

    transaction = "Alice chuyển 100.000.000 VNĐ cho Bob"
    say(f"[1] Nội dung giao dịch: '{transaction}'")

    signature = sign_message(transaction, alice_priv)
    say(f"[2] Alice ký xác nhận bằng khóa riêng. Chữ ký: {str(signature)[:30]}...")

    token = tsa.issue(signature)
    say(f"[3] TSA đóng dấu thời gian lên chữ ký: {token['time']}")

    # --- Tranh chấp: Alice chối ---
    say("\n[4] Tranh chấp - Alice chối: 'Tôi chưa từng ký giao dịch này!'. Trọng tài kiểm tra:")
    cert_ok, msg = verify_certificate(alice_cert, ca.certificate, ca.crl)
    sig_ok = verify_message(transaction, signature, tuple(alice_cert["public_key"]))
    ts_ok = tsa.verify(token, signature)
    say(f"    - Chứng thư của Alice do CA cấp, còn hiệu lực : {cert_ok} ({msg})")
    say(f"    - Chữ ký khớp khóa công khai trong chứng thư  : {sig_ok}")
    say(f"    - Dấu thời gian TSA hợp lệ                    : {ts_ok}")
    repudiation_blocked = cert_ok and sig_ok and ts_ok

    # --- Bob thử sửa số tiền ---
    forged_tx = "Alice chuyển 900.000.000 VNĐ cho Bob"
    bob_forge_ok = verify_message(forged_tx, signature, tuple(alice_cert["public_key"]))
    say(f"\n[5] Bob sửa số tiền thành 900 triệu rồi dùng lại chữ ký: "
        f"{'được chấp nhận ❌' if bob_forge_ok else 'BỊ TỪ CHỐI ✅ (Bob không có khóa riêng của Alice)'}")

    # --- Sửa thời điểm trong dấu thời gian ---
    bad_token = dict(token, time="2020-01-01 00:00:00")
    ts_forge_ok = tsa.verify(bad_token, signature)
    say(f"[6] Sửa thời điểm trong dấu thời gian: "
        f"{'được chấp nhận ❌' if ts_forge_ok else 'BỊ TỪ CHỐI ✅ (chữ ký của TSA không khớp)'}")

    success = repudiation_blocked and not bob_forge_ok and not ts_forge_ok
    if success:
        say("\n[SUCCESS] Alice KHÔNG THỂ CHỐI BỎ giao dịch này (so sánh S4: HMAC thì chối được).")
    else:
        say("\n[FAILED] Kịch bản S2 không đạt.")
    return success


if __name__ == "__main__":
    run_scenario_s2()
