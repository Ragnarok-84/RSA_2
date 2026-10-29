"""
scenarios/s2_nonrepudiation.py
[Báo cáo 4.3, 4.7, 6.5]
Kịch bản S2: Chống chối bỏ giao dịch (Non-Repudiation) = chữ ký số + chứng thư CA + dấu thời gian TSA.
Đối chiếu: HMAC (khóa bí mật dùng chung) KHÔNG chống chối bỏ được vì cả hai bên đều tạo được thẻ.
"""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.rsa_math import generate_keypair
from core.rsa_full import sign_message, verify_message
from core import hmac_utils
from pki.cert import CertificateAuthority, verify_certificate
from pki.timestamp import TimestampAuthority


def hmac_comparison(keysize, say):
    """Thu Thủy tự tạo thông điệp giả + thẻ HMAC bằng khóa chung -> trọng tài không phân biệt được."""
    shared_secret_key = "secret_key_123"                 # cả Thu Trang và Thu Thủy đều biết
    fake_message = "Thu Trang đồng ý đền bù cho Thu Thủy 1 tỷ đồng"
    fake_tag = hmac_utils.generate_hmac(shared_secret_key, fake_message)
    hmac_fooled = hmac_utils.verify_hmac(shared_secret_key, fake_message, fake_tag)
    say(f"\n[7] Đối chiếu HMAC: Thu Thủy tự tạo '{fake_message}' và tự sinh thẻ HMAC bằng khóa chung")
    say(f"    Trọng tài kiểm tra thẻ: {'HỢP LỆ' if hmac_fooled else 'sai'} -> không biết thẻ do Thu Trang hay Thu Thủy tạo"
        " => HMAC KHÔNG chống chối bỏ")
    _, alice_pub = generate_keypair(keysize=keysize)
    bob_priv, _ = generate_keypair(keysize=keysize)
    rsa_forged = verify_message(fake_message, sign_message(fake_message, bob_priv), alice_pub)
    say(f"    Với RSA: Thu Thủy chỉ có khóa CÔNG KHAI của Thu Trang, chữ ký Thu Thủy tự tạo: "
        f"{'chấp nhận (lỗi!)' if rsa_forged else 'BỊ TỪ CHỐI'} => RSA CÓ chống chối bỏ")
    return hmac_fooled and not rsa_forged


def run_scenario_s2(keysize=1024, verbose=True):
    say = print if verbose else (lambda *a, **k: None)
    say("\n=======================================================")
    say("KỊCH BẢN S2: CHỐNG CHỐI BỎ GIAO DỊCH (NON-REPUDIATION)")
    say("=======================================================")

    ca = CertificateAuthority("CA Goc ATBMTT", keysize=keysize)
    tsa = TimestampAuthority(keysize=keysize)
    alice_priv, alice_pub = generate_keypair(keysize=keysize)
    alice_cert = ca.issue_certificate("Thu Trang", alice_pub)

    transaction = "Thu Trang chuyển 100.000.000 VNĐ cho Thu Thủy"
    say(f"[1] Nội dung giao dịch: '{transaction}'")

    signature = sign_message(transaction, alice_priv)
    say(f"[2] Thu Trang ký xác nhận bằng khóa riêng. Chữ ký: {str(signature)[:30]}...")

    token = tsa.issue(signature)
    say(f"[3] TSA đóng dấu thời gian lên chữ ký: {token['time']}")

    # --- Tranh chấp: Thu Trang chối ---
    say("\n[4] Tranh chấp - Thu Trang chối: 'Tôi chưa từng ký giao dịch này!'. Trọng tài kiểm tra:")
    cert_ok, msg = verify_certificate(alice_cert, ca.certificate, ca.crl)
    sig_ok = verify_message(transaction, signature, tuple(alice_cert["public_key"]))
    ts_ok = tsa.verify(token, signature)
    say(f"    - Chứng thư của Thu Trang do CA cấp, còn hiệu lực : {cert_ok} ({msg})")
    say(f"    - Chữ ký khớp khóa công khai trong chứng thư      : {sig_ok}")
    say(f"    - Dấu thời gian TSA hợp lệ                        : {ts_ok}")
    repudiation_blocked = cert_ok and sig_ok and ts_ok

    # --- Thu Thủy thử sửa số tiền ---
    forged_tx = "Thu Trang chuyển 900.000.000 VNĐ cho Thu Thủy"
    bob_forge_ok = verify_message(forged_tx, signature, tuple(alice_cert["public_key"]))
    say(f"\n[5] Thu Thủy sửa số tiền thành 900 triệu rồi dùng lại chữ ký: "
        f"{'được chấp nhận' if bob_forge_ok else 'BỊ TỪ CHỐI (Thu Thủy không có khóa riêng của Thu Trang)'}")

    # --- Sửa thời điểm trong dấu thời gian ---
    bad_token = dict(token, time="2020-01-01 00:00:00")
    ts_forge_ok = tsa.verify(bad_token, signature)
    say(f"[6] Sửa thời điểm trong dấu thời gian: "
        f"{'được chấp nhận' if ts_forge_ok else 'BỊ TỪ CHỐI (chữ ký của TSA không khớp)'}")

    hmac_ok = hmac_comparison(keysize, say)

    success = repudiation_blocked and not bob_forge_ok and not ts_forge_ok and hmac_ok
    if success:
        say("\n[SUCCESS] Thu Trang KHÔNG THỂ CHỐI BỎ giao dịch này (còn HMAC thì chối được).")
    else:
        say("\n[FAILED] Kịch bản S2 không đạt.")
    return success


if __name__ == "__main__":
    run_scenario_s2()
