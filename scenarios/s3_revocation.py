"""
scenarios/s3_revocation.py
[Báo cáo 4.4, 4.7, 6.5]
Kịch bản S3: Khóa bị lộ, thu hồi chứng thư (CRL) và vai trò của dấu thời gian (TSA).
  Phần A — Thu hồi: Bob mất khóa -> CA thu hồi -> chữ ký mới bằng khóa đó bị từ chối dù "đúng toán học".
  Phần B — Khóa bị lộ + TSA: chữ ký TRƯỚC thời điểm thu hồi vẫn có giá trị, chữ ký SAU thì không;
           Eve sửa ngày trong dấu thời gian cũng bị phát hiện.
  Phần C — Chứng thư hết hạn: chữ ký có dấu thời gian lúc chứng thư còn hạn vẫn có giá trị.
"""
import os
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.rsa_math import generate_keypair
from core.rsa_full import sign_message, verify_message
from pki.cert import CertificateAuthority, verify_certificate, verify_data
from pki.crl import verify_published_crl
from pki.timestamp import TimestampAuthority, token_time, TIME_FMT


def judge(message, signature, token, cert, ca, tsa, now):
    """
    Trọng tài quyết định chữ ký có giá trị không:
      - Có dấu thời gian TSA hợp lệ -> kiểm tra chứng thư TẠI THỜI ĐIỂM TRONG DẤU THỜI GIAN.
      - Không có -> chỉ tin được thời điểm hiện tại (`now`).
    """
    if not verify_message(message, signature, cert["public_key"]):
        return False, "Chữ ký sai"
    if token is not None:
        if not tsa.verify(token, signature):
            return False, "Dấu thời gian không hợp lệ (bị sửa)"
        ok, why = verify_certificate(cert, ca.certificate, ca.crl, now=token_time(token), usage="signature")
        return ok, f"Theo dấu TSA {token['time']}: {why}"
    ok, why = verify_certificate(cert, ca.certificate, ca.crl, now=now, usage="signature")
    return ok, f"Không có dấu TSA, xét tại hiện tại: {why}"


def part_a_revocation(keysize, say):
    say("\n--- A. THU HỒI CHỨNG THƯ (CRL) ---")
    ca = CertificateAuthority("CA Goc ATBMTT", keysize=keysize)
    bob_priv, bob_pub = generate_keypair(keysize=keysize)
    bob_cert = ca.issue_certificate("Bob", bob_pub)
    say(f"[1] Chứng thư số của Bob có Serial: {bob_cert['serial']} (Trạng thái: Hợp lệ)")

    def accept(msg, sig):
        cert_ok, reason = verify_certificate(bob_cert, ca.certificate, ca.crl, usage="signature")
        return cert_ok and verify_message(msg, sig, bob_cert["public_key"]), reason

    msg1 = "Bob đặt mua 10 máy tính"
    ok1, _ = accept(msg1, sign_message(msg1, bob_priv))
    say(f"[2] Bob ký đơn hàng, bên bán kiểm tra: {'CHẤP NHẬN' if ok1 else 'từ chối'}")
    say("[3] SỰ CỐ: Bob bị mất thiết bị lưu trữ khóa riêng. Eve có khóa riêng của Bob.")
    ca.revoke(bob_cert["serial"], reason="keyCompromise")
    published = ca.publish_crl()
    crl_sig_ok = verify_published_crl(published, ca.certificate, verify_data)
    say(f"[4] CA thu hồi, công bố CRL có chữ ký CA (chữ ký CRL hợp lệ: {crl_sig_ok}): {published['entries']}")
    tampered = dict(published, entries={})
    crl_tamper_ok = verify_published_crl(tampered, ca.certificate, verify_data)
    say(f"    Eve xóa mục thu hồi khỏi CRL trên đường truyền -> chữ ký CRL: "
        f"{'hợp lệ' if crl_tamper_ok else 'SAI, bị phát hiện'}")

    msg2 = "Bob chuyển 500 triệu cho Eve"
    sig2 = sign_message(msg2, bob_priv)
    ok2, reason = accept(msg2, sig2)
    say(f"[5] Eve dùng khóa lấy cắp ký lệnh chuyển tiền: chữ ký đúng toán học = "
        f"{verify_message(msg2, sig2, bob_pub)}, chứng thư: {reason}")
    say(f"    => {'chấp nhận' if ok2 else 'BỊ TỪ CHỐI (nhờ kiểm tra CRL)'}")
    return ok1 and not ok2 and crl_sig_ok and not crl_tamper_ok


def part_b_key_compromise(keysize, say):
    say("\n--- B. KHÓA BỊ LỘ: CHỮ KÝ TRƯỚC / SAU THỜI ĐIỂM THU HỒI ---")
    now = datetime.now()
    ca, tsa = CertificateAuthority("CA Goc ATBMTT", keysize), TimestampAuthority(keysize=keysize)
    priv, pub = generate_keypair(keysize=keysize)
    cert = ca.issue_certificate("Alice", pub, days=365, start=now - timedelta(days=100))

    t_sign, t_leak = now - timedelta(days=30), now - timedelta(days=10)
    contract = "Hợp đồng thuê nhà 12 tháng"
    s1 = sign_message(contract, priv)
    tok1 = tsa.issue(s1, at=t_sign)
    say(f"[1] {t_sign:%Y-%m-%d}: Alice ký hợp đồng, TSA đóng dấu thời gian.")
    ca.revoke(cert["serial"], at=t_leak)
    say(f"[2] {t_leak:%Y-%m-%d}: Alice báo mất khóa, CA thu hồi chứng thư.")

    fake = "Alice bán nhà cho Eve giá 1 đồng"
    s2 = sign_message(fake, priv)                       # Eve có khóa bị lộ
    tok2 = tsa.issue(s2, at=now)
    say("[3] Hôm nay: Eve dùng khóa lấy cắp ký văn bản giả, cũng xin dấu thời gian.")
    tok_backdate = dict(tok2, time=t_sign.strftime(TIME_FMT))
    say("[4] Eve sửa ngày trong dấu thời gian về trước lúc thu hồi.")

    r1 = judge(contract, s1, tok1, cert, ca, tsa, now)
    r2 = judge(fake, s2, tok2, cert, ca, tsa, now)
    r3 = judge(fake, s2, tok_backdate, cert, ca, tsa, now)
    r4 = judge(fake, s2, None, cert, ca, tsa, now)
    for label, (ok, why) in (("Hợp đồng thật (ký trước thu hồi)", r1), ("Văn bản Eve (ký sau thu hồi)", r2),
                             ("Văn bản Eve + sửa ngày TSA", r3), ("Văn bản Eve, không dấu TSA", r4)):
        say(f"    {label:<34}: {'CÓ GIÁ TRỊ' if ok else 'BỊ TỪ CHỐI'} — {why}")
    return r1[0] and not r2[0] and not r3[0] and not r4[0]


def part_c_expired(keysize, say):
    say("\n--- C. CHỨNG THƯ HẾT HẠN ---")
    now = datetime.now()
    ca, tsa = CertificateAuthority("CA Goc ATBMTT", keysize), TimestampAuthority(keysize=keysize)
    priv, pub = generate_keypair(keysize=keysize)
    start = now - timedelta(days=400)
    cert = ca.issue_certificate("Alice", pub, days=365, start=start)
    say(f"[1] Chứng thư của Alice: {cert['not_before']} -> {cert['not_after']} (đã hết hạn)")

    doc = "Biên bản nghiệm thu 2025"
    s_old = sign_message(doc, priv)
    tok_old = tsa.issue(s_old, at=start + timedelta(days=100))
    say(f"[2] Alice ký biên bản khi chứng thư còn hạn, có dấu TSA {tok_old['time']}")
    late = "Phụ lục ký hôm nay"
    s_new = sign_message(late, priv)
    tok_new = tsa.issue(s_new, at=now)
    say("[3] Hôm nay Alice ký thêm phụ lục bằng khóa cũ (chứng thư đã hết hạn)")

    r1 = judge(doc, s_old, tok_old, cert, ca, tsa, now)
    r2 = judge(doc, s_old, None, cert, ca, tsa, now)
    r3 = judge(late, s_new, tok_new, cert, ca, tsa, now)
    for label, (ok, why) in (("Biên bản cũ + dấu TSA", r1), ("Biên bản cũ, không dấu TSA", r2),
                             ("Phụ lục ký sau khi hết hạn", r3)):
        say(f"    {label:<28}: {'CÓ GIÁ TRỊ' if ok else 'BỊ TỪ CHỐI'} — {why}")
    return r1[0] and not r2[0] and not r3[0]


def run_scenario_s3(keysize=1024, verbose=True):
    say = print if verbose else (lambda *a, **k: None)
    say("\n=======================================================")
    say("KỊCH BẢN S3: KHÓA BỊ LỘ, THU HỒI (CRL) VÀ DẤU THỜI GIAN")
    say("=======================================================")
    a = part_a_revocation(keysize, say)
    b = part_b_key_compromise(keysize, say)
    c = part_c_expired(keysize, say)
    success = a and b and c
    say("\n[SUCCESS] CRL vô hiệu khóa bị lộ; TSA giữ giá trị cho chữ ký hợp lệ trước đó." if success
        else f"\n[FAILED] A={a} B={b} C={c}")
    return success


if __name__ == "__main__":
    run_scenario_s3()
