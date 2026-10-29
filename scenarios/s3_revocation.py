"""
scenarios/s3_revocation.py
[Báo cáo 4.4, 4.7, 6.5]
Kịch bản S3: Khóa bị lộ, thu hồi chứng thư (CRL) và vai trò của dấu thời gian (TSA).
  Phần A — Thu hồi: Thu Thủy mất khóa -> CA thu hồi -> chữ ký mới bằng khóa đó bị từ chối dù "đúng toán học".
  Phần B — Khóa bị lộ + TSA: chữ ký TRƯỚC thời điểm thu hồi vẫn có giá trị, chữ ký SAU thì không;
           Mai Phương sửa ngày trong dấu thời gian cũng bị phát hiện.
  Phần C — Chứng thư hết hạn: chữ ký có dấu thời gian lúc chứng thư còn hạn vẫn có giá trị.
  Phần D — Ký lùi ngày: không có TSA thì thời điểm ký chỉ là lời khai của người ký -> Mai Phương khai lùi ngày
           để lọt vào lúc chứng thư còn hiệu lực; có TSA thì bị chặn.
  Phần E — Giới hạn của PKI: chữ ký Mai Phương tạo trong khoảng từ lúc LỘ khóa đến lúc THU HỒI vẫn được chấp nhận.
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
    bob_cert = ca.issue_certificate("Thu Thủy", bob_pub)
    say(f"[1] Chứng thư số của Thu Thủy có Serial: {bob_cert['serial']} (Trạng thái: Hợp lệ)")

    def accept(msg, sig):
        cert_ok, reason = verify_certificate(bob_cert, ca.certificate, ca.crl, usage="signature")
        return cert_ok and verify_message(msg, sig, bob_cert["public_key"]), reason

    msg1 = "Thu Thủy đặt mua 10 máy tính"
    ok1, _ = accept(msg1, sign_message(msg1, bob_priv))
    say(f"[2] Thu Thủy ký đơn hàng, bên bán kiểm tra: {'CHẤP NHẬN' if ok1 else 'từ chối'}")
    say("[3] SỰ CỐ: Thu Thủy bị mất thiết bị lưu trữ khóa riêng. Mai Phương có khóa riêng của Thu Thủy.")
    ca.revoke(bob_cert["serial"], reason="keyCompromise")
    published = ca.publish_crl()
    crl_sig_ok = verify_published_crl(published, ca.certificate, verify_data)
    say(f"[4] CA thu hồi, công bố CRL có chữ ký CA (chữ ký CRL hợp lệ: {crl_sig_ok}): {published['entries']}")
    tampered = dict(published, entries={})
    crl_tamper_ok = verify_published_crl(tampered, ca.certificate, verify_data)
    say(f"    Mai Phương xóa mục thu hồi khỏi CRL trên đường truyền -> chữ ký CRL: "
        f"{'hợp lệ' if crl_tamper_ok else 'SAI, bị phát hiện'}")

    msg2 = "Thu Thủy chuyển 500 triệu cho Mai Phương"
    sig2 = sign_message(msg2, bob_priv)
    ok2, reason = accept(msg2, sig2)
    say(f"[5] Mai Phương dùng khóa lấy cắp ký lệnh chuyển tiền: chữ ký đúng toán học = "
        f"{verify_message(msg2, sig2, bob_pub)}, chứng thư: {reason}")
    say(f"    => {'chấp nhận' if ok2 else 'BỊ TỪ CHỐI (nhờ kiểm tra CRL)'}")
    return ok1 and not ok2 and crl_sig_ok and not crl_tamper_ok


def part_b_key_compromise(keysize, say):
    say("\n--- B. KHÓA BỊ LỘ: CHỮ KÝ TRƯỚC / SAU THỜI ĐIỂM THU HỒI ---")
    now = datetime.now()
    ca, tsa = CertificateAuthority("CA Goc ATBMTT", keysize), TimestampAuthority(keysize=keysize)
    priv, pub = generate_keypair(keysize=keysize)
    cert = ca.issue_certificate("Thu Trang", pub, days=365, start=now - timedelta(days=100))

    t_sign, t_leak = now - timedelta(days=30), now - timedelta(days=10)
    contract = "Hợp đồng thuê nhà 12 tháng"
    s1 = sign_message(contract, priv)
    tok1 = tsa.issue(s1, at=t_sign)
    say(f"[1] {t_sign:%Y-%m-%d}: Thu Trang ký hợp đồng, TSA đóng dấu thời gian.")
    ca.revoke(cert["serial"], at=t_leak)
    say(f"[2] {t_leak:%Y-%m-%d}: Thu Trang báo mất khóa, CA thu hồi chứng thư.")

    fake = "Thu Trang bán nhà cho Mai Phương giá 1 đồng"
    s2 = sign_message(fake, priv)                       # Mai Phương có khóa bị lộ
    tok2 = tsa.issue(s2, at=now)
    say("[3] Hôm nay: Mai Phương dùng khóa lấy cắp ký văn bản giả, cũng xin dấu thời gian.")
    tok_backdate = dict(tok2, time=t_sign.strftime(TIME_FMT))
    say("[4] Mai Phương sửa ngày trong dấu thời gian về trước lúc thu hồi.")

    r1 = judge(contract, s1, tok1, cert, ca, tsa, now)
    r2 = judge(fake, s2, tok2, cert, ca, tsa, now)
    r3 = judge(fake, s2, tok_backdate, cert, ca, tsa, now)
    r4 = judge(fake, s2, None, cert, ca, tsa, now)
    for label, (ok, why) in (("Hợp đồng thật (ký trước thu hồi)", r1), ("Văn bản Mai Phương (ký sau thu hồi)", r2),
                             ("Văn bản Mai Phương + sửa ngày TSA", r3), ("Văn bản Mai Phương, không dấu TSA", r4)):
        say(f"    {label:<38}: {'CÓ GIÁ TRỊ' if ok else 'BỊ TỪ CHỐI'} — {why}")
    return r1[0] and not r2[0] and not r3[0] and not r4[0]


def part_c_expired(keysize, say):
    say("\n--- C. CHỨNG THƯ HẾT HẠN ---")
    now = datetime.now()
    ca, tsa = CertificateAuthority("CA Goc ATBMTT", keysize), TimestampAuthority(keysize=keysize)
    priv, pub = generate_keypair(keysize=keysize)
    start = now - timedelta(days=400)
    cert = ca.issue_certificate("Thu Trang", pub, days=365, start=start)
    say(f"[1] Chứng thư của Thu Trang: {cert['not_before']} -> {cert['not_after']} (đã hết hạn)")

    doc = "Biên bản nghiệm thu 2025"
    s_old = sign_message(doc, priv)
    tok_old = tsa.issue(s_old, at=start + timedelta(days=100))
    say(f"[2] Thu Trang ký biên bản khi chứng thư còn hạn, có dấu TSA {tok_old['time']}")
    late = "Phụ lục ký hôm nay"
    s_new = sign_message(late, priv)
    tok_new = tsa.issue(s_new, at=now)
    say("[3] Hôm nay Thu Trang ký thêm phụ lục bằng khóa cũ (chứng thư đã hết hạn)")

    r1 = judge(doc, s_old, tok_old, cert, ca, tsa, now)
    r2 = judge(doc, s_old, None, cert, ca, tsa, now)
    r3 = judge(late, s_new, tok_new, cert, ca, tsa, now)
    for label, (ok, why) in (("Biên bản cũ + dấu TSA", r1), ("Biên bản cũ, không dấu TSA", r2),
                             ("Phụ lục ký sau khi hết hạn", r3)):
        say(f"    {label:<28}: {'CÓ GIÁ TRỊ' if ok else 'BỊ TỪ CHỐI'} — {why}")
    return r1[0] and not r2[0] and not r3[0]


def judge_by_claimed_date(message, signature, cert, ca):
    """Trọng tài NGÂY THƠ: tin ngày ký do chính người ký ghi trong văn bản (dòng 'Ngày ký: ...')."""
    claimed = datetime.strptime(message.rsplit("Ngày ký: ", 1)[1], "%Y-%m-%d")
    if not verify_message(message, signature, cert["public_key"]):
        return False, "Chữ ký sai"
    ok, why = verify_certificate(cert, ca.certificate, ca.crl, now=claimed, usage="signature")
    return ok, f"Theo ngày tự khai {claimed:%Y-%m-%d}: {why}"


def part_d_backdating(keysize, say):
    say("\n--- D. KÝ LÙI NGÀY: TỰ KHAI NGÀY KÝ vs DẤU THỜI GIAN TSA ---")
    now = datetime.now()
    ca, tsa = CertificateAuthority("CA Goc ATBMTT", keysize), TimestampAuthority(keysize=keysize)
    priv, pub = generate_keypair(keysize=keysize)
    cert = ca.issue_certificate("Thu Trang", pub, days=365, start=now - timedelta(days=100))
    t_revoke = now - timedelta(days=10)
    ca.revoke(cert["serial"], at=t_revoke)
    say(f"[1] {t_revoke:%Y-%m-%d}: khóa của Thu Trang bị lộ, CA đã thu hồi chứng thư.")

    backdated = now - timedelta(days=40)
    fake = f"Thu Trang cam kết trả nợ thay cho Mai Phương 300 triệu đồng. Ngày ký: {backdated:%Y-%m-%d}"
    sig = sign_message(fake, priv)
    say(f"[2] Hôm nay Mai Phương dùng khóa lấy cắp ký văn bản và tự ghi 'Ngày ký: {backdated:%Y-%m-%d}' (trước thu hồi).")
    r_naive = judge_by_claimed_date(fake, sig, cert, ca)
    r_tsa = judge(fake, sig, tsa.issue(sig, at=now), cert, ca, tsa, now)
    for label, (ok, why) in (("Trọng tài tin ngày tự khai", r_naive), ("Trọng tài dùng dấu TSA", r_tsa)):
        say(f"    {label:<27}: {'CÓ GIÁ TRỊ' if ok else 'BỊ TỪ CHỐI'} — {why}")
    say("    => Không có bên thứ ba ghi thời gian thì thu hồi chứng thư vô tác dụng với chữ ký lùi ngày.")
    return r_naive[0] and not r_tsa[0]


def part_e_compromise_window(keysize, say):
    say("\n--- E. GIỚI HẠN: KHOẢNG TỪ LÚC LỘ KHÓA ĐẾN LÚC THU HỒI ---")
    now = datetime.now()
    ca, tsa = CertificateAuthority("CA Goc ATBMTT", keysize), TimestampAuthority(keysize=keysize)
    priv, pub = generate_keypair(keysize=keysize)
    cert = ca.issue_certificate("Thu Trang", pub, days=365, start=now - timedelta(days=100))
    t_leak, t_eve, t_revoke = (now - timedelta(days=d) for d in (20, 15, 10))
    say(f"[1] {t_leak:%Y-%m-%d}: Mai Phương lấy cắp khóa, Thu Trang CHƯA biết.")
    fake = "Thu Trang bán xe ô tô cho Mai Phương với giá 10 triệu đồng"
    sig = sign_message(fake, priv)
    token = tsa.issue(sig, at=t_eve)
    say(f"[2] {t_eve:%Y-%m-%d}: Mai Phương ký văn bản giả, xin dấu TSA THẬT (đúng thời gian thật).")
    ca.revoke(cert["serial"], at=t_revoke)
    say(f"[3] {t_revoke:%Y-%m-%d}: Thu Trang phát hiện, báo mất khóa, CA thu hồi.")
    ok, why = judge(fake, sig, token, cert, ca, tsa, now)
    say(f"    Văn bản Mai Phương ký trong khoảng lộ khóa: {'CÓ GIÁ TRỊ' if ok else 'bị từ chối'} — {why}")
    say("    => Toán học, CA và TSA đều không phân biệt được chữ ký này với chữ ký thật của Thu Trang.")
    say("       Chỉ giảm được rủi ro: lưu khóa trong token/HSM có PIN, báo mất ngay, OCSP thay vì CRL định kỳ.")
    return ok


def run_scenario_s3(keysize=1024, verbose=True):
    say = print if verbose else (lambda *a, **k: None)
    say("\n=======================================================")
    say("KỊCH BẢN S3: KHÓA BỊ LỘ, THU HỒI (CRL) VÀ DẤU THỜI GIAN")
    say("=======================================================")
    a = part_a_revocation(keysize, say)
    b = part_b_key_compromise(keysize, say)
    c = part_c_expired(keysize, say)
    d = part_d_backdating(keysize, say)
    e = part_e_compromise_window(keysize, say)
    success = a and b and c and d and e
    say("\n[SUCCESS] CRL vô hiệu khóa bị lộ; TSA giữ giá trị cho chữ ký hợp lệ trước đó và chặn ký lùi ngày;"
        "\n          khoảng lộ khóa trước khi thu hồi là giới hạn còn lại của PKI." if success
        else f"\n[FAILED] A={a} B={b} C={c} D={d} E={e}")
    return success


if __name__ == "__main__":
    run_scenario_s3()
