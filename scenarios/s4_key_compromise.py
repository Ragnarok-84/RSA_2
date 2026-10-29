"""S4 — Lộ khoá: khoá của Alice bị lộ ở thời điểm t_r → CA thu hồi → dấu thời gian phân định.

  - chữ ký có dấu thời gian < t_r vẫn hợp lệ (đã tồn tại trước khi khoá bị thu hồi);
  - chữ ký có dấu thời gian >= t_r bị từ chối;
  - sửa thời điểm trong dấu thời gian → chữ ký của TSA sai;
  - không có dấu thời gian → chỉ xét được tại hiện tại → bị từ chối.
Giới hạn còn lại: khoảng từ lúc khoá thực sự bị lộ đến lúc báo thu hồi.

Tấn công tương ứng (lấy được khoá riêng): attacks/a5_factorization.py, attacks/a6_crt_fault_attack.py.
"""
from __future__ import annotations

from core.rsa_keygen import generate_keypair
from core.signature import SignatureBundle, sign
from core.step_logger import StepLogger
from pki.ca import CertificateAuthority
from pki.certificate import DAY, fmt_time, now
from pki.timestamp import TimestampAuthority
from scenarios import ScenarioResult
from scenarios.s3_non_repudiation_contract import arbitrate

NAME = "S4: Lộ khoá → thu hồi → timestamp phân định"


def run(logger: StepLogger | None = None, bits: int = 2048) -> ScenarioResult:
    log = logger if logger is not None else StepLogger()
    log.head("KỊCH BẢN S4: LỘ KHOÁ, THU HỒI CHỨNG CHỈ VÀ DẤU THỜI GIAN")

    t0 = now()
    root = CertificateAuthority.create("Root CA ATBMTT", bits)
    root.self_signed_root(not_before=t0 - 400 * DAY)
    tsa = TimestampAuthority.create("TSA ATBMTT", bits)
    alice_pub, alice_priv = generate_keypair(bits)
    alice_cert = root.issue("Alice", alice_pub, days=365, not_before=t0 - 100 * DAY)
    t_sign, t_leak, t_window, t_r = t0 - 30 * DAY, t0 - 20 * DAY, t0 - 15 * DAY, t0 - 10 * DAY

    def bundle(msg_sig: bytes, at: int | None) -> SignatureBundle:
        token = tsa.stamp(msg_sig, at).to_dict() if at is not None else None
        return SignatureBundle("pkcs1v15", "", "", msg_sig.hex(), alice_cert.to_dict(), token)

    contract = "Hợp đồng thuê nhà 12 tháng, tiền thuê 8.000.000 VNĐ/tháng.".encode("utf-8")
    b1 = bundle(sign(contract, alice_priv), t_sign)
    log.note(f"[1] {fmt_time(t_sign)}: Alice ký hợp đồng thuê nhà, TSA đóng dấu thời gian")
    log.note(f"[2] {fmt_time(t_leak)}: Mallory lấy cắp được khoá riêng của Alice (Alice chưa biết)")
    window_doc = "Alice bán xe ô tô cho Mallory giá 10.000.000 VNĐ.".encode("utf-8")
    b_window = bundle(sign(window_doc, alice_priv), t_window)
    log.note(f"[3] {fmt_time(t_window)}: Mallory ký văn bản giả, xin dấu thời gian THẬT")
    root.revoke(alice_cert.serial, at=t_r)
    crl = root.publish_crl()
    log.note(f"[4] {fmt_time(t_r)} (= t_r): Alice báo mất khoá, CA thu hồi và công bố CRL có chữ ký",
             f"CRL: serial {alice_cert.serial} thu hồi từ {fmt_time(t_r)}")

    fake = "Alice bán căn nhà cho Mallory với giá 1 đồng.".encode("utf-8")
    fake_sig = sign(fake, alice_priv)
    b_after = bundle(fake_sig, t0)
    b_back = SignatureBundle(**{**b_after.__dict__, "timestamp_token": {**b_after.timestamp_token, "time": t_sign}})
    b_none = bundle(fake_sig, None)
    log.note(f"[5] {fmt_time(t0)}: Mallory dùng khoá lấy cắp ký văn bản giả, thử nhiều cách trình ra toà")

    roots = [root.certificate]
    r1 = arbitrate(contract, b1, roots, crl, tsa.public_key, t0)
    r2 = arbitrate(fake, b_after, roots, crl, tsa.public_key, t0)
    r3 = arbitrate(fake, b_back, roots, crl, tsa.public_key, t0)
    r4 = arbitrate(fake, b_none, roots, crl, tsa.public_key, t0)
    log.head("[6] Trọng tài phân xử (quy tắc: chứng chỉ phải hợp lệ tại thời điểm trong dấu thời gian)")
    log.log("    Hợp đồng thật, timestamp < t_r", r"t < t_r", r1.reason, level="ok" if r1.valid else "bad")
    log.log("    Văn bản giả, timestamp >= t_r", r"t \ge t_r", r2.reason, level="bad" if r2.valid else "ok")
    log.log("    Văn bản giả, sửa timestamp về trước t_r", None, r3.reason, level="bad" if r3.valid else "ok")
    log.log("    Văn bản giả, không có timestamp", None, r4.reason, level="bad" if r4.valid else "ok")

    r_window = arbitrate(window_doc, b_window, roots, crl, tsa.public_key, t0)
    log.log("[7] Giới hạn: văn bản Mallory ký TRONG khoảng lộ khoá (t_leak <= t < t_r)", None,
            ("vẫn được công nhận — " if r_window.valid else "bị từ chối — ") + r_window.reason +
            "\nToán học, CA và TSA không phân biệt được chữ ký này với chữ ký thật; chỉ giảm rủi ro bằng "
            "token/HSM có PIN, báo mất ngay, OCSP thay cho CRL định kỳ.", level="dim")

    valid = r1.valid and not r2.valid and not r3.valid and not r4.valid
    summary = ("CRL vô hiệu khoá bị lộ từ t_r; dấu thời gian giữ giá trị cho chữ ký trước t_r và chặn ký lùi ngày."
               if valid else "Kịch bản S4 không đạt.")
    (log.ok if valid else log.bad)("[KẾT LUẬN] " + summary)
    return ScenarioResult(NAME, valid, summary, {
        "before_revocation": r1.valid, "after_revocation": r2.valid, "backdated": r3.valid,
        "no_timestamp": r4.valid, "compromise_window": r_window.valid,
    })
