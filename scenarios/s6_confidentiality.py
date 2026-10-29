"""
scenarios/s6_confidentiality.py
[Bổ sung theo nhận xét của giảng viên - TÍNH BẢO MẬT]
Kịch bản S6: TÍNH BẢO MẬT (Confidentiality) — chữ ký số KHÔNG giữ bí mật nội dung.

  A. Chỉ ký          : Mai Phương đọc được toàn bộ nội dung (chữ ký đúng nhưng không che gì).
  B. Ký rồi mã hóa   : Mai Phương chỉ thấy bản mã; Thu Thủy mở được và xác định chắc chắn người gửi là Thu Trang.
  C. Mai Phương sửa bản mã  : HMAC phát hiện.
  D. Mai Phương tự mã hóa thư giả nhân danh Thu Trang (ai cũng có khóa công khai của Thu Thủy!) : chữ ký chặn.
  E. Thu Thủy chuyển tiếp lén thư của Thu Trang cho Tuyết Linh : trường "to" trong phần ký chặn.
  F. Dùng khóa KÝ của Thu Trang để mã hóa : chứng thư (key_usage) từ chối.
Cuối cùng in bảng so sánh: Chỉ ký / Chỉ mã hóa / Ký rồi mã hóa theo 4 tính chất an toàn.
"""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.rsa_math import generate_keypair
from core.rsa_full import sign_message, verify_message
from pki.cert import CertificateAuthority, verify_certificate
from core import secure_message as sm


def _preview(env):
    return {k: (v[:28] + "...") if isinstance(v, str) and len(v) > 28 else v for k, v in env.items()}


def run_scenario_s6(keysize=1024, verbose=True):
    say = print if verbose else (lambda *a, **k: None)
    say("\n=======================================================")
    say("KỊCH BẢN S6: TÍNH BẢO MẬT (CONFIDENTIALITY)")
    say("=======================================================")

    # --- Thiết lập PKI: mỗi người 2 cặp khóa, một để KÝ, một để MÃ HÓA ---
    ca = CertificateAuthority("CA Goc ATBMTT", keysize=keysize)
    people = {}
    for name in ("Thu Trang", "Thu Thủy", "Tuyết Linh", "Mai Phương"):
        s_priv, s_pub = generate_keypair(keysize=keysize)
        e_priv, e_pub = generate_keypair(keysize=keysize)
        people[name] = {
            "sign_priv": s_priv, "enc_priv": e_priv,
            "sign_cert": ca.issue_certificate(name, s_pub, key_usage="signature"),
            "enc_cert": ca.issue_certificate(name, e_pub, key_usage="encryption"),
        }
    say("[0] CA cấp cho mỗi người 2 chứng thư: một khóa KÝ (signature), một khóa MÃ HÓA (encryption).")

    def trusted_key(name, usage):
        """Lấy khóa công khai của `name` từ chứng thư, chỉ khi chứng thư hợp lệ đúng mục đích."""
        person = people.get(name)
        if person is None:
            return None
        cert = person["sign_cert"] if usage == "signature" else person["enc_cert"]
        ok, _ = verify_certificate(cert, ca.certificate, ca.crl, usage=usage)
        return tuple(cert["public_key"]) if ok else None

    sender_key = lambda name: trusted_key(name, "signature")
    A, B = people["Thu Trang"], people["Thu Thủy"]
    secret = "Mã khóa két sắt phòng tài vụ: 7-3-9-1. Đổi mã sau ngày 30/10."
    results = {}

    # ---------- A. Chỉ ký ----------
    say("\n--- A. CHỈ KÝ (không mã hóa) ---")
    sig = sign_message(secret, A["sign_priv"])
    eve_sees = secret
    results["A_sig_ok"] = verify_message(eve_sees, sig, sender_key("Thu Trang"))
    say(f"    Gói tin trên đường truyền: (M, S) với M = '{eve_sees}'")
    say(f"    Mai Phương đọc được M; Mai Phương còn tự kiểm tra được chữ ký: {results['A_sig_ok']} (chữ ký công khai)")
    results["A_leaked"] = eve_sees == secret

    # ---------- B. Ký rồi mã hóa ----------
    say("\n--- B. KÝ RỒI MÃ HÓA (RSA-OAEP + SHA256-CTR + HMAC) ---")
    env = sm.seal(secret, "Thu Trang", A["sign_priv"], "Thu Thủy", trusted_key("Thu Thủy", "encryption"))
    say(f"    Mai Phương thấy phong bì: {_preview(env)}")
    say(f"    Kích thước bản mã {len(env['ct'])} ký tự base64; không có tên người gửi (được giấu bên trong).")
    try:
        sm.open_sealed(env, "Mai Phương", people["Mai Phương"]["enc_priv"], sender_key)
        results["B_eve_blocked"] = False
    except sm.SecureMessageError as err:
        results["B_eve_blocked"] = True
        say(f"    Mai Phương thử mở bằng khóa riêng của Mai Phương -> {err.reason}")
    got = sm.open_sealed(env, "Thu Thủy", B["enc_priv"], sender_key)
    results["B_bob_ok"] = got["message"].decode() == secret and got["sender"] == "Thu Trang"
    say(f"    Thu Thủy mở bằng khóa riêng mã hóa của Thu Thủy -> '{got['message'].decode()}'")
    say(f"    Chữ ký xác định người gửi: {got['sender']} (thời điểm ký {got['meta']['time']})")

    # ---------- C. Sửa bản mã ----------
    say("\n--- C. MAI PHƯƠNG SỬA 1 BYTE BẢN MÃ ---")
    import base64
    ct = bytearray(base64.b64decode(env["ct"]))
    ct[len(ct) // 2] ^= 0x01
    tampered = dict(env, ct=base64.b64encode(bytes(ct)).decode())
    try:
        sm.open_sealed(tampered, "Thu Thủy", B["enc_priv"], sender_key)
        results["C_tamper_blocked"] = False
        say("    Thu Thủy chấp nhận bản mã bị sửa")
    except sm.SecureMessageError as err:
        results["C_tamper_blocked"] = True
        say(f"    Thu Thủy: {err.reason}")

    # ---------- D. Mai Phương giả mạo thư nhân danh Thu Trang ----------
    say("\n--- D. MAI PHƯƠNG TỰ MÃ HÓA THƯ GIẢ NHÂN DANH THU TRANG ---")
    say("    Mã hóa chỉ cần khóa CÔNG KHAI của Thu Thủy -> ai cũng gửi được thư mã hóa cho Thu Thủy.")
    fake = sm.seal("Thu Trang: chuyển ngay 200 triệu vào TK 0123 của Mai Phương", "Thu Trang", people["Mai Phương"]["sign_priv"],
                   "Thu Thủy", trusted_key("Thu Thủy", "encryption"))
    try:
        sm.open_sealed(fake, "Thu Thủy", B["enc_priv"], sender_key)
        results["D_forgery_blocked"] = False
        say("    Thu Thủy tin thư giả")
    except sm.SecureMessageError as err:
        results["D_forgery_blocked"] = True
        say(f"    Thu Thủy giải mã được nhưng: {err.reason}")
    say("    => Chỉ mã hóa thì có BẢO MẬT nhưng KHÔNG có CHỨNG THỰC. Cần chữ ký.")

    # ---------- E. Chuyển tiếp lén ----------
    say("\n--- E. THU THỦY CHUYỂN TIẾP LÉN THƯ CỦA THU TRANG CHO TUYẾT LINH ---")
    inner = sm.decrypt_envelope(env, B["enc_priv"])                # Thu Thủy giải mã, giữ nguyên chữ ký Thu Trang
    fwd = sm.encrypt_for(inner, "Tuyết Linh", trusted_key("Tuyết Linh", "encryption"))
    try:
        sm.open_sealed(fwd, "Tuyết Linh", people["Tuyết Linh"]["enc_priv"], sender_key)
        results["E_forward_blocked"] = False
    except sm.SecureMessageError as err:
        results["E_forward_blocked"] = True
        say(f"    Có ghi người nhận trong phần ký : Tuyết Linh -> {err.reason}")
    naive_inner = sm.build_signed_inner("Anh được thăng chức. Ký tên: Thu Trang", "Thu Trang", A["sign_priv"])
    naive_env = sm.encrypt_for(naive_inner, "Thu Thủy", trusted_key("Thu Thủy", "encryption"))
    naive_fwd = sm.encrypt_for(sm.decrypt_envelope(naive_env, B["enc_priv"]), "Tuyết Linh",
                               trusted_key("Tuyết Linh", "encryption"))
    naive = sm.open_sealed(naive_fwd, "Tuyết Linh", people["Tuyết Linh"]["enc_priv"], sender_key)
    results["E_naive_fooled"] = naive["sender"] == "Thu Trang"
    say(f"    Ký rồi mã hóa NGÂY THƠ (không ghi người nhận): Tuyết Linh tin Thu Trang viết cho mình: "
        f"'{naive['message'].decode()}'")

    # ---------- F. Sai mục đích khóa ----------
    say("\n--- F. DÙNG KHÓA KÝ CỦA THU TRANG ĐỂ MÃ HÓA ---")
    ok, why = verify_certificate(A["sign_cert"], ca.certificate, ca.crl, usage="encryption")
    results["F_usage_blocked"] = not ok
    say(f"    Kiểm tra chứng thư: {why}")
    say("    (Dùng chung khóa thì 'nhờ ký' = 'giải mã hộ' — xem attacks/confidentiality.py.)")

    # ---------- Bảng tổng kết ----------
    say("\n--- TỔNG KẾT: CƠ CHẾ NÀO ĐẢM BẢO TÍNH CHẤT NÀO ---")
    rows = [("Tính chất", "Chỉ ký", "Chỉ mã hóa", "Ký rồi mã hóa"),
            ("Bảo mật (Confidentiality)", "Không", "Có", "Có"),
            ("Toàn vẹn (Integrity)", "Có", "Có*", "Có"),
            ("Chứng thực (Authentication)", "Có", "Không", "Có"),
            ("Chống chối bỏ (Non-repudiation)", "Có", "Không", "Có")]
    for r in rows:
        say(f"    {r[0]:<33}| {r[1]:<8}| {r[2]:<11}| {r[3]}")
    say("    * chỉ phát hiện sửa đổi ngẫu nhiên; kẻ tấn công vẫn tạo được thư mới hoàn toàn (mục D).")

    expected = {"A_sig_ok": True, "A_leaked": True, "B_eve_blocked": True, "B_bob_ok": True,
                "C_tamper_blocked": True, "D_forgery_blocked": True, "E_forward_blocked": True,
                "E_naive_fooled": True, "F_usage_blocked": True}
    success = all(results.get(k) == v for k, v in expected.items())
    say("\n[SUCCESS] Ký rồi mã hóa đạt đủ Bảo mật + Toàn vẹn + Chứng thực + Chống chối bỏ." if success
        else f"\n[FAILED] {results}")
    return success


if __name__ == "__main__":
    run_scenario_s6()
