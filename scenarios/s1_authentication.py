"""
scenarios/s1_authentication.py
[Báo cáo 4.2, 4.7, 6.5]
Kịch bản S1: Xác thực danh tính người dùng (Authentication) bằng Thách - Đáp (Challenge-Response)
và chữ ký số: Server gửi nonce ngẫu nhiên, Alice ký nonce, Server kiểm tra bằng khóa trong chứng thư.
"""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.rsa_math import generate_keypair
from core.rsa_full import sign_message, verify_message
from pki.cert import CertificateAuthority, verify_certificate
from pki.timestamp import NonceRegistry


class AuthServer:
    """Server xác thực: phát nonce dùng một lần, kiểm tra chứng thư + chữ ký trên nonce."""

    def __init__(self, ca_cert, crl):
        self.ca_cert, self.crl = ca_cert, crl
        self.nonces = NonceRegistry()

    def challenge(self, username):
        return self.nonces.issue(username)

    def respond(self, cert, nonce, signature):
        ok, why = self.nonces.consume(nonce, cert["subject"])
        if not ok:
            return False, why
        ok, why = verify_certificate(cert, self.ca_cert, self.crl, usage="signature")
        if not ok:
            return False, why
        if not verify_message(nonce, signature, cert["public_key"]):
            return False, "Chữ ký trên nonce không hợp lệ"
        return True, f"Đã xác thực: {cert['subject']}"


def run_scenario_s1(keysize=1024, verbose=True):
    say = print if verbose else (lambda *a, **k: None)
    say("\n=======================================================")
    say("KỊCH BẢN S1: XÁC THỰC NGƯỜI DÙNG (AUTHENTICATION)")
    say("=======================================================")

    ca = CertificateAuthority("CA Goc ATBMTT", keysize=keysize)
    alice_priv, alice_pub = generate_keypair(keysize=keysize)
    alice_cert = ca.issue_certificate("Alice", alice_pub)
    server = AuthServer(ca.certificate, ca.crl)

    nonce = server.challenge("Alice")
    say(f"[1] Server gửi chuỗi thử thách (nonce ngẫu nhiên): '{nonce}'")
    sig = sign_message(nonce, alice_priv)
    say(f"[2] Alice ký nonce bằng khóa riêng: S = {str(sig)[:30]}...")
    ok, msg = server.respond(alice_cert, nonce, sig)
    say(f"[3] Server kiểm tra chứng thư + chữ ký: {msg}")

    # Eve không có khóa riêng của Alice, ký bằng khóa của mình
    eve_priv, eve_pub = generate_keypair(keysize=keysize)
    nonce2 = server.challenge("Alice")
    fake_ok, fake_msg = server.respond(alice_cert, nonce2, sign_message(nonce2, eve_priv))
    say(f"[4] Eve mạo danh Alice, ký bằng khóa của Eve: {'chấp nhận' if fake_ok else 'TỪ CHỐI'} ({fake_msg})")

    # Eve tự tạo chứng thư "Alice" bằng CA của mình
    eve_ca = CertificateAuthority("CA Goc ATBMTT", keysize=keysize)
    nonce3 = server.challenge("Alice")
    cert_ok, cert_msg = server.respond(eve_ca.issue_certificate("Alice", eve_pub), nonce3,
                                       sign_message(nonce3, eve_priv))
    say(f"[5] Eve dùng chứng thư 'Alice' do CA giả cấp: {'chấp nhận' if cert_ok else 'TỪ CHỐI'} ({cert_msg})")
    say("    (Tấn công phát lại gói (nonce, S) cũ: xem kịch bản S4)")

    success = ok and not fake_ok and not cert_ok
    say("[SUCCESS] Chỉ người giữ khóa riêng của Alice mới xác thực được." if success else "[FAILED]")
    return success


if __name__ == "__main__":
    run_scenario_s1()
