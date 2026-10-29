"""
attacks/crt_fault.py
[Báo cáo 3.6.2 - Lỗi khi ký bằng CRT (Boneh–DeMillo–Lipton 1997, biến thể Lenstra); 6.4]
Thẻ thông minh / HSM thường ký bằng định lý số dư Trung Hoa (CRT) cho nhanh gấp ~4 lần:
    s_p = EM^(d mod p-1) mod p,   s_q = EM^(d mod q-1) mod q,   S = ghép (s_p, s_q) bằng CRT.
Nếu một lỗi phần cứng (sụt áp, tia laser, quá nhiệt) làm sai s_q, chữ ký lỗi S' vẫn đúng modulo p
nhưng sai modulo q, nên:   gcd(S'^e - EM, N) = p.
Chỉ MỘT chữ ký lỗi + thông điệp (EM của PKCS#1 v1.5 là tất định) là đủ phân tích N.
"""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.rsa_math import generate_keypair, generate_prime, gcd, mod_inverse, mod_exp, byte_length
from core.rsa_full import sign_message, verify_message
from core.padding import add_pkcs1_v15_padding
from core.sha256 import hash_sha256


class FaultDetected(Exception):
    """Thiết bị phát hiện chữ ký tính sai và không trả chữ ký ra ngoài."""


class SmartCard:
    """Thẻ ký mô phỏng: giữ p, q bên trong, ký PKCS#1 v1.5 bằng CRT."""

    def __init__(self, keysize, check_before_release):
        half = keysize // 2
        self._p, self._q = generate_prime(half), generate_prime(keysize - half)
        priv, self.public_key = generate_keypair(p=self._p, q=self._q)
        d = priv[0]
        self._dp, self._dq = d % (self._p - 1), d % (self._q - 1)
        self._q_inv = mod_inverse(self._q, self._p)
        self.check = check_before_release
        self.glitch = False                         # True: lần ký tới bị lỗi phần cứng

    def sign(self, message):
        e, n = self.public_key
        em = add_pkcs1_v15_padding(hash_sha256(message), byte_length(n))
        s_p = mod_exp(em % self._p, self._dp, self._p)
        s_q = mod_exp(em % self._q, self._dq, self._q)
        if self.glitch:
            s_q ^= 1 << 7                           # 1 bit bị lật trong thanh ghi
            self.glitch = False
        s = s_q + self._q * ((self._q_inv * (s_p - s_q)) % self._p)
        if self.check and mod_exp(s, e, n) != em:   # biện pháp: tự kiểm tra trước khi trả chữ ký
            raise FaultDetected("Chữ ký tính sai -> thẻ từ chối trả kết quả")
        return s


def attack_fault(public_key, message, faulty_signature):
    """Từ một chữ ký lỗi: p = gcd(S'^e - EM, N). :return: (p, q, d) hoặc None"""
    e, n = public_key
    em = add_pkcs1_v15_padding(hash_sha256(message), byte_length(n))
    p = gcd((mod_exp(faulty_signature, e, n) - em) % n, n)
    if not 1 < p < n:
        return None
    q = n // p
    return p, q, mod_inverse(e, (p - 1) * (q - 1))


def demo_crt_fault(keysize=1024, verbose=True):
    """:return: (thẻ không tự kiểm tra bị lộ khóa, thẻ tự kiểm tra không lộ)"""
    say = print if verbose else (lambda *a, **k: None)
    doc = "Biên bản bàn giao thiết bị số 15"
    card = SmartCard(keysize, check_before_release=False)
    pub = card.public_key
    good = card.sign(doc)
    say(f"[1] Thẻ thông minh của Thu Trang ký bằng CRT ({keysize} bit). Chữ ký bình thường hợp lệ: "
        f"{verify_message(doc, good, pub)}")
    card.glitch = True
    bad = card.sign(doc)
    say(f"[2] Mai Phương gây sụt áp đúng lúc thẻ tính s_q -> nhận chữ ký lỗi. Hợp lệ: {verify_message(doc, bad, pub)}")
    res = attack_fault(pub, doc, bad)
    broken = False
    if res:
        p, q, d = res
        fake = "Thu Trang ủy quyền toàn bộ tài khoản cho Mai Phương"
        broken = verify_message(fake, sign_message(fake, (d, pub[1])), pub)
        say(f"[3] Mai Phương tính gcd(S'^e - EM, N) = p ({p.bit_length()} bit) -> q, d")
        say(f"    Mai Phương ký giả '{fake}': {'HỢP LỆ -> lộ khóa chỉ với 1 chữ ký lỗi' if broken else 'sai'}")

    safe_card = SmartCard(keysize, check_before_release=True)
    safe_card.glitch = True
    try:
        safe_card.sign(doc)
        protected = False
        say("[4] Thẻ có tự kiểm tra vẫn trả chữ ký lỗi (lỗi!)")
    except FaultDetected as err:
        protected = True
        say(f"[4] Thẻ có tự kiểm tra S^e = EM trước khi trả: {err} -> Mai Phương không có gì để tính gcd")
    say("[!] Phòng chống: kiểm tra lại chữ ký trước khi xuất; dùng PSS (EM ngẫu nhiên, Mai Phương không biết EM).")
    return broken, protected


if __name__ == "__main__":
    demo_crt_fault()
