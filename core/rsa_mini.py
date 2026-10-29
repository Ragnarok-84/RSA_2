# Tệp: core/rsa_mini.py   [Báo cáo 3.5 - Ví dụ tính tay]
# BẢN THU NHỎ (tính tay) của hệ chữ ký RSA, dùng bộ số trên lớp: p=17, q=11, e=7, M=88.
#   Phần 1: Sinh khóa, mã hóa / giải mã, ký / kiểm tra trực tiếp trên M (RSA sách giáo khoa)
#   Phần 2: Ký trên GIÁ TRỊ BĂM: h = SHA256(M) mod N  (thu nhỏ của ký-trên-băm thực tế)
#   Phần 3: TÍNH BẢO MẬT — Thu Trang ký rồi mã hóa gửi Thu Thủy (Thu Thủy: p=23, q=29, e=3)
# Mỗi phép lũy thừa đều in các bước của thuật toán bình phương và nhân để đối chiếu tính tay.
import os as _os
import sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))

from core.rsa_math import generate_keypair, explain_keygen, mod_exp
from core.sha256 import hash_sha256

P, Q, E, M = 17, 11, 7, 88                       # Thu Trang (ví dụ trên lớp)
BOB_P, BOB_Q, BOB_E = 23, 29, 3                  # Thu Thủy: N_B = 667 > N_A = 187


def encrypt(m, public_key):
    """C = M^e mod N"""
    e, N = public_key
    if not 0 <= m < N:
        raise ValueError(f"Bản rõ phải thỏa 0 <= M < N = {N}")
    return mod_exp(m, e, N)


def decrypt(c, private_key):
    """M = C^d mod N"""
    d, N = private_key
    return mod_exp(c, d, N)


def sign(m, private_key):
    """Ký số (bản thu nhỏ, không băm/đệm): S = M^d mod N"""
    d, N = private_key
    return mod_exp(m, d, N)


def verify(m, s, public_key):
    """Kiểm tra: M' = S^e mod N, so sánh với M"""
    e, N = public_key
    return mod_exp(s, e, N) == m


def tiny_hash(message, N):
    """Băm thu nhỏ: SHA-256 rồi lấy dư theo N (để giá trị băm nằm trong [0, N))."""
    return int(hash_sha256(message), 16) % N


def show_mod_exp(base, exp, mod, label, say):
    """In bảng bình phương và nhân cho base^exp mod mod, trả về kết quả."""
    trace = []
    result = mod_exp(base, exp, mod, trace)
    say(f"  {label} = {base}^{exp} mod {mod}, số mũ {exp} = {bin(exp)[2:]} (nhị phân)")
    say("     bit | thao tác          | kết quả")
    for bit, value in trace:
        op = "bình phương, nhân" if bit == "1" else "bình phương      "
        say(f"      {bit}  | {op} | {value}")
    say(f"  => {label} = {result}")
    return result


def run_demo(verbose=True):
    say = print if verbose else (lambda *a, **k: None)
    private_key, public_key = generate_keypair(p=P, q=Q, e=E)
    d, N = private_key
    phi = (P - 1) * (Q - 1)

    say("=" * 60)
    say(f"PHẦN 1 — RSA THU NHỎ: p={P}, q={Q}, e={E}, M={M}")
    say("=" * 60)
    say("--- Bước 1: Sinh khóa ---")
    for line in explain_keygen(P, Q, E):
        say("  " + line)
    say(f"  Khóa công khai (e, N) = {public_key}   Khóa riêng (d, N) = {private_key}")

    say("\n--- Bước 2: Mã hóa ---")
    C = show_mod_exp(M, E, N, "C", say)
    say("\n--- Bước 3: Giải mã ---")
    M2 = show_mod_exp(C, d, N, "M", say)
    say("  Giải mã đúng bản rõ: " + ("Thành công" if M2 == M else "Thất bại"))

    say("\n--- Bước 4: Ký số & kiểm tra (ký trực tiếp trên M) ---")
    S = show_mod_exp(M, d, N, "S", say)
    verify_ok = verify(M, S, public_key)
    verify_tampered = verify(M + 1, S, public_key)
    say(f"  Kiểm tra: S^e mod N = {S}^{E} mod {N} = {mod_exp(S, E, N)} " + ("= M" if verify_ok else "≠ M"))
    say(f"  Với M bị sửa (M={M + 1}): " + ("chấp nhận" if verify_tampered else "BỊ TỪ CHỐI"))

    # ---------------- Phần 2: ký trên giá trị băm ----------------
    doc = "Hop dong 01"
    h = tiny_hash(doc, N)
    say("\n" + "=" * 60)
    say("PHẦN 2 — KÝ TRÊN GIÁ TRỊ BĂM (thu nhỏ)")
    say("=" * 60)
    say(f"  Tài liệu: '{doc}'")
    say(f"  SHA-256 = {hash_sha256(doc)}")
    say(f"  h = SHA-256 mod N = {h}")
    S_h = show_mod_exp(h, d, N, "S", say)
    hash_ok = mod_exp(S_h, E, N) == tiny_hash(doc, N)
    hash_tampered = mod_exp(S_h, E, N) == tiny_hash("Hop dong 02", N)
    say(f"  Bên nhận: S^e mod N = {mod_exp(S_h, E, N)}, tự băm lại = {tiny_hash(doc, N)} -> "
        + ("HỢP LỆ" if hash_ok else "SAI"))
    say(f"  Tài liệu bị sửa thành 'Hop dong 02' (h = {tiny_hash('Hop dong 02', N)}) -> "
        + ("chấp nhận" if hash_tampered else "BỊ TỪ CHỐI"))

    # ---------------- Phần 3: tính bảo mật ----------------
    conf = run_confidentiality_demo(private_key, public_key, say)

    return {"N": N, "phi": phi, "d": d, "C": C, "M2": M2, "S": S,
            "verify_ok": verify_ok, "verify_tampered": verify_tampered,
            "hash_value": h, "hash_signature": S_h, "hash_ok": hash_ok, "hash_tampered": hash_tampered,
            **conf}


def run_confidentiality_demo(alice_priv, alice_pub, say):
    """Phần 3: Thu Trang ký bằng d_A rồi mã hóa bằng e_B. Cần N_A < N_B để S < N_B."""
    bob_priv, bob_pub = generate_keypair(p=BOB_P, q=BOB_Q, e=BOB_E)
    dA, NA = alice_priv
    dB, NB = bob_priv
    say("\n" + "=" * 60)
    say("PHẦN 3 — TÍNH BẢO MẬT: KÝ RỒI MÃ HÓA")
    say("=" * 60)
    say("  Chữ ký chỉ chứng thực, KHÔNG che nội dung: Mai Phương thấy (M, S) = "
        f"({M}, {sign(M, alice_priv)}) và đọc được M ngay.")
    say(f"  Thu Thủy: p={BOB_P}, q={BOB_Q}, e={BOB_E}")
    for line in explain_keygen(BOB_P, BOB_Q, BOB_E):
        say("    " + line)
    say(f"  Lưu ý: N_A = {NA} < N_B = {NB} nên S (< N_A) mã hóa được bằng khóa của Thu Thủy.")

    say("\n  [Thu Trang] 1) Ký bằng khóa riêng của mình:")
    S = show_mod_exp(M, dA, NA, "S", say)
    say("  [Thu Trang] 2) Mã hóa M và S bằng khóa CÔNG KHAI của Thu Thủy:")
    C1 = show_mod_exp(M, BOB_E, NB, "C1", say)
    C2 = show_mod_exp(S, BOB_E, NB, "C2", say)
    say(f"  -> Gửi (C1, C2) = ({C1}, {C2}). Mai Phương chỉ thấy hai số này.")

    say("\n  [Thu Thủy] 3) Giải mã bằng khóa riêng của Thu Thủy:")
    M_b = show_mod_exp(C1, dB, NB, "M", say)
    S_b = show_mod_exp(C2, dB, NB, "S", say)
    say("  [Thu Thủy] 4) Kiểm tra chữ ký bằng khóa công khai của Thu Trang:")
    sig_ok = verify(M_b, S_b, alice_pub)
    say(f"     S^e_A mod N_A = {S_b}^{alice_pub[0]} mod {NA} = {mod_exp(S_b, alice_pub[0], NA)} "
        + ("= M (đúng là Thu Trang, nội dung nguyên vẹn)" if sig_ok else "≠ M"))

    # Tấn công từ điển vào RSA sách giáo khoa (tất định)
    say(f"\n  [Mai Phương] Không có d_B nên không giải mã trực tiếp được (phải phân tích N_B = {NB}).")
    say("  [Mai Phương] Nhưng RSA sách giáo khoa là TẤT ĐỊNH: Mai Phương thử mọi M' < N_A, tính M'^e_B mod N_B:")
    recovered = next(m for m in range(NA) if mod_exp(m, BOB_E, NB) == C1)
    say(f"        tìm được M' = {recovered} khớp C1 -> Mai Phương ĐỌC ĐƯỢC bản rõ")
    say("        => Thực tế phải dùng RSA-OAEP (thêm ngẫu nhiên) + khóa >= 2048 bit (xem kịch bản S6 - tính bảo mật).")

    return {"conf_S": S, "conf_C1": C1, "conf_C2": C2, "conf_M": M_b, "conf_sig_ok": sig_ok,
            "conf_dict_attack": recovered, "bob_d": dB, "bob_N": NB}


if __name__ == "__main__":
    run_demo()
