from __future__ import annotations

from core.rsa_keygen import generate_keypair
from core.rsa_primitives import rsavp1
from core.signature import sign, sign_raw_no_hash, verify_detailed
from core.step_logger import StepLogger
from core.utils import i2osp, os2ip, byte_len
from attacks import AttackResult

NAME = "A1: Ký không băm → giả mạo nhờ tính nhân"


def run(logger: StepLogger | None = None, defended: bool = False, bits: int = 1024) -> AttackResult:
    log = logger if logger is not None else StepLogger()
    log.head(f"TẤN CÔNG A1: KÝ KHÔNG BĂM ({'CÓ' if defended else 'KHÔNG'} phòng chống)")
    pub, priv = generate_keypair(bits)
    m1, m2 = 2, 50_000_000
    target = m1 * m2
    log.note("[1] trang chịu ký hai lệnh vô hại", f"M1 = 'trả {m1} đồng', M2 = 'trả {m2:,} đồng'")

    if not defended:
        s1, s2 = sign_raw_no_hash(m1, priv), sign_raw_no_hash(m2, priv)
        log.log("    trang ký trực tiếp số (không băm, không đệm)", r"s_i = m_i^{d} \mathrm{mod}\ n",
                f"s1 = 0x{format(s1, 'x')[:32]}…\ns2 = 0x{format(s2, 'x')[:32]}…")
        s3 = (s1 * s2) % pub.n
        log.log("[2] phuong nhân hai chữ ký, không cần khoá riêng", r"s_3 = s_1 \cdot s_2 \mathrm{mod}\ n",
                f"s3 = 0x{format(s3, 'x')[:32]}…")
        success = rsavp1(pub, s3) == target % pub.n
        log.log("[3] Kiểm tra s3 cho M3 = M1·M2", r"s_3^{e} \mathrm{mod}\ n \equiv m_1 m_2",
                f"M3 = 'trả {target:,} đồng' → " + ("HỢP LỆ: giả mạo thành công" if success else "sai"),
                level="bad" if success else "ok")
    else:
        msg1, msg2 = f"trả {m1} đồng".encode(), f"trả {m2} đồng".encode()
        s1, s2 = sign(msg1, priv), sign(msg2, priv)
        log.note("    trang ký trên SHA-256(M) có đệm PKCS#1 v1.5")
        s3 = i2osp((os2ip(s1) * os2ip(s2)) % pub.n, byte_len(pub.n))
        res = verify_detailed(f"trả {target} đồng".encode(), s3, pub)
        success = res.valid
        log.log("[2] phuong vẫn nhân hai chữ ký và gắn vào M3", None, res.reason, level="bad" if success else "ok")

    summary = ("Giả mạo thành công: chữ ký RSA thuần có tính nhân." if success else
               "Thất bại: băm + đệm phá vỡ tính nhân.")
    (log.bad if success else log.ok)("[KẾT LUẬN] " + summary + " Phòng chống: ký trên băm có đệm.")
    return AttackResult(NAME, success, summary, {"defended": defended, "m1": m1, "m2": m2})
