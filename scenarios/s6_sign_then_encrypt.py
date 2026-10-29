from __future__ import annotations

import json
import secrets

from core.hash.sha256 import sha256
from core.number_theory import mod_pow
from core.padding.mgf1 import mgf1
from core.rsa_keygen import RSAPrivateKey, RSAPublicKey, generate_keypair
from core.signature import sign, verify_detailed
from core.step_logger import StepLogger
from core.utils import byte_len, canonical_json, constant_time_eq, from_hex, i2osp, os2ip
from pki.certificate import fmt_time, now
from scenarios import ScenarioResult

NAME = "S6: Ký rồi mã hoá (phong bì số)"
HASH_LEN = 32


class EnvelopeError(Exception):
    pass
def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def oaep_encrypt(message: bytes, pub: RSAPublicKey, label: bytes = b"") -> bytes:
    k = byte_len(pub.n)
    if len(message) > k - 2 * HASH_LEN - 2:
        raise ValueError("Thông điệp quá dài cho RSA-OAEP với khoá này")
    db = sha256(label) + b"\x00" * (k - len(message) - 2 * HASH_LEN - 2) + b"\x01" + message
    seed = secrets.token_bytes(HASH_LEN)
    masked_db = _xor(db, mgf1(seed, k - HASH_LEN - 1))
    masked_seed = _xor(seed, mgf1(masked_db, HASH_LEN))
    return i2osp(mod_pow(os2ip(b"\x00" + masked_seed + masked_db), pub.e, pub.n), k)


def oaep_decrypt(ciphertext: bytes, priv: RSAPrivateKey, label: bytes = b"") -> bytes:
    k = byte_len(priv.n)
    if len(ciphertext) != k or os2ip(ciphertext) >= priv.n:
        raise EnvelopeError("giải mã khoá phiên thất bại")
    em = i2osp(mod_pow(os2ip(ciphertext), priv.d, priv.n), k)
    masked_seed, masked_db = em[1:1 + HASH_LEN], em[1 + HASH_LEN:]
    seed = _xor(masked_seed, mgf1(masked_db, HASH_LEN))
    db = _xor(masked_db, mgf1(seed, k - HASH_LEN - 1))
    rest = db[HASH_LEN:]
    sep = rest.find(b"\x01")
    if em[0] != 0 or not constant_time_eq(db[:HASH_LEN], sha256(label)) or sep < 0 or any(rest[:sep]):
        raise EnvelopeError("giải mã khoá phiên thất bại")
    return rest[sep + 1:]
def _aesgcm():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as err:
        raise RuntimeError("S6 cần thư viện `cryptography` cho AES-GCM: pip install cryptography") from err
    return AESGCM


def signed_part(sender: str, to: str, t: int, message: bytes) -> bytes:
    return canonical_json({"from": sender, "to": to, "t": t}) + message


def seal(message: bytes, sender: str, sender_sign_priv: RSAPrivateKey, to: str, to_enc_pub: RSAPublicKey,
         t: int | None = None) -> dict:
    t = now() if t is None else t
    s = sign(signed_part(sender, to, t, message), sender_sign_priv)
    inner = canonical_json({"from": sender, "to": to, "t": t, "m": message.hex(), "s": s.hex()})
    return encrypt_inner(inner, to_enc_pub)


def encrypt_inner(inner: bytes, to_enc_pub: RSAPublicKey) -> dict:
    K, nonce = secrets.token_bytes(32), secrets.token_bytes(12)
    c2 = _aesgcm()(K).encrypt(nonce, inner, None)
    return {"C1": oaep_encrypt(K, to_enc_pub).hex(), "nonce": nonce.hex(), "C2": c2.hex()}


def decrypt_inner(envelope: dict, my_enc_priv: RSAPrivateKey) -> bytes:
    K = oaep_decrypt(from_hex(envelope["C1"]), my_enc_priv)
    try:
        return _aesgcm()(K).decrypt(from_hex(envelope["nonce"]), from_hex(envelope["C2"]), None)
    except Exception as err:                       # cryptography.exceptions.InvalidTag
        raise EnvelopeError("bản mã C2 bị sửa (thẻ xác thực GCM sai)") from err


def open_envelope(envelope: dict, me: str, my_enc_priv: RSAPrivateKey,
                  sign_keys: dict[str, RSAPublicKey]) -> dict:
    inner = json.loads(decrypt_inner(envelope, my_enc_priv))
    sender, message = inner["from"], from_hex(inner["m"])
    pub = sign_keys.get(sender)
    if pub is None:
        raise EnvelopeError(f"không có khoá công khai của người gửi '{sender}'")
    res = verify_detailed(signed_part(sender, inner["to"], inner["t"], message), from_hex(inner["s"]), pub)
    if not res.valid:
        raise EnvelopeError(f"chữ ký của '{sender}' không hợp lệ: {res.reason}")
    if inner["to"] != me:
        raise EnvelopeError(f"chữ ký hợp lệ nhưng '{sender}' ký thư gửi cho '{inner['to']}', không phải '{me}' "
                            "→ thư bị chuyển tiếp lén")
    return {"from": sender, "to": inner["to"], "t": inner["t"], "message": message}


def run(logger: StepLogger | None = None, bits: int = 2048) -> ScenarioResult:
    log = logger if logger is not None else StepLogger()
    log.head("KỊCH BẢN S6: KÝ RỒI MÃ HOÁ (PHONG BÌ SỐ)")
    _aesgcm()

    trang_sign_pub, trang_sign_priv = generate_keypair(bits)
    thuy_enc_pub, thuy_enc_priv = generate_keypair(bits)
    linh_enc_pub, linh_enc_priv = generate_keypair(bits)
    phuong_enc_pub, phuong_enc_priv = generate_keypair(bits)
    sign_keys = {"trang": trang_sign_pub}
    log.note("[1] Trang (Sender), Thủy (Receiver), Phương (Attacker) và Linh (Third Party) có khoá riêng", "trang_sign, thuy_enc, linh_enc, phuong_enc")

    message = "thuy thân mến, mật khẩu kho dữ liệu dự án là: X7#kq-2026. trang.".encode("utf-8")
    env = seal(message, "trang", trang_sign_priv, "thuy", thuy_enc_pub)
    log.log("[2] Trang (Sender) ký rồi mã hoá gửi Thủy (Receiver)", r"s = \mathrm{Sign}_{d_A}(H(to \| t \| M)),\; C_2 = \mathrm{AES{-}GCM}_K(M \| s),\; C_1 = \mathrm{RSA{-}Enc}_{e_B}(K)",
            f"C1 = {env['C1'][:48]}…\nC2 = {env['C2'][:48]}… ({len(env['C2']) // 2} byte)")
    log.log("    Phương (Attacker) nghe lén chỉ thấy C1, nonce, C2", None,
            f"Bản rõ có xuất hiện trong gói tin? {message.hex() in json.dumps(env)}", level="ok")

    try:
        opened = open_envelope(env, "thuy", thuy_enc_priv, sign_keys)
        thuy_ok = opened["message"] == message
        log.log("[3] Thủy (Receiver) giải mã K, C2 và kiểm tra chữ ký của Trang", None,
                f"Người gửi: {opened['from']}, gửi cho: {opened['to']}, lúc {fmt_time(opened['t'])}\n"
                f"M = {opened['message'].decode()}", level="ok" if thuy_ok else "bad")
    except EnvelopeError as err:
        thuy_ok = False
        log.bad("[3] Thủy không mở được phong bì", str(err))

    def attempt(title: str, fn) -> bool:
        try:
            fn()
            log.bad(title, "mở được — lỗi!")
            return True
        except EnvelopeError as err:
            log.ok(title, f"bị chặn: {err}")
            return False

    phuong_ok = attempt("[4] Phương (Attacker) mở phong bì bằng khoá riêng của mình",
                         lambda: open_envelope(env, "phuong", phuong_enc_priv, sign_keys))
    bad = dict(env)
    c2 = bytearray(from_hex(env["C2"]))
    c2[len(c2) // 2] ^= 0x01
    bad["C2"] = c2.hex()
    tamper_ok = attempt("[5] Phương (Attacker) lật 1 bít trong C2 rồi chuyển cho Thủy",
                        lambda: open_envelope(bad, "thuy", thuy_enc_priv, sign_keys))
    forwarded = encrypt_inner(decrypt_inner(env, thuy_enc_priv), linh_enc_pub)
    forward_ok = attempt("[6] Thủy chuyển tiếp (M, s) cho Linh (Third Party)",
                         lambda: open_envelope(forwarded, "linh", linh_enc_priv, sign_keys))

    valid = thuy_ok and not phuong_ok and not tamper_ok and not forward_ok
    summary = ("Phong bì số cho cả bảo mật (chỉ Thủy đọc được) lẫn chứng thực; ký kèm người nhận chặn chuyển tiếp lén."
               if valid else "Kịch bản S6 không đạt.")
    (log.ok if valid else log.bad)("[KẾT LUẬN] " + summary)
    return ScenarioResult(NAME, valid, summary, {
        "thuy_opens": thuy_ok, "phuong_opens": phuong_ok, "tampered_accepted": tamper_ok,
        "forward_accepted": forward_ok,
    })
