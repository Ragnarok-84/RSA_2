"""Ký, kiểm tra, ký rồi mã hóa tệp thật."""
import argparse
import getpass
import json
import os
import secrets
import shutil
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from core.rsa_math import generate_keypair, compare_hashes
from core.sha256 import hash_file
from core.hmac_utils import generate_hmac, pbkdf2_hmac_sha256
from core.rsa_full import sign_hash, verify_hash
from core import secure_message as sm

PBKDF2_ITERATIONS = 2000      # demo; thực tế OWASP khuyến nghị >= 600.000 lần với HMAC-SHA256
ALGORITHM = "RSASSA-PKCS1-v1_5 + SHA-256"


# Lưu / nạp khóa
def save_keypair(name, private_key, public_key, workdir=".", usage="signature", password=None):
    """Ghi <name>.private.json và <name>.public.json. Trả về (đường dẫn khóa riêng, khóa công khai)."""
    os.makedirs(workdir, exist_ok=True)
    priv_path = os.path.join(workdir, f"{name}.private.json")
    pub_path = os.path.join(workdir, f"{name}.public.json")
    d, N = private_key
    e, _ = public_key
    priv = {"owner": name, "type": "private", "usage": usage, "N": hex(N), "e": e}
    if password:
        # Mã hóa d bằng khóa sinh từ mật khẩu (PBKDF2), xác thực bằng HMAC
        salt, nonce = secrets.token_bytes(16), secrets.token_bytes(sm.NONCE_LEN)
        k_enc, k_mac = sm.derive_keys(pbkdf2_hmac_sha256(password, salt, PBKDF2_ITERATIONS))
        d_bytes = d.to_bytes((d.bit_length() + 7) // 8, "big")
        ct = sm.keystream_xor(k_enc, nonce, d_bytes)
        priv["protected"] = {"kdf": "PBKDF2-HMAC-SHA256", "iterations": PBKDF2_ITERATIONS,
                             "salt": salt.hex(), "nonce": nonce.hex(), "d_enc": ct.hex(),
                             "tag": generate_hmac(k_mac, nonce + ct)}
    else:
        priv["d"] = hex(d)
    with open(priv_path, "w", encoding="utf-8") as f:
        json.dump(priv, f, indent=2)
    with open(pub_path, "w", encoding="utf-8") as f:
        json.dump({"owner": name, "type": "public", "usage": usage, "e": e, "N": hex(N)}, f, indent=2)
    return priv_path, pub_path


def _read_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def load_private_key(path, password=None, with_owner=False):
    data = _read_json(path)
    N = int(data["N"], 16)
    if "protected" in data:
        p = data["protected"]
        if password is None:
            password = getpass.getpass(f"Mật khẩu cho khóa riêng {os.path.basename(path)}: ")
        k_enc, k_mac = sm.derive_keys(pbkdf2_hmac_sha256(password, bytes.fromhex(p["salt"]), p["iterations"]))
        nonce, ct = bytes.fromhex(p["nonce"]), bytes.fromhex(p["d_enc"])
        if not compare_hashes(generate_hmac(k_mac, nonce + ct), p["tag"]):
            raise ValueError("Sai mật khẩu (hoặc tệp khóa bị sửa)")
        d = int.from_bytes(sm.keystream_xor(k_enc, nonce, ct), "big")
    else:
        d = int(data["d"], 16)
    return ((d, N), data["owner"]) if with_owner else (d, N)


def load_public_key(path, with_owner=False):
    data = _read_json(path)
    key = (data["e"], int(data["N"], 16))
    return (key, data["owner"]) if with_owner else key


# Ký / kiểm tra tệp
def sign_file(path, private_key, signer="?", sig_path=None):
    h = hash_file(path)
    s = sign_hash(h, private_key)
    sig = {"file": os.path.basename(path), "size": os.path.getsize(path), "sha256": h,
           "signer": signer, "algorithm": ALGORITHM, "time": time.strftime("%Y-%m-%d %H:%M:%S"),
           "signature": hex(s)}
    sig_path = sig_path or path + ".sig.json"
    with open(sig_path, "w", encoding="utf-8") as f:
        json.dump(sig, f, indent=2, ensure_ascii=False)
    return sig_path, sig


def verify_file(path, public_key, sig_path=None):
    """:return: (True/False, lý do)"""
    sig = _read_json(sig_path or path + ".sig.json")
    h = hash_file(path)
    if not compare_hashes(h, sig["sha256"]):
        return False, f"Tệp đã bị thay đổi (SHA-256 hiện tại {h[:16]}... ≠ {sig['sha256'][:16]}...)"
    if not verify_hash(h, int(sig["signature"], 16), public_key):
        return False, "Chữ ký không khớp khóa công khai (sai người ký hoặc chữ ký bị sửa)"
    return True, f"Chữ ký hợp lệ của '{sig['signer']}' lúc {sig['time']}"


# Ký rồi mã hóa tệp
def seal_file(path, sender, sender_private_key, recipient, recipient_public_key, out_path=None):
    with open(path, "rb") as f:
        data = f.read()
    env = sm.seal(data, sender, sender_private_key, recipient, recipient_public_key,
                  filename=os.path.basename(path))
    out_path = out_path or path + ".enc.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(env, f)
    return out_path


def open_file(env_path, me, my_private_key, sender_keys, out_dir="."):
    """
    :param sender_keys: dict tên -> khóa công khai (ký) của những người gửi mình tin cậy
    :return: (đường dẫn tệp khôi phục, kết quả open_sealed)
    """
    env = _read_json(env_path)
    res = sm.open_sealed(env, me, my_private_key, sender_keys.get)
    name = os.path.basename(res["meta"].get("filename") or "giai_ma.bin")   # chống path traversal
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, name)
    with open(out_path, "wb") as f:
        f.write(res["message"])
    return out_path, res


# Demo trên tệp thật
HERE = ROOT
DEFAULT_SAMPLE = os.path.join(ROOT, "samples", "anh_mau.png")


def _tamper_copy(path, workdir):
    bad = os.path.join(workdir, "bi_sua_" + os.path.basename(path))
    shutil.copyfile(path, bad)
    with open(bad, "r+b") as f:
        f.seek(os.path.getsize(bad) // 2)
        b = f.read(1)
        f.seek(-1, 1)
        f.write(bytes([b[0] ^ 0x01]))           # đổi đúng 1 bit
    return bad


def demo_sign_file(path=None, keysize=1024, workdir=None, verbose=True):
    say = print if verbose else (lambda *a, **k: None)
    path = path or DEFAULT_SAMPLE
    workdir = workdir or os.path.join(HERE, "output")
    os.makedirs(workdir, exist_ok=True)
    say(f"[1] Tệp: {path} ({os.path.getsize(path):,} byte)")
    priv, pub = generate_keypair(keysize=keysize)
    save_keypair("thutrang", priv, pub, workdir)
    say(f"[2] Sinh khóa {keysize} bit, lưu thutrang.private.json / thutrang.public.json vào {workdir}")
    t = time.perf_counter()
    sig_path, sig = sign_file(path, priv, "Thu Trang", os.path.join(workdir, os.path.basename(path) + ".sig.json"))
    say(f"[3] Ký tệp ({time.perf_counter() - t:.2f}s): SHA-256 = {sig['sha256']}")
    say(f"    Chữ ký lưu tại {sig_path}")
    ok, why = verify_file(path, pub, sig_path)
    say(f"[4] Kiểm tra tệp gốc   : {'HỢP LỆ' if ok else 'SAI'} — {why}")
    bad = _tamper_copy(path, workdir)
    bad_ok, bad_why = verify_file(bad, pub, sig_path)
    say(f"[5] Đổi 1 bit trong tệp: {'hợp lệ' if bad_ok else 'BỊ TỪ CHỐI'} — {bad_why}")
    return {"valid_original": ok, "valid_tampered": bad_ok, "sig_path": sig_path}


def demo_seal_file(path=None, keysize=1024, workdir=None, verbose=True):
    say = print if verbose else (lambda *a, **k: None)
    path = path or DEFAULT_SAMPLE
    workdir = workdir or os.path.join(HERE, "output")
    os.makedirs(workdir, exist_ok=True)
    a_priv, a_pub = generate_keypair(keysize=keysize)
    b_priv, b_pub = generate_keypair(keysize=keysize)
    e_priv, _ = generate_keypair(keysize=keysize)
    say(f"[1] Thu Trang ký rồi mã hóa tệp {os.path.basename(path)} ({os.path.getsize(path):,} byte) gửi Thu Thủy")
    t = time.perf_counter()
    enc = seal_file(path, "Thu Trang", a_priv, "Thu Thủy", b_pub, os.path.join(workdir, os.path.basename(path) + ".enc.json"))
    t_seal = time.perf_counter() - t
    say(f"    -> {enc} ({os.path.getsize(enc):,} byte, {t_seal:.2f}s)")
    with open(enc, encoding="utf-8") as f:
        say(f"    Nội dung Mai Phương thấy: {f.read(120)}...")
    try:
        open_file(enc, "Thu Thủy", e_priv, {"Thu Trang": a_pub}, os.path.join(workdir, "maiphuong"))
        eve_blocked = False
    except sm.SecureMessageError as err:
        eve_blocked = True
        say(f"[2] Mai Phương mở bằng khóa của mình: {err.reason}")
    t = time.perf_counter()
    out, res = open_file(enc, "Thu Thủy", b_priv, {"Thu Trang": a_pub}, os.path.join(workdir, "thuthuy_nhan"))
    t_open = time.perf_counter() - t
    with open(path, "rb") as f1, open(out, "rb") as f2:
        same = f1.read() == f2.read()
    say(f"[3] Thu Thủy giải mã ({t_open:.2f}s) -> {out}")
    say(f"    Người gửi đã xác minh: {res['sender']} | Giống hệt tệp gốc: {'CÓ' if same else 'KHÔNG'}")
    return {"restored_equal": same, "eve_blocked": eve_blocked, "sender": res["sender"],
            "seal_seconds": t_seal, "open_seconds": t_open, "output": out}


# Dòng lệnh
def main(argv=None):
    ap = argparse.ArgumentParser(description="Ký / kiểm tra / ký-rồi-mã-hóa tệp bằng RSA tự cài")
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("keygen"); g.add_argument("--name", required=True); g.add_argument("--bits", type=int, default=2048)
    g.add_argument("--usage", default="signature", choices=["signature", "encryption"])
    g.add_argument("--out", default="."); g.add_argument("--password", action="store_true", help="mã hóa khóa riêng")
    s = sub.add_parser("sign"); s.add_argument("file"); s.add_argument("--key", required=True)
    v = sub.add_parser("verify"); v.add_argument("file"); v.add_argument("--pub", required=True); v.add_argument("--sig")
    se = sub.add_parser("seal"); se.add_argument("file"); se.add_argument("--key", required=True); se.add_argument("--to", required=True)
    op = sub.add_parser("open"); op.add_argument("file"); op.add_argument("--key", required=True)
    op.add_argument("--sender", required=True, action="append"); op.add_argument("--out", default=".")
    sub.add_parser("demo")
    a = ap.parse_args(argv)

    try:
        if a.cmd == "keygen":
            pw = getpass.getpass("Đặt mật khẩu bảo vệ khóa riêng: ") if a.password else None
            priv, pub = generate_keypair(keysize=a.bits)
            print("Đã ghi:", *save_keypair(a.name, priv, pub, a.out, a.usage, pw))
        elif a.cmd == "sign":
            priv, owner = load_private_key(a.key, with_owner=True)
            print("Đã ghi chữ ký:", sign_file(a.file, priv, owner)[0])
        elif a.cmd == "verify":
            ok, why = verify_file(a.file, load_public_key(a.pub), a.sig)
            print(("HỢP LỆ: " if ok else "KHÔNG HỢP LỆ: ") + why)
            return 0 if ok else 1
        elif a.cmd == "seal":
            priv, me = load_private_key(a.key, with_owner=True)
            pub, to = load_public_key(a.to, with_owner=True)
            print("Đã ghi phong bì:", seal_file(a.file, me, priv, to, pub))
        elif a.cmd == "open":
            priv, me = load_private_key(a.key, with_owner=True)
            senders = dict((o, k) for k, o in (load_public_key(p, with_owner=True) for p in a.sender))
            out, res = open_file(a.file, me, priv, senders, a.out)
            print(f"Đã giải mã: {out}\nNgười gửi (chữ ký hợp lệ): {res['sender']} lúc {res['meta']['time']}")
        elif a.cmd == "demo":
            demo_sign_file()
            print()
            demo_seal_file()
    except (sm.SecureMessageError, ValueError, OSError) as err:
        print("LỖI:", getattr(err, "reason", err))
        return 1
    return 0


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    sys.exit(main())
