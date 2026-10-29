# Tệp: core/secure_message.py   [bổ sung - TÍNH BẢO MẬT, báo cáo mục bảo mật]
# KẾT HỢP CHỮ KÝ SỐ + MÃ HÓA: "Ký rồi mã hóa" (Sign-then-Encrypt) theo mô hình mã hóa lai.
#
#   Người gửi (Thu Trang)                               Người nhận (Thu Thủy)
#   ---------------------------------------------   ---------------------------------------------
#   1. meta = {from, to, tên tệp, SHA256(M), time}
#      S = Sign_dA(meta)            (chữ ký RSA)
#   2. inner = meta || S || M
#   3. K ngẫu nhiên 32 byte (khóa phiên)
#      ct  = inner XOR KeyStream(K_enc, nonce)  ->   4. K = OAEP-Decrypt_dB(ek)       (chỉ Thu Thủy làm được)
#      tag = HMAC(K_mac, nonce || ct)           ->   5. kiểm tra tag  (phát hiện sửa bản mã)
#      ek  = OAEP-Encrypt_eB(K)                 ->   6. giải mã ct -> inner -> kiểm tra meta.to == Thu Thủy
#                                                     7. Verify_eA(meta, S), SHA256(M) == meta.sha256
#
# Đạt được cả 4 tính chất:
#   BẢO MẬT     : chỉ người giữ dB mới lấy được K -> đọc được M (kẻ nghe lén chỉ thấy bản mã).
#   TOÀN VẸN    : HMAC trên bản mã + băm SHA-256 của M nằm trong phần được ký.
#   CHỨNG THỰC  : chữ ký RSA của Thu Trang (khóa công khai lấy từ chứng thư CA).
#   CHỐNG CHỐI BỎ: Thu Thủy giữ (meta, S) làm bằng chứng; chỉ Thu Trang có dA để tạo S.
#
# Vì sao "ký rồi mã hóa" mà không "mã hóa rồi ký"?
#   - Mã hóa rồi ký: chữ ký nằm ngoài, Mai Phương gỡ chữ ký của Thu Trang và ký lại bằng khóa của Mai Phương
#     -> Thu Thủy tưởng thông điệp của Mai Phương. Đồng thời trọng tài không xem được nội dung đã ký.
#   - Ký song song với mã hóa (Enc(M) || Sign(M)): chữ ký lộ SHA256(M) -> Mai Phương đoán M từ tập nhỏ.
#   - Ký rồi mã hóa NGÂY THƠ (không ghi tên người nhận vào phần ký): Thu Thủy giải mã rồi mã hóa lại
#     gửi cho Tuyết Linh, Tuyết Linh tưởng Thu Trang viết cho mình (surreptitious forwarding, Davis 2001)
#     -> phải đưa trường "to" vào phần được ký như bước 1.
#
# Phần mã hóa đối xứng: dòng khóa sinh bằng SHA-256 ở chế độ đếm (giống CTR mode):
#   block_i = SHA256(K_enc || nonce || i)  ;  ct = pt XOR (block_0 || block_1 || ...)
# kết hợp HMAC-SHA256 theo kiểu Encrypt-then-MAC. (Hệ thống thực tế dùng AES-GCM; ở đây tự
# cài bằng SHA-256 để không phụ thuộc thư viện và vì đề tài tập trung vào RSA.)
import base64
import json
import secrets
import time

import os as _os
import sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))

from core.sha256 import sha256_bytes, hash_sha256
from core.hmac_utils import generate_hmac
from core.rsa_math import compare_hashes
from core.rsa_full import sign_message, verify_message, oaep_encrypt, oaep_decrypt, DecryptionError

VERSION = "RSA-SIGN-THEN-ENCRYPT/1"
KEY_LEN = 32
NONCE_LEN = 12


class SecureMessageError(Exception):
    """Mở gói tin thất bại; `reason` mô tả nguyên nhân để hiển thị khi demo."""

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


# ------------------------------------------------------------------ #
# Mã hóa đối xứng: SHA-256-CTR + HMAC-SHA256
# ------------------------------------------------------------------ #
def derive_keys(session_key):
    """Tách khóa phiên thành 2 khóa độc lập: một để mã hóa, một để tính MAC."""
    k_enc = bytes.fromhex(generate_hmac(session_key, b"encryption"))
    k_mac = bytes.fromhex(generate_hmac(session_key, b"authentication"))
    return k_enc, k_mac


def keystream_xor(k_enc, nonce, data):
    """Mã hóa / giải mã (cùng một phép): data XOR dòng khóa SHA256(k_enc || nonce || counter)."""
    out = bytearray(len(data))
    prefix = k_enc + nonce
    for block_index, offset in enumerate(range(0, len(data), 32)):
        ks = sha256_bytes(prefix + block_index.to_bytes(4, "big"))
        chunk = data[offset:offset + 32]
        out[offset:offset + len(chunk)] = bytes(a ^ b for a, b in zip(chunk, ks))
    return bytes(out)


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


# ------------------------------------------------------------------ #
# Bước KÝ: tạo phần "inner" đã ký
# ------------------------------------------------------------------ #
def build_signed_inner(message, sender, sender_private_key, recipient=None, filename=None):
    """
    Tạo inner = len(meta) || meta || len(S) || S || M.
    :param recipient: tên người nhận được ĐƯA VÀO PHẦN KÝ. Truyền None để mô phỏng
                      cách làm ngây thơ (bị tấn công chuyển tiếp lén).
    """
    if isinstance(message, str):
        message = message.encode("utf-8")
    meta = {"v": VERSION, "from": sender, "sha256": hash_sha256(message),
            "time": time.strftime("%Y-%m-%d %H:%M:%S"), "filename": filename}
    if recipient is not None:
        meta["to"] = recipient
    meta_bytes = _canonical(meta)
    sig = sign_message(meta_bytes, sender_private_key)
    sig_bytes = sig.to_bytes((sig.bit_length() + 7) // 8 or 1, "big")
    return (len(meta_bytes).to_bytes(4, "big") + meta_bytes +
            len(sig_bytes).to_bytes(4, "big") + sig_bytes + message)


def parse_inner(inner):
    """Tách inner -> (meta (dict), meta_bytes, chữ ký (int), message)."""
    try:
        n = int.from_bytes(inner[:4], "big")
        meta_bytes = inner[4:4 + n]
        pos = 4 + n
        m = int.from_bytes(inner[pos:pos + 4], "big")
        sig = int.from_bytes(inner[pos + 4:pos + 4 + m], "big")
        message = inner[pos + 4 + m:]
        return json.loads(meta_bytes.decode("utf-8")), meta_bytes, sig, message
    except (ValueError, UnicodeDecodeError) as err:
        raise SecureMessageError(f"Cấu trúc gói tin hỏng: {err}")


def verify_signed_inner(inner, me, get_sender_public_key):
    """
    Kiểm tra phần inner sau khi giải mã.
    :param me: tên của người đang mở gói (để chống chuyển tiếp lén)
    :param get_sender_public_key: hàm (tên người gửi) -> khóa công khai (đã kiểm tra chứng thư)
    """
    meta, meta_bytes, sig, message = parse_inner(inner)
    sender = meta.get("from")
    pub = get_sender_public_key(sender)
    if pub is None:
        raise SecureMessageError(f"Không có khóa công khai tin cậy của '{sender}'")
    if not verify_message(meta_bytes, sig, pub):
        raise SecureMessageError(f"Chữ ký của '{sender}' KHÔNG hợp lệ (giả mạo hoặc sai khóa)")
    if not compare_hashes(hash_sha256(message), meta.get("sha256")):
        raise SecureMessageError("Nội dung không khớp giá trị băm đã ký (bị sửa đổi)")
    if "to" in meta and meta["to"] != me:
        raise SecureMessageError(f"Thư được '{sender}' ký gửi cho '{meta['to']}', không phải '{me}' "
                                 f"-> nghi bị chuyển tiếp lén (surreptitious forwarding)")
    return {"message": message, "sender": sender, "meta": meta, "signature": sig,
            "bound_to_recipient": "to" in meta}


# ------------------------------------------------------------------ #
# Bước MÃ HÓA: bọc inner cho người nhận
# ------------------------------------------------------------------ #
def encrypt_for(inner, recipient, recipient_public_key):
    """Mã hóa lai: khóa phiên K bọc bằng RSA-OAEP, dữ liệu mã bằng SHA-256-CTR + HMAC."""
    session_key = secrets.token_bytes(KEY_LEN)
    nonce = secrets.token_bytes(NONCE_LEN)
    k_enc, k_mac = derive_keys(session_key)
    ct = keystream_xor(k_enc, nonce, inner)
    header = _canonical({"v": VERSION, "to": recipient})
    tag = generate_hmac(k_mac, header + nonce + ct)
    ek = oaep_encrypt(session_key, recipient_public_key, label=recipient.encode("utf-8"))
    return {"v": VERSION, "to": recipient, "ek": ek.hex(), "nonce": nonce.hex(),
            "ct": base64.b64encode(ct).decode("ascii"), "tag": tag}


def decrypt_envelope(envelope, my_private_key):
    """Giải mã phong bì -> inner. Lỗi nếu sai khóa hoặc bản mã bị sửa."""
    try:
        ek = bytes.fromhex(envelope["ek"])
        nonce = bytes.fromhex(envelope["nonce"])
        ct = base64.b64decode(envelope["ct"])
        recipient = envelope["to"]
    except (KeyError, ValueError) as err:
        raise SecureMessageError(f"Phong bì sai định dạng: {err}")
    try:
        session_key = oaep_decrypt(ek, my_private_key, label=recipient.encode("utf-8"))
    except DecryptionError:
        raise SecureMessageError("Không mở được khóa phiên: bạn không phải người nhận (sai khóa riêng)")
    k_enc, k_mac = derive_keys(session_key)
    header = _canonical({"v": envelope.get("v"), "to": recipient})
    if not compare_hashes(generate_hmac(k_mac, header + nonce + ct), envelope.get("tag")):
        raise SecureMessageError("Mã xác thực HMAC sai: bản mã đã bị sửa trên đường truyền")
    return keystream_xor(k_enc, nonce, ct)


# ------------------------------------------------------------------ #
# API cấp cao
# ------------------------------------------------------------------ #
def seal(message, sender, sender_private_key, recipient, recipient_public_key, filename=None):
    """Ký rồi mã hóa. Trả về phong bì (dict, lưu được thành JSON)."""
    inner = build_signed_inner(message, sender, sender_private_key, recipient, filename)
    return encrypt_for(inner, recipient, recipient_public_key)


def open_sealed(envelope, me, my_private_key, get_sender_public_key):
    """Giải mã rồi kiểm tra chữ ký. Trả về dict {message, sender, meta, ...}."""
    inner = decrypt_envelope(envelope, my_private_key)
    return verify_signed_inner(inner, me, get_sender_public_key)


if __name__ == "__main__":
    from core.rsa_math import generate_keypair
    a_priv, a_pub = generate_keypair(keysize=1024)
    b_priv, b_pub = generate_keypair(keysize=1024)
    env = seal("Lương tháng 10: 35.000.000 VNĐ", "Thu Trang", a_priv, "Thu Thủy", b_pub)
    print("Phong bì (Mai Phương nhìn thấy):", {k: (v[:40] + "...") if len(v) > 40 else v for k, v in env.items()})
    r = open_sealed(env, "Thu Thủy", b_priv, {"Thu Trang": a_pub}.get)
    print("Thu Thủy mở được:", r["message"].decode(), "| người gửi:", r["sender"])
