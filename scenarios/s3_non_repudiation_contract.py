"""S3 — Chống chối bỏ: Alice ký hợp đồng (có chứng chỉ CA + dấu thời gian TSA) rồi chối.

Trọng tài (toà án) kiểm tra:
  1. chữ ký khớp khoá công khai trong chứng chỉ của Alice;
  2. dấu thời gian của TSA gắn đúng chữ ký này và chữ ký của TSA hợp lệ;
  3. chuỗi chứng chỉ của Alice hợp lệ, chưa bị thu hồi TẠI thời điểm ghi trong dấu thời gian.
Đủ ba điều kiện → chỉ người giữ d_A mới tạo được chữ ký đó → Alice không thể chối.
Bob cũng không thể vu cho Alice: sửa hợp đồng thì chữ ký không còn khớp.

Tấn công tương ứng khi bỏ timestamp / nonce khỏi phần được ký: attacks/a8_replay_attack.py.
"""
from __future__ import annotations

from core.rsa_keygen import RSAPublicKey, generate_keypair
from core.signature import SignatureBundle, VerifyResult, sign, verify_detailed
from core.step_logger import StepLogger
from core.utils import from_hex
from pki.certificate import Certificate, fmt_time, now
from pki.chain_verify import verify_chain
from pki.ca import CertificateAuthority
from pki.revocation import CRL
from pki.timestamp import TimestampAuthority, TimestampToken, verify_token
from scenarios import ScenarioResult, sample_bytes

NAME = "S3: Chống chối bỏ hợp đồng (CA + timestamp + trọng tài)"

FALLBACK_CONTRACT = "HỢP ĐỒNG MUA BÁN\nTổng giá trị hợp đồng: 2.000.000.000 VNĐ.\n".encode("utf-8")


def arbitrate(message: bytes, bundle: SignatureBundle, trusted_roots: list[Certificate], crl: CRL | list[CRL] | None,
              tsa_public_key: RSAPublicKey, now_time: int | None = None,
              intermediates: list[Certificate] = ()) -> VerifyResult:
    """Trọng tài quyết định chữ ký trong bundle có ràng buộc người ký hay không.

    Có dấu thời gian hợp lệ → xét chứng chỉ tại thời điểm trong dấu thời gian.
    Không có → chỉ tin được thời điểm hiện tại.
    """
    if bundle.signer_certificate is None:
        return VerifyResult(False, "không có chứng chỉ người ký")
    cert = Certificate.from_dict(bundle.signer_certificate)
    sig = from_hex(bundle.signature_hex)
    res = verify_detailed(message, sig, cert.public_key, bundle.scheme)
    if not res.valid:
        return VerifyResult(False, f"chữ ký không khớp khoá trong chứng chỉ của '{cert.subject}': {res.reason}")
    if bundle.timestamp_token is not None:
        token = TimestampToken.from_dict(bundle.timestamp_token)
        if not verify_token(token, sig, tsa_public_key):
            return VerifyResult(False, "dấu thời gian không hợp lệ (bị sửa hoặc không gắn với chữ ký này)")
        at, basis = token.time, f"theo dấu thời gian TSA {fmt_time(token.time)}"
    else:
        at = now() if now_time is None else now_time
        basis = f"không có dấu thời gian, xét tại hiện tại {fmt_time(at)}"
    chain = verify_chain(cert, intermediates, trusted_roots, crl, at)
    if not chain.valid:
        return VerifyResult(False, f"{basis}: {chain.reason}")
    return VerifyResult(True, f"{basis}: chữ ký hợp lệ, {chain.reason} → '{cert.subject}' không thể chối bỏ")


def run(logger: StepLogger | None = None, bits: int = 2048) -> ScenarioResult:
    log = logger if logger is not None else StepLogger()
    log.head("KỊCH BẢN S3: CHỐNG CHỐI BỎ HỢP ĐỒNG (NON-REPUDIATION)")

    root = CertificateAuthority.create("Root CA ATBMTT", bits)
    root.self_signed_root()
    tsa = TimestampAuthority.create("TSA ATBMTT", bits)
    tsa.certificate = root.issue(tsa.name, tsa.public_key)
    alice_pub, alice_priv = generate_keypair(bits)
    alice_cert = root.issue("Alice", alice_pub)
    log.note("[1] Hạ tầng: Root CA cấp chứng chỉ cho Alice và cho TSA", alice_cert.describe())

    contract = sample_bytes("messages/contract.txt", FALLBACK_CONTRACT)
    sig = sign(contract, alice_priv)
    token = tsa.stamp(sig)
    bundle = SignatureBundle("pkcs1v15", "contract.txt", "", sig.hex(), alice_cert.to_dict(), token.to_dict())
    log.log("[2] Alice ký hợp đồng, TSA đóng dấu thời gian lên chữ ký",
            r"\mathrm{token} = \mathrm{Sign}_{d_{TSA}}(\mathrm{SHA256}(S) \| t)",
            f"S = {sig.hex()[:48]}…\nt = {fmt_time(token.time)}")
    log.note("    Bob nhận gói (hợp đồng, S, chứng chỉ Alice, token) và lưu lại làm bằng chứng")

    log.head("[3] Tranh chấp: Alice chối 'Tôi chưa từng ký hợp đồng này' → trọng tài kiểm tra")
    crl = root.publish_crl()
    verdict = arbitrate(contract, bundle, [root.certificate], crl, tsa.public_key)
    tsa_chain = verify_chain(tsa.certificate, [], [root.certificate], crl)
    log.log("    Chứng chỉ của TSA", None, tsa_chain.reason, level="ok" if tsa_chain.valid else "bad")
    log.log("    Phán quyết", None, verdict.reason, level="ok" if verdict.valid else "bad")

    edited = contract.replace("2.000.000.000".encode(), "200.000.000".encode(), 1)
    if edited == contract:
        edited = contract + b" "
    framed = arbitrate(edited, bundle, [root.certificate], crl, tsa.public_key)
    log.log("[4] Bob sửa giá trị hợp đồng rồi dùng lại chữ ký của Alice", None, framed.reason,
            level="bad" if framed.valid else "ok")

    bob_pub, bob_priv = generate_keypair(bits)
    bob_sig = sign(contract, bob_priv)
    bob_bundle = SignatureBundle("pkcs1v15", "contract.txt", "", bob_sig.hex(), alice_cert.to_dict(),
                                 tsa.stamp(bob_sig).to_dict())
    framed2 = arbitrate(contract, bob_bundle, [root.certificate], crl, tsa.public_key)
    log.log("[5] Bob tự ký bằng khoá của Bob rồi gắn chứng chỉ của Alice", None, framed2.reason,
            level="bad" if framed2.valid else "ok")

    backdated = SignatureBundle(**{**bundle.__dict__, "timestamp_token": {**token.to_dict(), "time": token.time - 86400 * 400}})
    r_back = arbitrate(contract, backdated, [root.certificate], crl, tsa.public_key)
    log.log("[6] Sửa thời điểm trong dấu thời gian", None, r_back.reason, level="bad" if r_back.valid else "ok")

    valid = verdict.valid and tsa_chain.valid and not framed.valid and not framed2.valid and not r_back.valid
    summary = ("Chứng chỉ CA + chữ ký + dấu thời gian ràng buộc Alice với hợp đồng: Alice không chối được, "
               "Bob cũng không vu cho Alice được." if valid else "Kịch bản S3 không đạt.")
    (log.ok if valid else log.bad)("[KẾT LUẬN] " + summary)
    return ScenarioResult(NAME, valid, summary, {
        "verdict": verdict.reason, "bob_edits_contract": framed.valid, "bob_own_key": framed2.valid,
        "backdated_token": r_back.valid,
    })
