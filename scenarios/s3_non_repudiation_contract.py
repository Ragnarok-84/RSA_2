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
    trang_pub, trang_priv = generate_keypair(bits)
    trang_cert = root.issue("Trang", trang_pub)
    log.note("[1] Hạ tầng: Root CA cấp chứng chỉ cho trang và cho TSA", trang_cert.describe())

    contract = sample_bytes("messages/contract.txt", FALLBACK_CONTRACT)
    sig = sign(contract, trang_priv)
    token = tsa.stamp(sig)
    bundle = SignatureBundle("pkcs1v15", "contract.txt", "", sig.hex(), trang_cert.to_dict(), token.to_dict())
    log.log("[2] trang ký hợp đồng, TSA đóng dấu thời gian lên chữ ký",
            r"\mathrm{token} = \mathrm{Sign}_{d_{TSA}}(\mathrm{SHA256}(S) \| t)",
            f"S = {sig.hex()[:48]}…\nt = {fmt_time(token.time)}")
    log.note("    thuy nhận gói (hợp đồng, S, chứng chỉ trang, token) và lưu lại làm bằng chứng")

    log.head("[3] Linh (Third Party) làm trọng tài: Trang chối 'Tôi chưa từng ký hợp đồng này' → trọng tài kiểm tra")
    crl = root.publish_crl()
    verdict = arbitrate(contract, bundle, [root.certificate], crl, tsa.public_key)
    tsa_chain = verify_chain(tsa.certificate, [], [root.certificate], crl)
    log.log("    Chứng chỉ của TSA", None, tsa_chain.reason, level="ok" if tsa_chain.valid else "bad")
    log.log("    Phán quyết", None, verdict.reason, level="ok" if verdict.valid else "bad")

    edited = contract.replace("2.000.000.000".encode(), "200.000.000".encode(), 1)
    if edited == contract:
        edited = contract + b" "
    framed = arbitrate(edited, bundle, [root.certificate], crl, tsa.public_key)
    log.log("[4] thuy sửa giá trị hợp đồng rồi dùng lại chữ ký của trang", None, framed.reason,
            level="bad" if framed.valid else "ok")

    thuy_pub, thuy_priv = generate_keypair(bits)
    thuy_sig = sign(contract, thuy_priv)
    thuy_bundle = SignatureBundle("pkcs1v15", "contract.txt", "", thuy_sig.hex(), trang_cert.to_dict(),
                                 tsa.stamp(thuy_sig).to_dict())
    framed2 = arbitrate(contract, thuy_bundle, [root.certificate], crl, tsa.public_key)
    log.log("[5] thuy tự ký bằng khoá của thuy rồi gắn chứng chỉ của trang", None, framed2.reason,
            level="bad" if framed2.valid else "ok")

    backdated = SignatureBundle(**{**bundle.__dict__, "timestamp_token": {**token.to_dict(), "time": token.time - 86400 * 400}})
    r_back = arbitrate(contract, backdated, [root.certificate], crl, tsa.public_key)
    log.log("[6] Sửa thời điểm trong dấu thời gian", None, r_back.reason, level="bad" if r_back.valid else "ok")

    valid = verdict.valid and tsa_chain.valid and not framed.valid and not framed2.valid and not r_back.valid
    summary = ("Chứng chỉ CA + chữ ký + dấu thời gian ràng buộc trang với hợp đồng: trang không chối được, "
               "thuy cũng không vu cho trang được." if valid else "Kịch bản S3 không đạt.")
    (log.ok if valid else log.bad)("[KẾT LUẬN] " + summary)
    return ScenarioResult(NAME, valid, summary, {
        "verdict": verdict.reason, "thuy_edits_contract": framed.valid, "thuy_own_key": framed2.valid,
        "backdated_token": r_back.valid,
    })
