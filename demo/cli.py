from __future__ import annotations

import argparse
import struct
import sys
import zlib
from pathlib import Path

from core import key_io
from core.rsa_keygen import generate_keypair
from core.signature import SCHEMES, sign_file, verify_file
from core.step_logger import StepLogger
from core.tiny_rsa import TinyRSA
from core.utils import Timer, from_hex
from demo import ROOT, SAMPLE

COLORS = {"head": "\033[1;34m", "ok": "\033[32m", "bad": "\033[31m", "dim": "\033[90m"}
RESET = "\033[0m"


def _color(text: str, level: str) -> str:
    if level and sys.stdout.isatty():
        return f"{COLORS[level]}{text}{RESET}"
    return text


def print_steps(log: StepLogger) -> None:
    for step in log:
        lines = step.to_text().splitlines()
        print(_color(lines[0], step.level))
        for line in lines[1:]:
            print(line)
def cmd_tiny(p: int = 17, q: int = 11, e: int = 7, h: int | None = 88, message: str | None = None) -> None:
    tiny = TinyRSA(p, q, e)
    data: bytes | int = message.encode("utf-8") if message is not None else (88 if h is None else h)
    log = StepLogger()
    s = tiny.sign(data, log)
    tiny.verify(data, s, log)
    print_steps(log)


def cmd_keygen(bits: int, out: Path, e: int = 65537, owner: str = "") -> None:
    with Timer() as t:
        pub, priv = generate_keypair(bits, e)
    key_io.save_private_key(priv, out, owner)
    pub_path = out.with_name(out.stem + ".pub.json")
    key_io.save_public_key(pub, pub_path)
    print(f"Sinh khoá {bits} bít trong {t.elapsed:.2f}s\n  khoá riêng  : {out}\n  khoá công khai: {pub_path}")
    print(_color(f"{key_io.DEMO_WARNING}", "dim"))


def cmd_sign(key: Path, infile: Path, out: Path | None, scheme: str, cert: Path | None, tsa_key: Path | None) -> Path:
    priv = key_io.load_private_key(key)
    with Timer() as t:
        bundle = sign_file(infile, priv, scheme)
    if cert is not None:
        bundle.signer_certificate = key_io.read_json(cert)
    if tsa_key is not None:
        from pki.timestamp import TimestampAuthority
        tsa_priv = key_io.load_private_key(tsa_key)
        bundle.timestamp_token = TimestampAuthority("TSA ATBMTT", (tsa_priv.public_key, tsa_priv)).stamp(
            bundle.signature).to_dict()
    out = out or infile.with_name(infile.name + ".sig.json")
    key_io.save_signature(bundle, out)
    print(f"SHA-256  : {bundle.message_hash_hex}\nChữ ký   : {bundle.signature_hex[:64]}…\n"
          f"Thời gian: {t.elapsed * 1000:.1f} ms\nĐã lưu   : {out}")
    return out


def cmd_verify(infile: Path, sig: Path, key: Path | None, root: Path | None) -> bool:
    from pki.certificate import Certificate
    from pki.chain_verify import verify_chain
    from pki.timestamp import TimestampToken, verify_token
    bundle = key_io.load_signature(sig)
    if key is not None:
        pub = key_io.load_public_key(key)
        chain_ok = True
    elif bundle.signer_certificate is not None:
        cert = Certificate.from_dict(bundle.signer_certificate)
        pub = cert.public_key
        root_path = root or SAMPLE / "certs" / "root_ca.cert.json"
        roots = [Certificate.from_dict(key_io.read_json(root_path))] if root_path.is_file() else []
        at = None
        if bundle.timestamp_token is not None:
            token = TimestampToken.from_dict(bundle.timestamp_token)
            tsa_path = SAMPLE / "keys" / "tsa.json"
            if tsa_path.is_file():
                ok = verify_token(token, from_hex(bundle.signature_hex), key_io.load_public_key(tsa_path))
                print(_color(f"Dấu thời gian TSA: {'hợp lệ' if ok else 'KHÔNG hợp lệ'}", "ok" if ok else "bad"))
                at = token.time if ok else None
        chain = verify_chain(cert, [], roots, None, at)
        chain_ok = chain.valid
        print(_color(f"Chứng chỉ người ký '{cert.subject}': {chain.reason}", "ok" if chain.valid else "bad"))
    else:
        raise SystemExit("Cần --key hoặc chữ ký có kèm chứng chỉ")
    res = verify_file(infile, bundle, pub)
    ok = res.valid and chain_ok
    print(f"SHA-256(tệp): {res.computed_hash.hex() if res.computed_hash else '-'}")
    print(_color(f"{'HỢP LỆ' if ok else 'KHÔNG HỢP LỆ'}: {res.reason}", "ok" if ok else "bad"))
    return ok


def cmd_pki_demo(bits: int = 1024) -> None:
    from pki.ca import CertificateAuthority
    from pki.chain_verify import verify_chain
    root = CertificateAuthority.create("Root CA ATBMTT", bits)
    root.self_signed_root()
    inter = root.create_intermediate("Intermediate CA ATBMTT", bits)
    trang = inter.issue("Trang", generate_keypair(bits)[0])
    for c in (root.certificate, inter.certificate, trang):
        print(_color(f"--- Chứng chỉ của {c.subject} ---", "head"))
        print(c.describe())
    res = verify_chain(trang, [inter.certificate], [root.certificate], inter.publish_crl())
    print(_color(f"Kiểm tra chuỗi: {res.reason}", "ok" if res.valid else "bad"))
    inter.revoke(trang.serial)
    res = verify_chain(trang, [inter.certificate], [root.certificate], inter.publish_crl())
    print(_color(f"Sau khi thu hồi: {res.reason}", "ok" if res.valid else "bad"))


def _run_registry(package: str, name: str, **kw) -> None:
    mod = __import__(package)
    names = [m for m, _ in mod.REGISTRY] if name == "all" else [name]
    for n in names:
        log = StepLogger()
        mod.load(n).run(log, **kw)
        print_steps(log)
        print()
HELLO = "Xin chào! Đây là tệp mẫu để thử ký và kiểm tra chữ ký RSA.\n"


def make_logo_png(size: int = 320) -> bytes:
    glyphs = {"R": ["1110", "1001", "1110", "1010", "1001"], "S": ["0111", "1000", "0110", "0001", "1110"],
              "A": ["0110", "1001", "1111", "1001", "1001"]}
    cell, x0, y0 = size // 22, size // 2 - 7 * (size // 22), size // 2 - 5 * (size // 44)
    seed = 20261029
    raw = bytearray()
    for y in range(size):
        raw.append(0)
        for x in range(size):
            seed = (seed * 1103515245 + 12345) & 0x7FFFFFFF
            noise = (seed >> 16) % 24 - 12
            t = (x + y) / (2 * size)
            r, g, b = 244 + (255 - 244) * t, 168 + (248 - 168) * t, 208 + (167 - 208) * t
            dx, dy = x - size / 2, y - size / 2
            if abs((dx * dx + dy * dy) ** 0.5 - size * 0.4) < size * 0.025:
                r, g, b = 194, 24, 91
            gx, gy = (x - x0) // cell, (y - y0) // cell
            if 0 <= gy < 5 and 0 <= gx < 14 and gx % 5 < 4:
                if glyphs["RSA"[gx // 5]][gy][gx % 5] == "1":
                    r, g, b = 90, 26, 60
            raw += bytes(max(0, min(255, int(v) + noise)) for v in (r, g, b))

    def chunk(tag: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(bytes(raw), 9)) + chunk(b"IEND", b""))


def gen_samples(bits: int = 2048, say=print) -> None:
    from pki.ca import CertificateAuthority
    from pki.timestamp import TimestampAuthority
    msgs, keys, certs, sigs = (SAMPLE / d for d in ("messages", "keys", "certs", "signatures"))
    for d in (msgs, keys, certs, sigs, SAMPLE / "images"):
        d.mkdir(parents=True, exist_ok=True)
    (msgs / "hello.txt").write_bytes(HELLO.encode("utf-8"))
    contract = (msgs / "contract.txt").read_bytes()
    tampered = contract.replace(b"2.000.000.000", b"8.000.000.000", 1)
    (msgs / "contract_tampered.txt").write_bytes(tampered)
    say(f"messages/: hello.txt, contract.txt, contract_tampered.txt (khác {sum(a != b for a, b in zip(contract, tampered))} byte)")
    logo = make_logo_png()
    (SAMPLE / "images" / "logo.png").write_bytes(logo)
    say(f"images/logo.png: {len(logo) // 1024} KB")

    pairs = {}
    for name in ("trang_sign", "thuy_sign", "thuy_enc", "root_ca", "tsa"):
        pairs[name] = generate_keypair(bits)
        key_io.save_private_key(pairs[name][1], keys / f"{name}.json", owner=name)
        say(f"keys/{name}.json ({bits} bít)")
    (keys / "README.md").write_bytes(
        "# Khoá DEMO\n\nCác tệp trong thư mục này là **khoá demo cho bài tập, KHÔNG dùng thật**. "
        "Khoá riêng được lưu không mã hoá. Sinh lại bằng `python -m demo.cli gen-samples`.\n".encode("utf-8"))

    root = CertificateAuthority("Root CA ATBMTT", pairs["root_ca"])
    key_io.write_json(certs / "root_ca.cert.json", root.self_signed_root().to_dict())
    trang_cert = root.issue("Trang", pairs["trang_sign"][0], days=730)
    for fname, cert in (("trang.cert.json", trang_cert), ("thuy.cert.json", root.issue("Thủy", pairs["thuy_sign"][0], 730)),
                        ("tsa.cert.json", root.issue("TSA ATBMTT", pairs["tsa"][0], 730))):
        key_io.write_json(certs / fname, cert.to_dict())
    say("certs/: root_ca, trang, thuy, tsa (.cert.json)")

    bundle = sign_file(msgs / "contract.txt", pairs["trang_sign"][1])
    bundle.signer_certificate = trang_cert.to_dict()
    bundle.timestamp_token = TimestampAuthority("TSA ATBMTT", pairs["tsa"]).stamp(bundle.signature).to_dict()
    key_io.save_signature(bundle, sigs / "contract.txt.sig.json")
    say("signatures/contract.txt.sig.json (trang ký, kèm chứng chỉ + dấu thời gian)")
MENU = """
==================== HỆ CHỮ KÝ ĐIỆN TỬ RSA ====================
1. Tiny RSA — ký/kiểm tra từng bước (p=17, q=11, e=7)
2. Sinh cặp khoá RSA (1024/2048/3072)
3. Ký tệp
4. Kiểm tra chữ ký tệp
5. PKI: tạo CA, cấp chứng chỉ, thu hồi
6. Chạy tấn công (chọn từ danh sách)
7. Chạy kịch bản chứng thực / chống chối bỏ
8. Benchmark
9. Chạy kiểm thử đối chiếu (bảng từ test/report.py)
0. Thoát"""


def _ask(prompt: str, default: str = "") -> str:
    s = input(f"{prompt}{f' [{default}]' if default else ''}: ").strip()
    return s or default


def _pick(registry) -> str | None:
    for i, (_, title) in enumerate(registry, 1):
        print(f"  {i}. {title}")
    print(f"  {len(registry) + 1}. Tất cả")
    c = _ask("Chọn", "1")
    if not c.isdigit() or not 1 <= int(c) <= len(registry) + 1:
        return None
    return "all" if int(c) == len(registry) + 1 else registry[int(c) - 1][0]


def menu() -> None:
    import attacks
    import scenarios
    while True:
        print(MENU)
        choice = _ask("Chọn")
        try:
            if choice == "0":
                return
            if choice == "1":
                v = _ask("Giá trị h (số) hoặc thông điệp (chữ)", "88")
                cmd_tiny(int(_ask("p", "17")), int(_ask("q", "11")), int(_ask("e", "7")),
                         h=int(v) if v.isdigit() else None, message=None if v.isdigit() else v)
            elif choice == "2":
                bits = int(_ask("Số bít (1024/2048/3072)", "2048"))
                cmd_keygen(bits, Path(_ask("Lưu khoá riêng vào", str(SAMPLE / "keys" / "my_key.json"))))
            elif choice == "3":
                cmd_sign(Path(_ask("Tệp khoá riêng", str(SAMPLE / "keys" / "trang_sign.json"))),
                         Path(_ask("Tệp cần ký", str(SAMPLE / "messages" / "contract.txt"))), None,
                         _ask("Lược đồ (pkcs1v15/pss)", "pkcs1v15"), None, None)
            elif choice == "4":
                f = Path(_ask("Tệp cần kiểm tra", str(SAMPLE / "messages" / "contract.txt")))
                cmd_verify(f, Path(_ask("Tệp chữ ký", str(f) + ".sig.json")), None, None)
            elif choice == "5":
                cmd_pki_demo()
            elif choice == "6":
                name = _pick(attacks.REGISTRY)
                if name:
                    _run_registry("attacks", name, defended=_ask("Bật phòng chống? (c/k)", "k").lower() == "c")
            elif choice == "7":
                name = _pick(scenarios.REGISTRY)
                if name:
                    _run_registry("scenarios", name)
            elif choice == "8":
                from demo import benchmark
                benchmark.main(["--quick"])
            elif choice == "9":
                from test import report
                rows = report.build_report()
                print(report.to_console(rows))
        except (ValueError, OSError, KeyError) as err:
            print(_color(f"Lỗi: {err}", "bad"))


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser(prog="python -m demo.cli", description="Hệ chữ ký điện tử RSA — CLI")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("menu", help="menu số (mặc định)")
    t = sub.add_parser("tiny", help="Tiny RSA từng bước")
    t.add_argument("--p", type=int, default=17)
    t.add_argument("--q", type=int, default=11)
    t.add_argument("--e", type=int, default=7)
    t.add_argument("--h", type=int, default=88)
    t.add_argument("--message")
    k = sub.add_parser("keygen", help="sinh cặp khoá")
    k.add_argument("--bits", type=int, default=2048)
    k.add_argument("--e", type=int, default=65537)
    k.add_argument("--out", type=Path, required=True)
    k.add_argument("--owner", default="")
    s = sub.add_parser("sign", help="ký tệp → *.sig.json")
    s.add_argument("--key", type=Path, required=True)
    s.add_argument("--in", dest="infile", type=Path, required=True)
    s.add_argument("--out", type=Path)
    s.add_argument("--scheme", choices=SCHEMES, default="pkcs1v15")
    s.add_argument("--cert", type=Path, help="chứng chỉ người ký (.cert.json) gắn vào chữ ký")
    s.add_argument("--tsa-key", type=Path, help="khoá TSA để đóng dấu thời gian")
    v = sub.add_parser("verify", help="kiểm tra chữ ký tệp")
    v.add_argument("--in", dest="infile", type=Path, required=True)
    v.add_argument("--sig", type=Path, required=True)
    v.add_argument("--key", type=Path, help="khoá công khai (bỏ trống: dùng chứng chỉ trong chữ ký)")
    v.add_argument("--root", type=Path, help="chứng chỉ root tin cậy (mặc định sample/certs/root_ca.cert.json)")
    sub.add_parser("pki", help="demo PKI: root, intermediate, cấp, thu hồi")
    a = sub.add_parser("attack", help="chạy tấn công (tên module hoặc all)")
    a.add_argument("name")
    a.add_argument("--defended", action="store_true")
    sc = sub.add_parser("scenario", help="chạy kịch bản (tên module hoặc all)")
    sc.add_argument("name")
    b = sub.add_parser("benchmark", help="đo hiệu năng")
    b.add_argument("--quick", action="store_true")
    r = sub.add_parser("report", help="bảng đối chiếu kiểm thử")
    r.add_argument("--slow", action="store_true")
    g = sub.add_parser("gen-samples", help="sinh lại sample/")
    g.add_argument("--bits", type=int, default=2048)
    args = ap.parse_args(argv)

    if args.cmd in (None, "menu"):
        menu()
    elif args.cmd == "tiny":
        cmd_tiny(args.p, args.q, args.e, args.h, args.message)
    elif args.cmd == "keygen":
        cmd_keygen(args.bits, args.out, args.e, args.owner)
    elif args.cmd == "sign":
        cmd_sign(args.key, args.infile, args.out, args.scheme, args.cert, args.tsa_key)
    elif args.cmd == "verify":
        return 0 if cmd_verify(args.infile, args.sig, args.key, args.root) else 1
    elif args.cmd == "pki":
        cmd_pki_demo()
    elif args.cmd == "attack":
        _run_registry("attacks", args.name, defended=args.defended)
    elif args.cmd == "scenario":
        _run_registry("scenarios", args.name)
    elif args.cmd == "benchmark":
        from demo import benchmark
        return benchmark.main(["--quick"] if args.quick else [])
    elif args.cmd == "report":
        from test import report
        return report.main(["--slow"] if args.slow else [])
    elif args.cmd == "gen-samples":
        gen_samples(args.bits)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
