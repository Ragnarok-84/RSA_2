from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import QComboBox, QFileDialog, QGroupBox, QHBoxLayout, QLabel, QVBoxLayout, QWidget

from core import key_io
from core.hash.sha256 import sha256, sha256_file
from core.rsa_keygen import RSAPrivateKey, RSAPublicKey, generate_keypair
from core.signature import SignatureBundle, sign_hash, verify_hash
from core.step_logger import StepLogger
from core.utils import Timer, from_hex
from demo.gui.widgets import common
from demo.gui.widgets.common import SAMPLE, DataSource, OutputBox, bold_label, button, hbox
from demo.gui.widgets.hex_view import HexView
from demo.gui.widgets.result_badge import ResultBadge

IMAGE_EXT = {".png", ".jpg", ".jpeg", ".gif", ".bmp"}
# Mặc định theo slide: y = h(x)^a mod n; PKCS#1 v1.5 là lựa chọn chuẩn thực tế (đối chiếu từng byte với thư viện)
SCHEMES = {"Mặc định": "textbook", "PKCS#1 v1.5": "pkcs1v15"}


class SignVerifyTab(QWidget):
    def __init__(self, app) -> None:
        super().__init__()
        self.app = app
        self.setAcceptDrops(True)
        self.pub: RSAPublicKey | None = None
        self.priv: RSAPrivateKey | None = None
        self.bundle: SignatureBundle | None = None
        self.last_message: bytes | None = None
        self._last_file: Path | None = None
        self._received_override: bytes | None = None       
        lay = QHBoxLayout(self)
        left = QGroupBox("BÊN KÝ: Trang (Sender) - dùng khoá bí mật")
        ll = QVBoxLayout(left)
        self.bits = QComboBox()
        self.bits.addItems(("1024", "2048", "3072"))
        self.bits.setCurrentText("2048")
        self.key_info = QLabel("Chưa có khoá")
        ll.addLayout(hbox(QLabel("Khoá:"), self.bits, button("Sinh khoá mới", self.generate),
                          button("Mở khoá…", self.open_key), None))
        ll.addWidget(self.key_info)
        self.src = DataSource("Thông điệp cần ký", lines=4)
        self.src.path.textChanged.connect(self._preview)
        ll.addWidget(self.src)
        self.preview = QLabel()
        self.preview.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.preview.setVisible(False)
        ll.addWidget(self.preview)
        self.scheme = QComboBox()
        self.scheme.addItems(tuple(SCHEMES))
        self.time_label = QLabel("")
        ll.addLayout(hbox(QLabel("Lược đồ:"), self.scheme, button("Ký", self.sign), self.time_label, None,
                          button("Lưu .sig.json…", self.save_sig)))
        self.hash_view = HexView("[1] h(x) = SHA-256(x)", 1)
        self.em_view = HexView("[2] m đưa vào lũy thừa (Mặc định: m = h(x); PKCS#1: m = EM)", 3)
        self.sig_view = HexView("[3] Chữ ký y = m^a mod n", 4)
        for w in (self.hash_view, self.em_view, self.sig_view):
            ll.addWidget(w)
        ll.addStretch(1)
        right = QGroupBox("BÊN KIỂM TRA: Thủy (Receiver) - dùng khoá công khai của Trang")
        rl = QVBoxLayout(right)
        self.recv = DataSource("Thông điệp nhận được", lines=4)
        self.recv.text.textChanged.connect(self._clear_override)
        self.recv.path.textChanged.connect(self._clear_override)
        rl.addWidget(self.recv)
        self.sig_label = QLabel("Chữ ký: (chưa có)")
        rl.addLayout(hbox(button("Dùng thông điệp + chữ ký vừa ký", self.use_last),
                          button("Mở .sig.json…", self.open_sig), None))
        rl.addWidget(self.sig_label)
        rl.addLayout(hbox(button("Kiểm tra", self.verify), button("Phương lật 1 bit thông điệp", self.flip_message),
                          button("Phương lật 1 bit chữ ký", self.flip_signature), None))
        self.badge = ResultBadge()
        rl.addWidget(self.badge)
        self.detail = OutputBox()
        rl.addWidget(self.detail, 1)

        lay.addWidget(left, 1)
        lay.addWidget(right, 1)
        self._load_default_key()
    def _set_key(self, pub: RSAPublicKey, priv: RSAPrivateKey | None, origin: str) -> None:
        self.pub, self.priv = pub, priv
        self.key_info.setText(f"{origin}: n {pub.n.bit_length()} bit, e = {pub.e}"
                              + ("" if priv else " (chỉ khoá công khai - không ký được)"))

    def _load_default_key(self) -> None:
        path = SAMPLE / "keys" / "trang_sign.json"
        if path.is_file():
            try:
                priv = key_io.load_private_key(path)
                self._set_key(priv.public_key, priv, "sample/keys/trang_sign.json")
            except (ValueError, KeyError, OSError):
                pass

    def generate(self) -> None:
        bits = int(self.bits.currentText())
        self.app.run(lambda: generate_keypair(bits), lambda kp: self._set_key(kp[0], kp[1], "Khoá vừa sinh"),
                     status=f"Đang sinh khoá {bits} bit…", owner=self)

    def open_key(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Mở khoá (JSON)", str(SAMPLE / "keys"), "Khoá (*.json)")
        if not path:
            return
        try:
            key = key_io.load_key(Path(path))
        except (ValueError, KeyError, OSError) as err:
            common.show_error(self, "Không mở được khoá", str(err))
            return
        if isinstance(key, RSAPrivateKey):
            self._set_key(key.public_key, key, Path(path).name)
        else:
            self._set_key(key, None, Path(path).name)

    def open_file(self) -> None:
        self.src.file_mode.setChecked(True)
        self.src._browse()

    def _preview(self) -> None:
        p = self.src.file()
        pix = QPixmap(str(p)) if p is not None and p.suffix.lower() in IMAGE_EXT and p.is_file() else QPixmap()
        self.preview.setVisible(not pix.isNull())
        if not pix.isNull():
            self.preview.setPixmap(pix.scaled(160, 160, Qt.AspectRatioMode.KeepAspectRatio,
                                              Qt.TransformationMode.SmoothTransformation))
    def dragEnterEvent(self, event) -> None:
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event) -> None:
        for url in event.mimeData().urls():
            p = Path(url.toLocalFile())
            if p.name.endswith(".sig.json"):
                self._load_sig(p)
            elif p.is_file():
                self.src.set_file(p)
                self.recv.set_file(p)
    def _scheme(self) -> str:
        return SCHEMES[self.scheme.currentText()]

    def sign(self) -> None:
        if self.priv is None:
            common.show_warning(self, "Thiếu khoá", "Hãy sinh khoá hoặc mở một khoá riêng trước.")
            return
        file = self.src.file()
        text = None
        if file is None:
            got = self.src.read()
            if got is None:
                return
            text = got[0]
        priv, scheme = self.priv, self._scheme()

        def job(progress):
            log = StepLogger()
            with Timer() as t:
                h = sha256_file(file, progress) if file is not None else sha256(text)
                sig = sign_hash(h, priv, scheme, logger=log)
            em = next((s.value_str for s in log if s.title.startswith(("Mã hoá EM", "Số đưa vào"))), "")
            return h, em, sig, t.elapsed

        def done(res) -> None:
            h, em, sig, elapsed = res
            self.hash_view.set_hex(h)
            self.em_view.set_hex(em)
            self.sig_view.set_hex(sig)
            self.time_label.setText(f"{elapsed * 1000:.1f} ms")
            name = file.name if file is not None else "message.txt"
            self.bundle = SignatureBundle(scheme, name, h.hex(), sig.hex())
            self.last_message = file.read_bytes() if file is not None and file.stat().st_size < (64 << 20) else text
            self._last_file = file
            self.badge.set_info("Đã ký - bấm Kiểm tra ở bên phải")
            self.detail.append(f"=== Trang ký {name} bằng {self.scheme.currentText()}, khoá {priv.n.bit_length()} bít ===\n")
            self.use_last()

        self.app.run(job, done, status="Đang băm và ký…", owner=self)

    def save_sig(self) -> None:
        if self.bundle is None:
            common.show_info(self, "Chưa có chữ ký", "Bấm Ký trước.")
            return
        default = SAMPLE / "signatures" / f"{self.bundle.message_file}.sig.json"
        path, _ = QFileDialog.getSaveFileName(self, "Lưu chữ ký", str(default), "Chữ ký (*.sig.json)")
        if path:
            key_io.save_signature(self.bundle, Path(path))
            self.detail.append(f"Đã lưu {path}\n", "ok")
    def _clear_override(self) -> None:
        self._received_override = None

    def use_last(self) -> None:
        if self.bundle is None:
            return
        if self._last_file is not None:
            self.recv.set_file(self._last_file)
        else:
            self.recv.set_text((self.last_message or b"").decode("utf-8", "replace"))
        self._received_override = None
        self.sig_label.setText(f"Chữ ký: {self.bundle.signature_hex[:48]}… ({self.bundle.scheme})")

    def open_sig(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Mở chữ ký", str(SAMPLE / "signatures"), "Chữ ký (*.sig.json)")
        if path:
            self._load_sig(Path(path))

    def _load_sig(self, path: Path) -> None:
        try:
            self.bundle = key_io.load_signature(path)
        except (ValueError, KeyError, OSError) as err:
            common.show_error(self, "Không đọc được chữ ký", str(err))
            return
        self._received_override = None
        self.sig_label.setText(f"Chữ ký: {path.name} ({self.bundle.scheme}, tệp gốc: {self.bundle.message_file})")
        msg = path.parent.parent / "messages" / self.bundle.message_file
        if msg.is_file():
            self.recv.set_file(msg)
        if self.bundle.signer_certificate:
            from pki.certificate import Certificate
            cert = Certificate.from_dict(self.bundle.signer_certificate)
            self._set_key(cert.public_key, None if self.priv is None or self.priv.n != cert.public_key.n else self.priv,
                          f"Chứng chỉ của {cert.subject}")
        self.detail.append(f"Đã mở {path}\n")

    def flip_message(self) -> None:
        got = self.recv.read()
        if got is None:
            return
        data = bytearray(got[0])
        if not data:
            return
        data[len(data) // 2] ^= 0x01
        self._received_override = bytes(data)
        self.detail.append(f"Phương (Attacker) lật 1 bít ở byte thứ {len(data) // 2:,} của thông điệp nhận được.\n", "bad")

    def flip_signature(self) -> None:
        if self.bundle is None:
            return
        sig = bytearray(from_hex(self.bundle.signature_hex))
        sig[-1] ^= 0x01
        self.bundle = SignatureBundle(**{**self.bundle.__dict__, "signature_hex": sig.hex()})
        self.detail.append("Phương (Attacker) lật 1 bít cuối của chữ ký.\n", "bad")

    def verify(self) -> None:
        if self.bundle is None or self.pub is None:
            common.show_warning(self, "Thiếu dữ liệu", "Cần có chữ ký (ký ở bên trái hoặc mở .sig.json) và khoá công khai.")
            return
        override = self._received_override
        file = self.recv.file() if override is None else None
        text = override
        if override is None and file is None:
            got = self.recv.read()
            if got is None:
                return
            text = got[0]
        bundle, pub = self.bundle, self.pub

        def job(progress):
            log = StepLogger()
            h = sha256_file(file, progress) if file is not None else sha256(text)
            log.log("Băm thông điệp nhận được", "h(x) = SHA-256(x)", h.hex())
            res = verify_hash(h, from_hex(bundle.signature_hex), pub, bundle.scheme, log)
            return res, log

        def done(out) -> None:
            res, log = out
            self.badge.set_result(res.valid, res.reason)
            self.detail.append(f"\n--- Kiểm tra bằng khoá công khai (n {pub.n.bit_length()} bít) ---\n", "head")
            self.detail.append_steps(log)

        self.app.run(job, done, status="Đang kiểm tra…", owner=self)
