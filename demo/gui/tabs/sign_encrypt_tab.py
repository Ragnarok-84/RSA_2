from __future__ import annotations

import json
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import QComboBox, QFileDialog, QGroupBox, QHBoxLayout, QLabel, QVBoxLayout, QWidget

from core import key_io
from core.encryption import ALGORITHM, MAX_ENVELOPE_FILE_BYTES, MAX_MESSAGE_BYTES, seal, unseal
from core.hash.sha256 import sha256
from core.rsa_keygen import RSAPrivateKey, RSAPublicKey, generate_keypair
from core.signature import SignatureBundle, sign_hash, verify_hash
from core.step_logger import StepLogger
from core.utils import Timer
from demo.gui.tabs.sign_verify_tab import SCHEMES
from demo.gui.widgets import common
from demo.gui.widgets.common import SAMPLE, DataSource, OutputBox, button, hbox
from demo.gui.widgets.hex_view import HexView
from demo.gui.widgets.result_badge import ResultBadge

# Luồng theo slide: (1) y = sig_A(h(x)) -> (2) z = e_B(x, y) -> (3) (x, y) = d_B(z) -> (4) ver_A(x, y) = TRUE?
NOTE = ("Mã hoá chỉ thêm tính bí mật; chứng thực và không chối bỏ vẫn đến từ chữ ký ở bước 1. "
        "z dùng RSA-OAEP chia khối (tối đa 16 KiB), mỗi khối nhỏ hơn n_B.")


def _pixmap(data: bytes) -> QPixmap:
    pix = QPixmap()
    pix.loadFromData(data)
    return pix


class SignEncryptTab(QWidget):
    def __init__(self, app) -> None:
        super().__init__()
        self.app = app
        self.setAcceptDrops(True)
        self.receiver_pub: RSAPublicKey | None = None
        self.receiver_priv: RSAPrivateKey | None = None
        self.sent: bytes | None = None                 # x Trang gửi, để so khớp sau khi Thủy giải mã
        self.envelope: dict | None = None              # z đang trên đường truyền
        self.received: tuple[bytes, SignatureBundle] | None = None
        lay = QHBoxLayout(self)

        left = QGroupBox("BÊN GỬI: Trang - ký bằng a_A, mã hoá bằng e_B của Thủy")
        ll = QVBoxLayout(left)
        self.signer_info = QLabel("Khoá ký a_A: dùng khoá của Trang ở tab Ký & Kiểm tra")
        self.signer_info.setWordWrap(True)
        ll.addWidget(self.signer_info)
        self.src = DataSource(f"Thông điệp x (tối đa {MAX_MESSAGE_BYTES // 1024} KiB)", lines=4)
        self.src.path.textChanged.connect(self._preview_source)
        ll.addWidget(self.src)
        self.src_preview = QLabel()
        self.src_preview.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.src_preview.setVisible(False)
        ll.addWidget(self.src_preview)
        self.scheme = QComboBox()
        self.scheme.addItems(tuple(SCHEMES))
        self.time_label = QLabel("")
        ll.addLayout(hbox(QLabel("Lược đồ ký:"), self.scheme, button("Ký rồi mã hoá", self.sign_and_seal),
                          self.time_label, None, button("Lưu z…", self.save_encrypted)))
        self.sig_view = HexView("[1] y = sig_A(h(x)) — Trang dùng khoá bí mật a_A", 3)
        self.z_view = HexView("[2] z = e_B(x, y) — Trang dùng khoá công khai e_B của Thủy", 5)
        ll.addWidget(self.sig_view)
        ll.addWidget(self.z_view)
        note = QLabel(NOTE)
        note.setWordWrap(True)
        ll.addWidget(note)
        ll.addStretch(1)

        right = QGroupBox("BÊN NHẬN: Thủy - giải mã bằng d_B, kiểm tra bằng b_A của Trang")
        rl = QVBoxLayout(right)
        self.receiver_key_info = QLabel("Khoá mã hoá của Thủy: chưa có")
        self.receiver_key_info.setWordWrap(True)
        rl.addWidget(self.receiver_key_info)
        rl.addLayout(hbox(button("Sinh khoá Thủy", self.generate_receiver_key),
                          button("Mở khoá Thủy…", self.open_receiver_key),
                          button("Lưu khoá Thủy…", self.save_receiver_key), None))
        rl.addLayout(hbox(button("Mở z…", self.open_encrypted), button("Giải mã z", self.decrypt_received),
                          button("Kiểm tra chữ ký", self.verify), None))
        rl.addLayout(hbox(button("Phương sửa 1 bít z", self.tamper_z),
                          button("Thủy chuyển tiếp z cho người khác (A8)", self.show_forwarding), None))
        self.x_view = HexView("[3] (x, y) = d_B(z) — thông điệp Thủy giải mã được", 3)
        rl.addWidget(self.x_view)
        self.match_label = QLabel("")
        self.match_label.setWordWrap(True)
        rl.addWidget(self.match_label)
        self.recv_preview = QLabel()
        self.recv_preview.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.recv_preview.setVisible(False)
        rl.addWidget(self.recv_preview)
        rl.addWidget(QLabel("[4] ver_A(x, y) = TRUE?"))
        self.badge = ResultBadge()
        rl.addWidget(self.badge)
        self.detail = OutputBox()
        rl.addWidget(self.detail, 1)

        lay.addWidget(left, 1)
        lay.addWidget(right, 1)
        receiver_path = SAMPLE / "keys" / "thuy_enc.json"
        if receiver_path.is_file():
            try:
                self._set_receiver_key(key_io.load_private_key(receiver_path), receiver_path.name)
            except (ValueError, KeyError, OSError):
                pass

    # ---- khoá -------------------------------------------------------------------------------------------
    def _signer(self) -> tuple[RSAPublicKey | None, RSAPrivateKey | None]:
        tab = self.app.sign_tab
        return tab.pub, tab.priv

    def _set_receiver_key(self, key: RSAPrivateKey | RSAPublicKey, origin: str) -> None:
        self.receiver_priv = key if isinstance(key, RSAPrivateKey) else None
        self.receiver_pub = key.public_key if isinstance(key, RSAPrivateKey) else key
        kind = "có khoá bí mật d_B để giải mã" if self.receiver_priv else "chỉ có e_B, chưa giải mã được"
        self.receiver_key_info.setText(f"Khoá Thủy (e_B, d_B): {origin}, {key.bits} bít ({kind})")

    def generate_receiver_key(self) -> None:
        bits = self.receiver_pub.bits if self.receiver_pub is not None else 2048
        self.app.run(lambda: generate_keypair(bits),
                     lambda kp: self._set_receiver_key(kp[1], "vừa sinh"),
                     status="Đang sinh khoá mã hoá của Thủy…", owner=self)

    def open_receiver_key(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Mở khoá mã hoá/giải mã của Thủy",
                                             str(SAMPLE / "keys"), "Khoá (*.json)")
        if path:
            try:
                self._set_receiver_key(key_io.load_key(Path(path)), Path(path).name)
            except (ValueError, KeyError, OSError) as err:
                common.show_error(self, "Không mở được khoá Thủy", str(err))

    def save_receiver_key(self) -> None:
        if self.receiver_pub is None:
            common.show_info(self, "Chưa có khoá Thủy", "Sinh hoặc mở khoá Thủy trước.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Lưu khoá Thủy", "thuy_enc.json", "Khoá (*.json)")
        if path:
            try:
                if self.receiver_priv is not None:
                    key_io.save_private_key(self.receiver_priv, Path(path), "Thủy")
                else:
                    key_io.save_public_key(self.receiver_pub, Path(path))
            except OSError as err:
                common.show_error(self, "Không lưu được khoá Thủy", str(err))

    # ---- bên gửi ----------------------------------------------------------------------------------------
    def _preview_source(self) -> None:
        p = self.src.file()
        pix = QPixmap(str(p)) if p is not None and p.is_file() else QPixmap()
        self._set_preview(self.src_preview, pix)

    @staticmethod
    def _set_preview(label: QLabel, pix: QPixmap) -> None:
        label.setVisible(not pix.isNull())
        if not pix.isNull():
            label.setPixmap(pix.scaled(140, 140, Qt.AspectRatioMode.KeepAspectRatio,
                                       Qt.TransformationMode.SmoothTransformation))

    def _read_message(self) -> bytes | None:
        try:
            file = self.src.file()
            if file is not None:
                with file.open("rb") as stream:
                    data = stream.read(MAX_MESSAGE_BYTES + 1)
            else:
                got = self.src.read()
                if got is None:
                    return None
                data = got[0]
            if len(data) > MAX_MESSAGE_BYTES:
                raise ValueError(f"Chế độ ký rồi mã hoá hỗ trợ thông điệp tối đa {MAX_MESSAGE_BYTES // 1024} KiB. "
                                 f"Tệp lớn hơn hãy ký ở tab Ký & Kiểm tra.")
            return data
        except (ValueError, OSError) as err:
            common.show_warning(self, "Không mã hoá được", str(err))
            return None

    def sign_and_seal(self) -> None:
        _, priv = self._signer()
        if priv is None:
            common.show_warning(self, "Thiếu khoá Trang", "Sinh hoặc mở khoá bí mật của Trang ở tab Ký & Kiểm tra.")
            return
        if self.receiver_pub is None:
            common.show_warning(self, "Thiếu khoá Thủy", "Mở hoặc sinh khoá mã hoá của Thủy trước.")
            return
        message = self._read_message()
        if message is None:
            return
        scheme, receiver_pub = SCHEMES[self.scheme.currentText()], self.receiver_pub
        name = self.src.file().name if self.src.file() is not None else "message.txt"

        def job():
            with Timer() as t:
                h = sha256(message)
                sig = sign_hash(h, priv, scheme)
                bundle = SignatureBundle(scheme, name, h.hex(), sig.hex())
                envelope = seal(message, bundle, receiver_pub)
            return sig, envelope, t.elapsed

        def done(res) -> None:
            sig, envelope, elapsed = res
            self.sent, self.envelope, self.received = message, envelope, None
            self.sig_view.set_hex(sig)
            self.z_view.set_hex("".join(envelope["blocks"]))
            self.time_label.setText(f"{elapsed * 1000:.1f} ms")
            self.signer_info.setText(f"Khoá ký a_A của Trang: n {priv.n.bit_length()} bít "
                                     f"(lấy từ tab Ký & Kiểm tra)")
            self._clear_receiver()
            self.badge.set_info("Đã gửi z cho Thủy", "Bấm Giải mã z, rồi Kiểm tra chữ ký")
            self.detail.append(f"=== Trang ký {name} ({self.scheme.currentText()}) rồi mã hoá bằng e_B: "
                               f"{len(envelope['blocks'])} khối RSA-OAEP, n_B {receiver_pub.n.bit_length()} bít ===\n")

        self.app.run(job, done, status="Đang ký rồi mã hoá…", owner=self)

    def save_encrypted(self) -> None:
        if self.envelope is None:
            common.show_info(self, "Chưa có bản mã", "Bấm Ký rồi mã hoá, hoặc mở một tệp z.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Lưu bản mã z", "message.enc.json", "Bản mã (*.enc.json)")
        if path:
            try:
                Path(path).write_text(json.dumps(self.envelope, ensure_ascii=False, indent=2), encoding="utf-8")
                self.detail.append(f"Đã lưu bản mã z: {path}\n", "ok")
            except OSError as err:
                common.show_error(self, "Không lưu được bản mã", str(err))

    # ---- đường truyền -----------------------------------------------------------------------------------
    def tamper_z(self) -> None:
        if self.envelope is None:
            common.show_info(self, "Chưa có z", "Bấm Ký rồi mã hoá trước.")
            return
        block = bytearray.fromhex(self.envelope["blocks"][0])
        block[-1] ^= 0x01
        self.envelope = {**self.envelope, "blocks": [block.hex(), *self.envelope["blocks"][1:]]}
        self.z_view.set_hex("".join(self.envelope["blocks"]))
        self._clear_receiver()
        self.badge.set_info("Phương đã sửa z", "Bấm Giải mã z để xem Thủy phát hiện")
        self.detail.append("Phương (Attacker) lật 1 bít cuối của khối z đầu tiên.\n", "bad")

    def show_forwarding(self) -> None:
        # Chuyển tiếp lén: tấn công dành riêng cho ký rồi mã hoá, đã có ở tab Phân tích an toàn
        tab = self.app.attacks_tab
        self.app.tabs.setCurrentWidget(tab)
        tab.select("a8_surreptitious_forwarding")
        tab.run_selected()

    # ---- bên nhận ---------------------------------------------------------------------------------------
    def _clear_receiver(self) -> None:
        self.received = None
        self.x_view.clear()
        self.match_label.clear()
        self.recv_preview.setVisible(False)

    def open_encrypted(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Mở bản mã z", "", "Bản mã (*.enc.json)")
        if path:
            self._load_encrypted(Path(path))

    def _load_encrypted(self, path: Path) -> None:
        try:
            if path.stat().st_size > MAX_ENVELOPE_FILE_BYTES:
                raise ValueError("Tệp bản mã quá lớn cho demo")
            envelope = json.loads(path.read_text(encoding="utf-8"))
            if (envelope["algorithm"] != ALGORITHM or not isinstance(envelope["blocks"], list)
                    or not envelope["blocks"]):
                raise ValueError("Định dạng bản mã không hợp lệ")
            bytes.fromhex(envelope["package_id"])
            for block in envelope["blocks"]:
                bytes.fromhex(block)
        except (OSError, ValueError, KeyError, TypeError) as err:
            common.show_error(self, "Không mở được bản mã", str(err))
            return
        self.envelope, self.sent = envelope, None
        self.z_view.set_hex("".join(envelope["blocks"]))
        self._clear_receiver()
        self.badge.set_info("Đã nhận z", "Bấm Giải mã z")

    def decrypt_received(self) -> None:
        if self.envelope is None:
            common.show_info(self, "Chưa có bản mã cần giải mã", "Bấm Ký rồi mã hoá hoặc mở tệp z.")
            return
        if self.receiver_priv is None:
            common.show_warning(self, "Thiếu khoá bí mật của Thủy", "Mở đúng khoá bí mật d_B của Thủy để giải mã z.")
            return
        envelope, priv = self.envelope, self.receiver_priv

        def job():
            try:
                return unseal(envelope, priv), None
            except ValueError as err:
                return None, str(err)

        def done(res) -> None:
            opened, error = res
            self._clear_receiver()
            if error is not None:
                self.badge.set_result(False, error, bad_text="GIẢI MÃ THẤT BẠI")
                self.detail.append(f"Giải mã z bằng d_B thất bại: {error}\n", "bad")
                return
            message, bundle = opened
            self.received = (message, bundle)
            self.x_view.set_hex(message.decode("utf-8") if _is_text(message) else message.hex())
            if self.sent is not None:
                same = message == self.sent
                self.match_label.setText(f"So với x Trang gửi: {'khớp từng byte' if same else 'KHÁC'} "
                                         f"({len(message):,} byte)")
            self._set_preview(self.recv_preview, _pixmap(message))
            self.badge.set_info("Đã giải mã z", "Bấm Kiểm tra chữ ký bằng khoá công khai b_A của Trang")
            self.detail.append("Giải mã z bằng d_B của Thủy: đã khôi phục (x, y).\n", "ok")

        self.app.run(job, done, status="Đang giải mã z…", owner=self)

    def verify(self) -> None:
        if self.received is None:
            common.show_warning(self, "Cần giải mã z", "Thủy phải giải mã z bằng d_B trước, rồi mới kiểm tra chữ ký.")
            return
        pub, _ = self._signer()
        if pub is None:
            common.show_warning(self, "Thiếu khoá Trang", "Cần khoá công khai b_A của Trang ở tab Ký & Kiểm tra.")
            return
        message, bundle = self.received
        log = StepLogger()
        h = sha256(message)
        log.log("Băm thông điệp giải mã được", "h(x) = SHA-256(x)", h.hex())
        res = verify_hash(h, bundle.signature, pub, bundle.scheme, log)
        self.badge.set_result(res.valid, res.reason)
        self.detail.append(f"\n--- ver_A(x, y) bằng khoá công khai b_A của Trang (n {pub.n.bit_length()} bít) ---\n",
                           "head")
        self.detail.append_steps(log)

    def dragEnterEvent(self, event) -> None:
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event) -> None:
        for url in event.mimeData().urls():
            p = Path(url.toLocalFile())
            if p.name.endswith(".enc.json"):
                self._load_encrypted(p)
            elif p.is_file():
                self.src.set_file(p)


def _is_text(data: bytes) -> bool:
    try:
        data.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False
