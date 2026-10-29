"""Sáu tab của giao diện, mỗi tab một class."""
import base64
import json
import os
import subprocess
import sys

from PySide6.QtCore import Qt
from PySide6.QtGui import QTextOption
from PySide6.QtWidgets import (QAbstractItemView, QCheckBox, QComboBox, QFileDialog, QFrame, QGridLayout,
                               QGroupBox, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QScrollArea, QSplitter,
                               QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget)

from core.rsa_math import generate_keypair, explain_keygen, byte_length, mod_exp
from core.sha256 import hash_sha256
from core import rsa_full, rsa_mini, padding
from core import secure_message as sm
from scenarios.s1_authentication import run_scenario_s1
from scenarios.s2_nonrepudiation import run_scenario_s2
from scenarios.s3_revocation import run_scenario_s3
from scenarios.s4_replay import run_scenario_s4
from scenarios.s5_key_substitution import run_scenario_s5
from scenarios.s6_confidentiality import run_scenario_s6
from scenarios.run_all import run_all
from attacks import (small_n, forgery_no_padding, bleichenbacher_e3, hash_collision, weak_keys, crt_fault,
                     confidentiality)
from attacks.run_all import run_all as run_all_attacks
from demo import avalanche, file_signer
from demo.gui import widgets
from demo.gui.widgets import (BLUE, GREEN, GREY, PEOPLE, RED, ROLES, ROOT, DataSource, OutputBox, amp, bold_label,
                              button, glass, hbox, labeled_entry, mono_font, parse_int, short_int, text_box,
                              with_role)


# ======================================================================
# Tab 1: Khóa — sinh, xem, lưu và nạp khóa
# ======================================================================
class KeyTab(QWidget):
    def __init__(self, app):
        super().__init__()
        self.app = app
        lay = QVBoxLayout(self)

        ctl = QGroupBox("Sinh khóa")
        self.who = QComboBox()
        for n in PEOPLE + ("Tất cả",):
            self.who.addItem(with_role(n), n)           # hiện tên kèm vai trò, dữ liệu là tên trần
        self.who.setCurrentText("Tất cả")
        self.bits = QComboBox()
        self.bits.addItems(("512", "1024", "2048", "3072"))
        self.bits.setCurrentText("2048")
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.VLine)
        lp, self.p = labeled_entry("p")
        lq, self.q = labeled_entry("q")
        le, self.e = labeled_entry("e")
        ctl.setLayout(hbox(QLabel("Người:"), self.who, QLabel("Độ dài khóa:"), self.bits,
                           button("Sinh khóa ngẫu nhiên", self.gen_random), sep,
                           lp, self.p, lq, self.q, le, self.e, button("Sinh từ p, q, e", self.gen_manual), None))
        lay.addWidget(ctl)

        self.protect = QCheckBox("Mã hóa khóa riêng bằng mật khẩu khi lưu (PBKDF2)")
        lay.addLayout(hbox(button("Lưu khóa của người đang chọn...", self.save),
                           button("Nạp khóa riêng từ tệp JSON...", self.load), self.protect, None))

        self.table = glass(QTableWidget(0, 5))
        self.table.setHorizontalHeaderLabels(("Người", "Vai trò", "Số bit N", "e", "N (hex)"))
        self.table.setAlternatingRowColors(False)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setShowGrid(False)
        header = self.table.horizontalHeader()
        header.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft)
        for c, w in enumerate((100, 150, 80, 80)):
            self.table.setColumnWidth(c, w)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        rows = len(PEOPLE) + 1
        self.table.setFixedHeight(header.sizeHint().height() + self.table.verticalHeader().defaultSectionSize() * rows)
        self.table.itemSelectionChanged.connect(self.show_detail)
        lay.addWidget(self.table)

        self.out = OutputBox()
        lay.addWidget(self.out, 1)

    def _targets(self):
        return PEOPLE if self.who.currentData() == "Tất cả" else (self.who.currentData(),)

    def gen_random(self):
        self.app.generate_keys(self._targets(), int(self.bits.currentText()))

    def gen_manual(self):
        if not all(w.text().strip() for w in (self.p, self.q, self.e)):
            widgets.show_warning(self, "Thiếu tham số", "Hãy nhập đủ p, q, e.")
            return
        try:
            p, q, e = int(self.p.text()), int(self.q.text()), int(self.e.text())
            pair = generate_keypair(p=p, q=q, e=e)
        except ValueError as err:
            widgets.show_error(self, "Tham số không hợp lệ", str(err))
            return
        self.out.clear()
        self.out.append(f"=== Sinh khóa từ p={p}, q={q}, e={e} ===\n")
        self.out.append("\n".join(explain_keygen(p, q, e)) + "\n")
        bits = pair[1][1].bit_length()
        if bits < 512:                      # khóa nhỏ không ký/mã hóa có đệm được: chỉ xem, không đè khóa đang dùng
            self.out.append(f"\nN chỉ {bits} bit: chỉ để xem cách sinh khóa, KHÔNG thay khóa đang dùng.\n"
                            "Ký và mã hóa ở tab 2, 3 cần N >= 512 / 1024 bit; tính tay với số nhỏ dùng tab 4.\n", "dim")
            return
        for n in self._targets():
            self.app.keys[n] = pair
        self.refresh()
        self.out.append(f"\nĐã dùng khóa này cho: {', '.join(self._targets())}\n", "ok")

    def refresh(self):
        self.table.blockSignals(True)
        self.table.setRowCount(0)
        for n in PEOPLE:
            if n in self.app.keys:
                (_, N), (e, _) = self.app.keys[n]
                r = self.table.rowCount()
                self.table.insertRow(r)
                for c, v in enumerate((with_role(n), ROLES[n], N.bit_length(), e, short_int(N, 60, 16))):
                    self.table.setItem(r, c, QTableWidgetItem(str(v)))
                self.table.item(r, 0).setData(Qt.ItemDataRole.UserRole, n)
        self.table.blockSignals(False)

    def show_detail(self):
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return
        n = self.table.item(rows[0].row(), 0).data(Qt.ItemDataRole.UserRole)
        self.who.setCurrentIndex(self.who.findData(n))
        (d, N), (e, _) = self.app.keys[n]
        self.out.clear()
        self.out.append(f"=== Khóa của {n} — {ROLES[n]} ===\n")
        self.out.append(f"Khóa công khai (e, N):\n  e = {e}\n  N = {N}\n\n")
        self.out.append(f"Khóa riêng d (bí mật, chỉ {n} giữ):\n  d = {d}\n", "dim")
        self.out.append(f"\nKiểm tra: (2^e)^d mod N = 2 ? {mod_exp(mod_exp(2, e, N), d, N) == 2}\n")

    def save(self):
        n = self.who.currentData()
        if n not in self.app.keys:
            widgets.show_info(self, "Chọn người", "Chọn một người (không phải 'Tất cả') đã có khóa.")
            return
        folder = QFileDialog.getExistingDirectory(self, with_role(f"Chọn thư mục lưu khóa của {n}"))
        if not folder:
            return
        pw = None
        if self.protect.isChecked():
            pw = widgets.ask_password(self, "Đặt mật khẩu bảo vệ khóa riêng:")
            if not pw:
                return
        usage = "encryption" if n == "Thu Thủy" else "signature"
        priv, pub = self.app.keys[n]
        paths = file_signer.save_keypair(n.lower(), priv, pub, folder, usage, pw)
        self.out.append(f"Đã lưu: {paths[0]}\n       {paths[1]}\n", "ok")

    def load(self):
        path, _ = QFileDialog.getOpenFileName(self, "Chọn tệp khóa riêng (*.private.json)", "",
                                              "Khóa riêng (*.private.json);;JSON (*.json)")
        if not path:
            return
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            pw = None
            if "protected" in data:
                pw = widgets.ask_password(self, "Nhập mật khẩu của khóa riêng:")
                if pw is None:
                    return
            priv = file_signer.load_private_key(path, password=pw)
            pub = (data["e"], priv[1])
        except (ValueError, KeyError, OSError) as err:
            widgets.show_error(self, "Không nạp được khóa", str(err))
            return
        cur = self.who.currentData()
        n = cur if cur in PEOPLE else data.get("owner", "Thu Trang").capitalize()
        if n not in PEOPLE:
            n = "Thu Trang"
        self.app.keys[n] = (priv, pub)
        self.refresh()
        self.out.append(f"Đã nạp khóa từ {path} cho {n}\n", "ok")


# ======================================================================
# Tab 2: Ký & Kiểm tra
# ======================================================================
class SignTab(QWidget):
    def __init__(self, app):
        super().__init__()
        self.app = app
        self.recv_data = None
        lay = QHBoxLayout(self)

        left = QGroupBox(with_role("BÊN KÝ: Thu Trang - dùng khóa riêng"))
        ll = QVBoxLayout(left)
        self.src = DataSource("Thông điệp cần ký")
        ll.addWidget(self.src)
        self.scheme = QComboBox()
        self.scheme.addItems(("PKCS#1 v1.5", "PSS"))
        ll.addLayout(hbox(QLabel("Lược đồ đệm:"), self.scheme, button("Ký", self.sign), None))
        ll.addWidget(QLabel("[1] SHA-256(M)"))
        self.hash_box = QLineEdit()
        self.hash_box.setReadOnly(True)
        self.hash_box.setFont(mono_font())
        ll.addWidget(self.hash_box)
        ll.addWidget(QLabel("[2] Khối đệm EM (đưa vào lũy thừa)"))
        self.em = text_box(5, read_only=True)
        self.em.setWordWrapMode(QTextOption.WrapMode.WrapAnywhere)
        ll.addWidget(self.em)
        ll.addWidget(QLabel("[3] Chữ ký S = EM^d mod N (hex) — có thể sửa để thử giả mạo"))
        self.sig = text_box()
        self.sig.setWordWrapMode(QTextOption.WrapMode.WrapAnywhere)
        ll.addWidget(self.sig, 1)

        right = QGroupBox(with_role("BÊN NHẬN: Thu Thủy - dùng khóa công khai của Thu Trang"))
        rl = QVBoxLayout(right)
        rl.addWidget(bold_label("Thông điệp nhận được (sửa thử rồi bấm Kiểm tra)"))
        self.recv = text_box(6)
        rl.addWidget(self.recv)
        self.flip_btn = button("Mai Phương đổi 1 bit của tệp", self.flip_bit)
        self.flip_btn.setEnabled(False)
        rl.addLayout(hbox(button("Kiểm tra chữ ký", self.verify), self.flip_btn,
                          button("Thử khóa của Mai Phương", lambda: self.verify("Mai Phương")), None))
        self.result = QLabel("")
        self.result.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.result.setMinimumHeight(48)
        self._set_result("", GREY)
        rl.addWidget(self.result)
        self.detail = OutputBox()
        rl.addWidget(self.detail, 1)

        lay.addWidget(left, 1)
        lay.addWidget(right, 1)

    def _set_result(self, text, color):
        self.result.setText(text)
        self.result.setStyleSheet(f"color: {color}; font-size: 18px; font-weight: 700;")

    def _scheme(self):
        return "pss" if self.scheme.currentText() == "PSS" else "pkcs1v15"

    def sign(self):
        pair = self.app.key("Thu Trang", 1024 if self._scheme() == "pss" else 512, "Chữ ký có đệm")
        if not pair:
            return
        got = self.src.read()
        if got is None:
            return
        data, name = got
        priv, _ = pair
        scheme = self._scheme()

        def job():
            h = hash_sha256(data)
            if scheme == "pkcs1v15":
                em = padding.pkcs1_v15_encode(bytes.fromhex(h), byte_length(priv[1])).hex()
            else:
                em = "(PSS: EM = maskedDB || H || BC, chứa salt ngẫu nhiên nên mỗi lần ký ra khối khác nhau)"
            return h, em, rsa_full.sign_hash(h, priv, scheme)

        def done(res):
            h, em, s = res
            self.hash_box.setText(h)
            self.em.setPlainText(em)
            self.sig.setPlainText(format(s, "x"))
            self.recv_data = data
            if name:
                self.recv.setPlainText(f"[Tệp nhận được: {name}, {len(data):,} byte — dùng nút 'Mai Phương đổi 1 bit' để sửa]")
                self.recv.setReadOnly(True)
                self.flip_btn.setEnabled(True)
            else:
                self.recv.setPlainText(data.decode("utf-8"))
                self.recv.setReadOnly(False)
                self.flip_btn.setEnabled(False)
            self._set_result("Đã ký — bấm Kiểm tra", BLUE)
            self.detail.clear()
            self.detail.append(f"Thu Trang ký {'tệp ' + name if name else 'văn bản'} ({len(data):,} byte) "
                               f"bằng {self.scheme.currentText()}, khóa {priv[1].bit_length()} bit.\n")

        self.app.run(job, done, status="Đang băm và ký...")

    def flip_bit(self):
        if self.recv_data:
            b = bytearray(self.recv_data)
            b[len(b) // 2] ^= 0x01
            self.recv_data = bytes(b)
            self.detail.append(f"Mai Phương đổi 1 bit ở byte thứ {len(b) // 2:,} của tệp.\n", "bad")

    def verify(self, signer="Thu Trang"):
        pair = self.app.key(signer)
        if not pair:
            return
        try:
            s = parse_int(self.sig.toPlainText())
        except ValueError:
            widgets.show_error(self, "Chữ ký không hợp lệ", "Ô chữ ký phải là số hex.")
            return
        data = (self.recv_data or b"") if self.recv.isReadOnly() else self.recv.toPlainText().encode("utf-8")
        _, pub = pair
        scheme = self._scheme()

        def job():
            h = hash_sha256(data)
            ok = rsa_full.verify_hash(h, s, pub, scheme)
            recovered = rsa_full.verify_signature(s, pub) if scheme == "pkcs1v15" else None
            return ok, h, recovered

        def done(res):
            ok, h, recovered = res
            self._set_result("CHỮ KÝ HỢP LỆ" if ok else "CHỮ KÝ KHÔNG HỢP LỆ", GREEN if ok else RED)
            self.detail.append(f"\n--- Kiểm tra bằng khóa công khai của {signer} ---\n", "head")
            self.detail.append(f"Băm A (tự tính từ thông điệp nhận) : {h}\n")
            if scheme == "pkcs1v15":
                self.detail.append(f"Băm B (gỡ từ chữ ký S^e mod N)     : {recovered or '(khối đệm sai cấu trúc)'}\n")
            self.detail.append(("Khớp: đúng người ký, nội dung nguyên vẹn.\n" if ok else
                                "Không khớp: nội dung bị sửa, chữ ký bị sửa, hoặc sai người ký.\n"),
                               "ok" if ok else "bad")

        self.app.run(job, done, status="Đang kiểm tra...")


# ======================================================================
# Tab 3: Bảo mật — chỉ ký so với ký rồi mã hóa
# ======================================================================
class ConfidentialityTab(QWidget):
    def __init__(self, app):
        super().__init__()
        self.app = app
        self.env = None
        self.plain = None
        self.opened = None
        lay = QVBoxLayout(self)

        self.src = DataSource("Thông điệp / tệp bí mật Thu Trang gửi Thu Thủy", lines=3)
        lay.addWidget(self.src)

        btns = QGroupBox("Thao tác")
        grid = QGridLayout(btns)
        actions = [
            ("1. Chỉ ký, không mã hóa: Mai Phương thấy gì?", self.only_sign),
            ("2. Thu Trang KÝ RỒI MÃ HÓA gửi Thu Thủy", self.seal),
            ("3. Thu Thủy mở", self.bob_open),
            ("4. Mai Phương mở bằng khóa của Mai Phương", self.eve_open),
            ("5. Mai Phương sửa 1 byte bản mã", self.tamper),
            ("6. Mai Phương giả thư nhân danh Thu Trang", self.forge),
            ("7. Thu Thủy chuyển tiếp lén cho Tuyết Linh", self.forward),
            ("Lưu tệp Thu Thủy đã giải mã...", self.save_plain),
        ]
        for i, (t, cmd) in enumerate(actions):
            grid.addWidget(button(t, cmd), i // 3, i % 3)
        for c in range(3):
            grid.setColumnStretch(c, 1)
        lay.addWidget(btns)

        body = QSplitter(Qt.Orientation.Horizontal)
        self.wire, self.log = OutputBox(), OutputBox()
        for title, out in (("Gói tin trên đường truyền (Mai Phương nhìn thấy)", self.wire), ("Nhật ký", self.log)):
            box = QGroupBox(with_role(title))
            QVBoxLayout(box).addWidget(out)
            body.addWidget(box)
        lay.addWidget(body, 1)

    def _keys(self):
        pairs = [self.app.key(n, 1024, "Mã hóa OAEP") for n in PEOPLE]
        return None if None in pairs else dict(zip(PEOPLE, pairs))

    def _show_env(self, env, title):
        view = {k: (v[:64] + f"… ({len(v):,} ký tự)") if len(v) > 70 else v for k, v in env.items()}
        self.wire.clear()
        self.wire.append(f"=== {title} ===\n")
        self.wire.append(json.dumps(view, indent=2, ensure_ascii=False) + "\n")
        self.wire.append("\nĐối chiếu sơ đồ bài giảng (mã hóa lai bằng khóa phiên K):\n"
                         "  ek  = C1 = RSA-OAEP(K, khóa công khai của người nhận)\n"
                         "  ct  = C2 = Mã hóa đối xứng (P, S) bằng khóa phiên K\n"
                         "  tag = HMAC trên C2 (phát hiện sửa bản mã)\n")
        self.wire.append("\nKhông có nội dung rõ, không có tên người gửi, không có chữ ký ở dạng rõ.\n", "ok")

    def only_sign(self):
        k = self._keys()
        if not k:
            return
        got = self.src.read()
        if got is None:
            return
        data, name = got

        def job():
            return rsa_full.sign_message(data, k["Thu Trang"][0])

        def done(s):
            self.wire.clear()
            self.wire.append("=== Chỉ ký: gói (M, S) ===\n")
            preview = data[:600].decode("utf-8", "replace") if not name else f"<tệp {name}, {len(data):,} byte — gửi nguyên văn>"
            self.wire.append(f"M = {preview}\n", "bad", roles=False)
            self.wire.append(f"S = {short_int(s)}\n")
            ok = rsa_full.verify_message(data, s, k["Thu Trang"][1])
            self.log.append(f"\n[Chỉ ký] Mai Phương đọc được toàn bộ nội dung; Mai Phương còn tự kiểm tra được chữ ký: {ok}\n"
                            "=> Chữ ký số KHÔNG cung cấp tính bảo mật.\n", "bad")

        self.app.run(job, done, status="Đang ký...")

    def seal(self):
        k = self._keys()
        if not k:
            return
        got = self.src.read()
        if got is None:
            return
        data, name = got

        def job():
            return sm.seal(data, "Thu Trang", k["Thu Trang"][0], "Thu Thủy", k["Thu Thủy"][1], filename=name)

        def done(env):
            self.env, self.plain, self.opened = env, data, None
            self._show_env(env, "Thu Trang → Thu Thủy: phong bì đã ký rồi mã hóa")
            self.log.append(f"\n[Thu Trang] Đã ký và mã hóa {len(data):,} byte gửi Thu Thủy\n", "ok")

        self.app.run(job, done, status="Đang ký rồi mã hóa...")

    def _open(self, env, me, label, expect_ok):
        k = self._keys()
        if not k or env is None:
            if env is None:
                widgets.show_info(self, "Chưa có phong bì", "Bấm '2. Thu Trang KÝ RỒI MÃ HÓA' trước.")
            return

        def job():
            try:
                return True, sm.open_sealed(env, me, k[me][0], {"Thu Trang": k["Thu Trang"][1]}.get)
            except sm.SecureMessageError as err:
                return False, err.reason

        def done(res):
            ok, val = res
            self.log.append(f"\n[{label}]\n", "head")
            if ok:
                msg = val["message"]
                same = msg == self.plain
                self.opened = val
                body = msg.decode("utf-8", "replace") if not val["meta"].get("filename") else \
                    f"<tệp {val['meta']['filename']}, {len(msg):,} byte>"
                self.log.append(f"{me} mở được: ")
                self.log.append(f"{body[:500]}\n", roles=False)        # nội dung thư: in nguyên văn
                self.log.append(f"Chữ ký hợp lệ, người gửi: {val['sender']} lúc {val['meta']['time']}; "
                                f"giống hệt bản gốc: {same}\n", "ok" if expect_ok else "bad")
            else:
                self.log.append(f"{me}: {val}" + ("\n" if expect_ok else " (tấn công bị chặn)\n"),
                                "bad" if expect_ok else "ok")

        self.app.run(job, done, status=f"{me} đang mở phong bì...")

    def bob_open(self):
        self._open(self.env, "Thu Thủy", "Thu Thủy mở bằng khóa riêng của Thu Thủy", True)

    def eve_open(self):
        self._open(self.env, "Mai Phương", "Mai Phương chặn được phong bì, mở bằng khóa riêng của Mai Phương", False)

    def tamper(self):
        if self.env is None:
            return self._open(None, "Thu Thủy", "", False)
        ct = bytearray(base64.b64decode(self.env["ct"]))
        ct[len(ct) // 2] ^= 0x01
        bad = dict(self.env, ct=base64.b64encode(bytes(ct)).decode())
        self._show_env(bad, "Phong bì đã bị Mai Phương sửa 1 bit trong bản mã")
        self._open(bad, "Thu Thủy", "Mai Phương sửa 1 bit bản mã rồi chuyển tiếp cho Thu Thủy", False)

    def forge(self):
        k = self._keys()
        if not k:
            return
        fake = "Thu Trang: chuyển ngay 200 triệu vào tài khoản 0123 của Mai Phương."

        def job():
            return sm.seal(fake, "Thu Trang", k["Mai Phương"][0], "Thu Thủy", k["Thu Thủy"][1])

        def done(env):
            self._show_env(env, "Phong bì giả do Mai Phương tạo (mã hóa bằng khóa CÔNG KHAI của Thu Thủy)")
            self.log.append("\n[Mai Phương] Ai cũng có khóa công khai của Thu Thủy nên Mai Phương tự mã hóa thư giả, ký bằng khóa của Mai Phương.\n")
            self._open(env, "Thu Thủy", "Thu Thủy mở thư giả", False)

        self.app.run(job, done, status="Mai Phương đang tạo thư giả...")

    def forward(self):
        k = self._keys()
        if not k or self.env is None:
            return self._open(None, "Thu Thủy", "", False)
        env = self.env

        def job():
            inner = sm.decrypt_envelope(env, k["Thu Thủy"][0])
            return sm.encrypt_for(inner, "Tuyết Linh", k["Tuyết Linh"][1])

        def done(fwd):
            self._show_env(fwd, "Thu Thủy giải mã rồi mã hóa lại thư của Thu Trang gửi Tuyết Linh")
            self._open(fwd, "Tuyết Linh", "Tuyết Linh mở thư Thu Thủy chuyển tiếp (chữ ký Thu Trang vẫn nguyên)", False)

        self.app.run(job, done, status="Thu Thủy đang chuyển tiếp...")

    def save_plain(self):
        if not self.opened:
            widgets.show_info(self, "Chưa có", "Bấm '3. Thu Thủy mở' thành công trước.")
            return
        name = self.opened["meta"].get("filename") or "thong_diep.txt"
        path, _ = QFileDialog.getSaveFileName(self, "Lưu tệp đã giải mã", "giai_ma_" + name)
        if path:
            with open(path, "wb") as f:
                f.write(self.opened["message"])
            self.log.append(f"Đã lưu tệp giải mã: {path}\n", "ok")


# ======================================================================
# Tab 4: Tính tay — RSA thu nhỏ
# ======================================================================
class MiniTab(QWidget):
    def __init__(self, app):
        super().__init__()
        self.app = app
        lay = QVBoxLayout(self)
        self.vars = {}
        row = []
        for name in ("p", "q", "e", "M"):
            label, entry = labeled_entry(name)
            row += [label, entry]
            self.vars[name] = entry
        lay.addLayout(hbox(*row, button("Tính từng bước", self.compute),
                           button("Ví dụ đầy đủ (3 phần, có ký rồi mã hóa)", self.class_demo),
                           None, button("Xóa", lambda: self.out.clear())))
        self.out = OutputBox()
        lay.addWidget(self.out, 1)

    def compute(self):
        self.out.clear()
        if not all(self.vars[k].text().strip() for k in ("p", "q", "e", "M")):
            self.out.append("[Lỗi] Hãy nhập đủ p, q, e, M (ví dụ trên lớp: p = 17, q = 11, e = 7, M = 88).\n", "bad")
            return
        try:
            p, q, e, M = (int(self.vars[k].text()) for k in ("p", "q", "e", "M"))
            priv, pub = generate_keypair(p=p, q=q, e=e)
        except ValueError as err:
            self.out.append(f"[Lỗi] {err}\n", "bad")
            return
        d, N = priv
        if not 0 <= M < N:
            self.out.append(f"[Lỗi] Cần 0 <= M < N = {N}\n", "bad")
            return
        say = lambda *a: self.out.append(" ".join(str(x) for x in a) + "\n")
        say(f"=== Sinh khóa: p={p}, q={q}, e={e} ===")
        for line in explain_keygen(p, q, e):
            say("  " + line)
        say("\n=== Mã hóa C = M^e mod N ===")
        C = rsa_mini.show_mod_exp(M, e, N, "C", say)
        say("\n=== Giải mã M = C^d mod N ===")
        M2 = rsa_mini.show_mod_exp(C, d, N, "M", say)
        say("  Giải mã đúng bản rõ" if M2 == M else "  Sai")
        say("\n=== Ký S = M^d mod N ===")
        S = rsa_mini.show_mod_exp(M, d, N, "S", say)
        say("\n=== Kiểm tra S^e mod N ===")
        V = rsa_mini.show_mod_exp(S, e, N, "V", say)
        say(f"  V = {V} " + ("= M -> chữ ký hợp lệ" if V == M else "≠ M"))
        bad = (M + 1) % N
        say(f"  Với M bị sửa thành {bad}: " + ("chấp nhận" if rsa_mini.verify(bad, S, pub) else "bị từ chối"))

    def class_demo(self):
        self.out.clear()
        self.app.run(lambda: rsa_mini.run_demo(), output=self.out, status="Đang chạy ví dụ trên lớp...")


# ======================================================================
# Tab 5: Kịch bản & Tấn công
# ======================================================================
class ScenarioTab(QWidget):
    def __init__(self, app):
        super().__init__()
        self.app = app
        lay = QHBoxLayout(self)
        left = QWidget()
        ll = QVBoxLayout(left)
        ll.setContentsMargins(0, 0, 6, 0)
        self.bits = QComboBox()
        self.bits.addItems(("512", "1024", "2048"))
        self.bits.setCurrentText("1024")
        ll.addLayout(hbox(QLabel("Độ dài khóa:"), self.bits, None, button("Xóa kết quả", lambda: self.out.clear())))

        ks = lambda: int(self.bits.currentText())
        groups = [
            ("Kịch bản an toàn", [
                ("S1: Xác thực người dùng", lambda: run_scenario_s1(keysize=ks())),
                ("S2: Chống chối bỏ", lambda: run_scenario_s2(keysize=ks())),
                ("S3: Khóa bị lộ, thu hồi", lambda: run_scenario_s3(keysize=ks())),
                ("S4: Phát lại (nonce)", lambda: run_scenario_s4(keysize=ks())),
                ("S5: Thay khóa công khai", lambda: run_scenario_s5(keysize=ks())),
                ("S6: Tính bảo mật", lambda: run_scenario_s6(keysize=max(ks(), 1024))),
                ("Chạy tất cả S1-S6", lambda: run_all(keysize=max(ks(), 1024))),
            ]),
            ("Tấn công: lược đồ ký & hàm băm", [
                ("Phân tích N nhỏ", lambda: small_n.demo_small_n()),
                ("Giả mạo tồn tại", lambda: forgery_no_padding.demo_existential_forgery()),
                ("Giả mạo nhân tính", lambda: forgery_no_padding.demo_no_padding_forgery()),
                ("Bleichenbacher e = 3", lambda: bleichenbacher_e3.demo_bleichenbacher(keysize=max(ks(), 1536))),
                ("Va chạm băm (ngày sinh)", lambda: hash_collision.demo_hash_collision(keysize=max(ks(), 1024))),
            ]),
            ("Tấn công: sinh khóa & thiết bị ký", [
                ("Fermat (p ≈ q)", lambda: weak_keys.demo_fermat(keysize=max(ks(), 1024))),
                ("Chung thừa số (gcd)", lambda: weak_keys.demo_shared_prime(keysize=max(ks(), 1024))),
                ("Dùng chung modulus N", lambda: weak_keys.demo_common_modulus(keysize=max(ks(), 1024))),
                ("Lỗi phần cứng ký CRT", lambda: crt_fault.demo_crt_fault(keysize=max(ks(), 1024))),
            ]),
            ("Tấn công vào tính bảo mật", [
                ("Từ điển: RSA thuần / OAEP", lambda: confidentiality.demo_dictionary(keysize=max(ks(), 1024))),
                ("Ký song song mã hóa", lambda: confidentiality.demo_encrypt_and_sign_leak(keysize=max(ks(), 1024))),
                ("Håstad (e = 3)", lambda: confidentiality.demo_hastad(keysize=1024)),
                ("Chung khóa ký & giải mã", lambda: confidentiality.demo_same_key_sign_decrypt()),
            ]),
            ("Tổng hợp", [
                ("Chạy toàn bộ 13 tấn công + bảng tổng kết", lambda: run_all_attacks()),
            ]),
        ]
        for title, items in groups:
            box = QGroupBox(amp(title))
            grid = QGridLayout(box)
            grid.setSpacing(4)
            cols = 2 if len(items) > 1 else 1
            for i, (label, fn) in enumerate(items):
                grid.addWidget(button(label, lambda f=fn, l=label: self.launch(f, l)), i // cols, i % cols)
            ll.addWidget(box)
        ll.addStretch(1)
        scroll = glass(QScrollArea())              # màn hình thấp thì cuộn được cột nút
        scroll.setWidget(left)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setFixedWidth(450)
        lay.addWidget(scroll)

        self.out = OutputBox()
        lay.addWidget(self.out, 1)

    def launch(self, fn, label):
        self.out.append(f"\n>>> {label}\n", "head")
        self.app.run(fn, output=self.out, status=f"Đang chạy: {label}")


# ======================================================================
# Tab 6: Kiểm thử & Đánh giá
# ======================================================================
class ToolsTab(QWidget):
    def __init__(self, app):
        super().__init__()
        self.app = app
        lay = QVBoxLayout(self)
        lay.addLayout(hbox(button("Đối chiếu NIST / RFC / thư viện", self.cross_check),
                           button("Hiệu ứng thác lũ (lý do ký trên băm)", self.avalanche),
                           button("Benchmark (nhanh)", self.benchmark),
                           button("Chạy bộ test (tests/)", self.tests),
                           None, button("Xóa", lambda: self.out.clear())))
        self.out = OutputBox()
        lay.addWidget(self.out, 1)

    def _go(self, fn, label):
        self.out.append(f"\n>>> {label}\n", "head")
        self.app.run(fn, output=self.out, status=f"Đang chạy: {label}")

    def cross_check(self):
        def job():
            sys.path.insert(0, str(ROOT / "tests"))
            import tests.cross_check
            return tests.cross_check.run()
        self._go(job, "Đối chiếu chuẩn")

    def avalanche(self):
        self._go(lambda: avalanche.run_demo(), "Hiệu ứng thác lũ")

    def benchmark(self):
        def job():
            from demo import benchmark
            benchmark.run_benchmark(real=False)
        self._go(job, "Benchmark")

    def tests(self):
        def job():
            env = dict(os.environ, PYTHONIOENCODING="utf-8", QT_QPA_PLATFORM="offscreen")
            proc = subprocess.Popen([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"], cwd=ROOT,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                    encoding="utf-8", errors="replace", env=env,
                                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            for line in proc.stdout:
                print(line.rstrip("\n"))
            return proc.wait()
        self._go(job, "Bộ test")
