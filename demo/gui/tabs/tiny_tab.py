from __future__ import annotations

from dataclasses import replace

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QIntValidator
from PySide6.QtWidgets import (QAbstractItemView, QBoxLayout, QButtonGroup, QCheckBox, QFrame, QGroupBox,
                               QHeaderView, QLabel, QLineEdit, QRadioButton, QSizePolicy, QSplitter, QTableWidget,
                               QTableWidgetItem, QTabWidget, QVBoxLayout, QWidget)

from core.number_theory import mod_pow
from core.primality import is_probable_prime
from core.step_logger import StepLogger
from core.tiny_rsa import TinyRSA, decrypt_pair, encrypt_pair
from demo.gui.widgets import common
from demo.gui.widgets.common import button, glass, hbox, mono_font
from demo.gui.widgets.result_badge import ResultBadge
from demo.gui.widgets.step_view import StepView

# Ví dụ trên lớp (slide 43–44): p = 17, q = 11, e = 7, x = 88. Khoá Thủy chọn n_B = 299 > n_A = 187.
CLASS_EXAMPLE = {"p": 17, "q": 11, "e": 7, "x": 88, "p_b": 23, "q_b": 13, "e_b": 5}

# (khoá, tên tab, mô tả, chữ khi chưa có dữ liệu) — thứ tự đúng luồng của slide: ký -> mã hoá -> giải mã -> kiểm tra
SECTIONS = (
    ("key_a", "Khoá A", "Euclid mở rộng: a = d = e^(-1) mod φ(n)",
     "Bấm Sinh khoá để xem bảng tìm a = e^(-1) mod φ(n)."),
    ("sign", "Ký", "Bình phương và nhân: y = h(x)^a mod n", "Bấm Ký để xem bảng tính y = h(x)^a mod n."),
    ("key_b", "Khoá B", "Euclid mở rộng: d_B = e_B^(-1) mod φ(n_B)",
     "Bấm Sinh khoá Thủy (hoặc Mã hoá z) để xem bảng tìm d_B."),
    ("enc", "Mã hoá", "Mã hoá từng khối: z = m^e_B mod n_B", "Bấm Mã hoá z để xem bảng z = e_B(x, y)."),
    ("dec", "Giải mã", "Giải mã từng khối: m = z^d_B mod n_B",
     "Bấm Giải mã z rồi kiểm tra để xem bảng (x, y) = d_B(z)."),
    ("verify", "Kiểm tra", "Bình phương và nhân: y^b mod n, so sánh với h(x)",
     "Bấm Kiểm tra để xem bảng tính y^b mod n."),
)
ENCRYPT_SECTIONS = ("key_b", "enc", "dec")


class IntField(QLineEdit):

    def __init__(self, value: int, lo: int, hi: int) -> None:
        super().__init__(str(value))
        self.setValidator(QIntValidator(lo, hi, self))
        self.setFixedWidth(90)

    def value(self) -> int:
        return int(self.text()) if self.text().strip() else 0

    def setValue(self, v: int) -> None:
        self.setText(str(v))


def spin(value: int, lo: int = 0, hi: int = 1_000_000) -> IntField:
    return IntField(value, lo, hi)


def table_widget(headers=()) -> QTableWidget:
    t = glass(QTableWidget(0, len(headers)))
    t.setStyleSheet("""
        QTableWidget { background-color: #FFFFFF; }
        QTableWidget > QWidget#qt_scrollarea_viewport { background-color: #FFFFFF; }
    """)
    t.setHorizontalHeaderLabels(list(headers))
    t.verticalHeader().setVisible(False)
    t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    t.setShowGrid(False)
    t.setFont(mono_font())
    t.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
    t.verticalHeader().setDefaultSectionSize(t.fontMetrics().height() + 6)
    return t


def panel(name: str, radius: int) -> QFrame:
    frame = QFrame()
    frame.setObjectName(name)
    frame.setStyleSheet(f"""
        QFrame#{name} {{
            background-color: #FFFAFC;
            border: 1px solid #F4A8D0;
            border-radius: {radius}px;
        }}
    """)
    return frame


def _blocks(values) -> str:
    return "(" + ", ".join(map(str, values)) + ")"


class TinyTab(QWidget):
    def __init__(self, app) -> None:
        super().__init__()
        self.app = app
        self._key: TinyRSA | None = None            # khoá chữ ký của Trang (a, b)
        self._key_b: TinyRSA | None = None          # khoá mã hoá của Thủy (e_B, d_B)
        self._z: list[int] | None = None
        self._z_bytes = False
        lay = QVBoxLayout(self)
        lay.setContentsMargins(8, 6, 8, 8)
        lay.setSpacing(6)

        ex = CLASS_EXAMPLE
        self.p, self.q, self.e = spin(ex["p"], 2), spin(ex["q"], 2), spin(ex["e"], 2)
        self.p_b, self.q_b, self.e_b = spin(ex["p_b"], 2), spin(ex["q_b"], 2), spin(ex["e_b"], 2)
        self.x_num = spin(ex["x"])
        self.y = spin(0)
        for field in (self.p, self.q, self.e, self.p_b, self.q_b, self.e_b, self.x_num, self.y):
            field.setFixedWidth(68)
        self.message = QLineEdit("Thu Trang")
        self.use_msg = QRadioButton("Có băm: x =")
        self.use_raw = QRadioButton("Không băm (VD): x =")
        self.use_raw.setChecked(True)
        grp = QButtonGroup(self)
        grp.addButton(self.use_msg)
        grp.addButton(self.use_raw)
        key_box = QGroupBox("Khoá chữ ký của Trang")
        key_box.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Maximum)
        key_layout = QVBoxLayout(key_box)
        key_layout.setSpacing(4)
        key_layout.addLayout(hbox(QLabel("p ="), self.p, QLabel("q ="), self.q, QLabel("e ="), self.e,
                                  button("Sinh khoá", self.generate_key), None))
        self.key_info = QLabel("Nhập p, q, e rồi bấm Sinh khoá.")
        self.key_info.setWordWrap(True)
        key_layout.addWidget(self.key_info)

        action_box = QGroupBox("Ký và kiểm tra chữ ký")
        action_box.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Maximum)
        action_layout = QVBoxLayout(action_box)
        action_layout.setSpacing(4)
        action_layout.addLayout(hbox(self.use_msg, self.message, self.use_raw, self.x_num))
        self.encrypt_flow = QCheckBox("Ký rồi mã hoá")
        self.encrypt_flow.toggled.connect(self._sync_flow)
        action_layout.addLayout(hbox(button("Ký", self.sign), QLabel("Chữ ký y ="), self.y,
                                     button("Kiểm tra", self.verify), None, self.encrypt_flow,
                                     button("Nạp ví dụ", self.load_class_example)))
        controls = hbox(key_box, action_box, spacing=8)
        controls.setStretch(0, 2)
        controls.setStretch(1, 3)

        self.enc_box = QGroupBox("Mã hoá cho Thủy: Trang dùng khoá công khai e_B, Thủy giải mã bằng d_B")
        self.enc_box.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Maximum)
        enc_layout = QVBoxLayout(self.enc_box)
        enc_layout.setSpacing(4)
        enc_layout.addLayout(hbox(QLabel("p_B ="), self.p_b, QLabel("q_B ="), self.q_b, QLabel("e_B ="), self.e_b,
                                  button("Sinh khoá Thủy", self.generate_key_b), None,
                                  button("Mã hoá z", self.encrypt), button("Phương sửa z", self.tamper_z),
                                  button("Giải mã z rồi kiểm tra", self.decrypt_verify)))
        self.key_b_info = QLabel("Khoá Thủy: chưa sinh. Cần n_B > n_A để mã hoá được chữ ký y.")
        self.key_b_info.setWordWrap(True)
        enc_layout.addWidget(self.key_b_info)

        controls_panel = panel("TinyControlsPanel", 12)
        controls_panel.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Maximum)
        panel_layout = QVBoxLayout(controls_panel)
        panel_layout.setContentsMargins(6, 4, 6, 6)
        panel_layout.addLayout(controls)
        panel_layout.addWidget(self.enc_box)
        lay.addWidget(controls_panel)

        self.badge = ResultBadge()
        self.badge.layout().setDirection(QBoxLayout.Direction.LeftToRight)
        self.badge.layout().setContentsMargins(8, 2, 8, 2)
        self.badge.layout().setSpacing(12)
        self.badge.title.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        self.badge.reason.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        self.badge.layout().setStretch(1, 1)
        status_panel = panel("TinyStatusPanel", 10)
        status_layout = QVBoxLayout(status_panel)
        status_layout.setContentsMargins(4, 3, 4, 3)
        status_layout.addWidget(self.badge)
        lay.addWidget(status_panel)

        split = QSplitter(Qt.Orientation.Horizontal)
        self.steps = StepView()
        left = QGroupBox("Từng bước tính toán")
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(6, 6, 6, 6)
        left_layout.setSpacing(4)
        left_layout.addLayout(hbox(None, button("Xoá", self.clear)))
        left_layout.addWidget(self.steps, 1)
        split.addWidget(left)
        right = QGroupBox("Bảng tính chi tiết")
        right.setObjectName("TinyTablesPanel")
        rl = QVBoxLayout(right)
        rl.setContentsMargins(6, 6, 6, 6)
        self.table_tabs = QTabWidget()
        self.table_tabs.setDocumentMode(True)
        # Mỗi tab một bảng; trong mỗi tab: đầu vào -> bảng tính -> kết quả.
        self.sections: dict[str, tuple[QWidget, QLabel, QTableWidget, QLabel]] = {}
        for key, title, description, _ in SECTIONS:
            page = QWidget()
            page_layout = QVBoxLayout(page)
            page_layout.setContentsMargins(0, 4, 0, 0)
            page_layout.setSpacing(4)
            heading = QLabel(description)
            heading.setStyleSheet("font-weight: 700;")
            info, result, tbl = QLabel(), QLabel(), table_widget()
            info.setWordWrap(True)
            result.setWordWrap(True)
            result.setStyleSheet("font-weight: 700;")
            page_layout.addWidget(heading)
            page_layout.addWidget(info)
            page_layout.addWidget(tbl, 1)
            page_layout.addWidget(result)
            index = self.table_tabs.addTab(page, title)
            self.table_tabs.setTabToolTip(index, description)
            self.sections[key] = (page, info, tbl, result)
        self.euclid, self.sm_sign, self.sm_verify = (self.sections[k][2] for k in ("key_a", "sign", "verify"))
        self._reset(*self.sections)
        rl.addWidget(self.table_tabs)
        split.addWidget(right)
        split.setChildrenCollapsible(False)
        split.setStretchFactor(0, 1)
        split.setStretchFactor(1, 1)
        split.setSizes([480, 600])
        lay.addWidget(split, 1)
        for field in (self.p, self.q, self.e):
            field.textChanged.connect(self._invalidate_key)
        for field in (self.p_b, self.q_b, self.e_b):
            field.textChanged.connect(self._invalidate_key_b)
        self._sync_flow()

    # ---- trạng thái ---------------------------------------------------------------------------------------
    def _sync_flow(self) -> None:
        on = self.encrypt_flow.isChecked()
        self.enc_box.setVisible(on)
        for key in ENCRYPT_SECTIONS:
            self.table_tabs.setTabVisible(self.table_tabs.indexOf(self.sections[key][0]), on)

    def _invalidate_key(self) -> None:
        self._key = None
        self._z = None
        self.y.setValue(0)
        self.key_info.setText("Tham số đã thay đổi — bấm Sinh khoá để cập nhật.")
        self.clear()

    def _invalidate_key_b(self) -> None:
        self._key_b = None
        self._z = None
        self.key_b_info.setText("Tham số của Thủy đã thay đổi — bấm Sinh khoá Thủy để cập nhật.")
        self._reset("key_b", "enc", "dec")

    def load_class_example(self) -> None:
        ex = CLASS_EXAMPLE
        for field, key in ((self.p, "p"), (self.q, "q"), (self.e, "e"), (self.x_num, "x"),
                           (self.p_b, "p_b"), (self.q_b, "q_b"), (self.e_b, "e_b")):
            field.setValue(ex[key])
        self.use_raw.setChecked(True)
        self.generate_key()
        self.badge.set_info("Đã nạp ví dụ lớp", f"p = {ex['p']}, q = {ex['q']}, e = {ex['e']}, x = {ex['x']} "
                                                f"— bấm Ký")

    def _reset(self, *keys: str) -> None:
        placeholders = {key: text for key, _, _, text in SECTIONS}
        for key in keys:
            _, info, tbl, result = self.sections[key]
            info.setText(placeholders[key])
            result.clear()
            tbl.setRowCount(0)

    def _select(self, key: str) -> None:
        self.table_tabs.setCurrentWidget(self.sections[key][0])

    # ---- khoá ---------------------------------------------------------------------------------------------
    def _check_primes(self, fields, suffix: str = "") -> bool:
        problems = []
        p_box, q_box = fields
        for name, box in ((f"p{suffix}", p_box), (f"q{suffix}", q_box)):
            v = box.value()
            if not is_probable_prime(v):
                nxt = v + 1
                while not is_probable_prime(nxt):
                    nxt += 1
                problems.append(f"{name} = {v} không phải số nguyên tố (gợi ý: {nxt})")
        if not problems and p_box.value() == q_box.value():
            problems.append(f"p{suffix} và q{suffix} phải khác nhau (đang cùng bằng {p_box.value()})")
        if problems:
            msg = "\n".join(problems)
            self.badge.set_result(False, msg, bad_text="THAM SỐ KHÔNG HỢP LỆ")
            common.show_warning(self, "Tham số không hợp lệ", msg)
            return False
        return True

    def _tiny(self, p: IntField, q: IntField, e: IntField, suffix: str = "") -> TinyRSA | None:
        if not self._check_primes((p, q), suffix):
            return None
        try:
            return TinyRSA(p.value(), q.value(), e.value())
        except ValueError as err:
            self.badge.set_result(False, str(err), bad_text="THAM SỐ KHÔNG HỢP LỆ")
            common.show_warning(self, "Tham số không hợp lệ", str(err))
            return None

    def _show_keygen(self, tiny: TinyRSA, log: StepLogger, key: str, owner: str) -> None:
        self._show(log)
        self._fill(self.sections[key][2], next((s for s in log.tables() if s.title.startswith("Euclid")), None))
        _, info, _, result = self.sections[key]
        if key == "key_a":
            info.setText(f"Đầu vào: dòng 0 có r0 = φ(n) = {tiny.phi}, r1 = b = e = {tiny.e}, t0 = 0, t1 = 1. "
                         f"Lặp đến khi r2 = 0.")
            result.setText(f"Kết quả: r1 = 1 nên a = d = t1 = {tiny.a} "
                           f"(kiểm tra: {tiny.e}*{tiny.a} mod {tiny.phi} = {(tiny.e * tiny.a) % tiny.phi})")
        else:
            info.setText(f"Đầu vào: dòng 0 có r0 = φ(n_B) = {tiny.phi}, r1 = e_B = {tiny.e}, t0 = 0, t1 = 1. "
                         f"Lặp đến khi r2 = 0.")
            result.setText(f"Kết quả: r1 = 1 nên d_B = t1 = {tiny.d} "
                           f"(kiểm tra: {tiny.e}*{tiny.d} mod {tiny.phi} = {(tiny.e * tiny.d) % tiny.phi})")
        self._select(key)
        self.badge.set_info(f"Đã sinh khoá của {owner}", "Xem bảng Euclid mở rộng bên phải.")

    def generate_key(self) -> None:
        tiny = self._tiny(self.p, self.q, self.e)
        if tiny is None:
            return
        self._key = tiny
        self._z = None
        self.y.setValue(0)
        self.key_info.setText(f"n = {tiny.n}, φ(n) = {tiny.phi} | KU (e, n) = ({tiny.e}, {tiny.n}) | "
                              f"KR (d, p, q) = ({tiny.d}, {tiny.p}, {tiny.q})")
        log = StepLogger()
        tiny.keygen_steps(log, "TRANG")
        self._reset(*self.sections)
        self._show_keygen(tiny, log, "key_a", "Trang")

    def generate_key_b(self) -> None:
        tiny = self._tiny(self.p_b, self.q_b, self.e_b, "_B")
        if tiny is None:
            return
        self._key_b = tiny
        self._z = None
        note = ""
        if self._key is not None and tiny.n <= self._key.n:
            note = f" | Lưu ý: n_B = {tiny.n} ≤ n_A = {self._key.n}, chữ ký y có thể không mã hoá được."
        self.key_b_info.setText(f"n_B = {tiny.n}, φ(n_B) = {tiny.phi} | KU (e_B, n_B) = ({tiny.e}, {tiny.n}) | "
                                f"KR (d_B, p_B, q_B) = ({tiny.d}, {tiny.p}, {tiny.q}){note}")
        log = StepLogger()
        tiny.keygen_steps(log, "THỦY")
        self._reset("key_b", "enc", "dec")
        self._show_keygen(tiny, log, "key_b", "Thủy")

    def _current_key(self) -> TinyRSA | None:
        # Ký trực tiếp vẫn được: tự sinh khoá nếu chưa bấm Sinh khoá.
        if self._key is None:
            y = self.y.value()
            self.generate_key()
            self.y.setValue(y)
        return self._key

    def _current_key_b(self) -> TinyRSA | None:
        if self._key_b is None:
            self.generate_key_b()
        return self._key_b

    # ---- hiển thị -----------------------------------------------------------------------------------------
    def _input(self) -> bytes | int:
        # x nhập tay phải nằm trong [0, n): TinyRSA.hash_value báo lỗi thay vì tự lấy mod n
        if self.use_msg.isChecked():
            return self.message.text().encode("utf-8")
        return self.x_num.value()

    @staticmethod
    def _h_source(tiny: TinyRSA, h: int, hashed: bool) -> str:
        if hashed:
            return f"h(x) = SHA-256(x) mod {tiny.n} = {h}"
        return f"không băm: h(x) = x = {h}"

    @staticmethod
    def _x_text(message: bytes | int) -> str:
        return f'"{message.decode("utf-8", "replace")}"' if isinstance(message, bytes) else str(message)

    @staticmethod
    def _fill(table: QTableWidget, step) -> None:
        table.setRowCount(0)
        if step is None:
            return
        headers, rows = step.table
        table.setColumnCount(len(headers))
        table.setHorizontalHeaderLabels(list(headers))
        for r, row in enumerate(rows):
            table.insertRow(r)
            for c, v in enumerate(row):
                item = QTableWidgetItem("" if v is None else str(v))
                item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                table.setItem(r, c, item)

    def _show(self, log: StepLogger) -> None:
        # Bảng đã có vùng riêng; tránh lặp bảng dạng chữ làm phần giải thích quá dài.
        display_steps = [replace(s, table=None, value_str=(s.value_str + "\n" if s.value_str else "")
                                 + "Xem bảng tính chi tiết bên phải.") if s.table else s for s in log.steps]
        self.steps.set_steps(display_steps, reveal_all=True)
        QTimer.singleShot(0, lambda: self.steps.verticalScrollBar().setValue(0))

    @staticmethod
    def _table(log: StepLogger, prefix: str, last: bool = False):
        found = [s for s in log.tables() if s.title.startswith(prefix)]
        return (found[-1] if last else found[0]) if found else None

    def _show_verify(self, tiny: TinyRSA, message: bytes | int, y: int, ok: bool, log: StepLogger,
                     source: str) -> str:
        self._fill(self.sm_verify, self._table(log, "Bình phương", last=True))
        _, info, _, result = self.sections["verify"]
        h = tiny.hash_value(message)
        info.setText(f"Đầu vào: x = {self._x_text(message)} ({source}); {self._h_source(tiny, h, isinstance(message, bytes))}; "
                     f"y = {y}; b = {tiny.b} = {tiny.b:b} (nhị phân).")
        if 0 <= y < tiny.n:
            reason = f"{y}^{tiny.b} mod {tiny.n} = {mod_pow(y, tiny.b, tiny.n)} {'=' if ok else '≠'} h(x) = {h}"
        else:
            reason = f"y = {y} nằm ngoài [0, n = {tiny.n}) nên bị loại, không tính y^b mod n"
        result.setText(f"Kết luận: {reason} => chữ ký {'HỢP LỆ' if ok else 'KHÔNG HỢP LỆ'}")
        self._select("verify")
        return reason

    # ---- thao tác -----------------------------------------------------------------------------------------
    def sign(self) -> None:
        tiny = self._current_key()
        if tiny is None:
            return
        log = StepLogger()
        message = self._input()
        try:
            y = tiny.sign(message, log, with_keygen=False)
        except ValueError as err:
            self.badge.set_result(False, str(err), bad_text="LỖI")
            return
        self.y.setValue(y)
        self._z = None
        self._reset("sign", "enc", "dec", "verify")
        self._show(log)
        self._fill(self.sm_sign, self._table(log, "Bình phương"))
        h = tiny.hash_value(message)
        _, info, _, result = self.sections["sign"]
        info.setText(f"Đầu vào: x = {self._x_text(message)}; {self._h_source(tiny, h, isinstance(message, bytes))}; "
                     f"a = {tiny.a} = {tiny.a:b} (nhị phân). "
                     f"Đọc b_i từ trái sang phải: luôn bình phương f, b_i = 1 thì nhân thêm h(x).")
        result.setText(f"Kết quả: y = {h}^{tiny.a} mod {tiny.n} = {y}")
        self._select("sign")
        nxt = "bấm Mã hoá z" if self.encrypt_flow.isChecked() else "bấm Kiểm tra"
        self.badge.set_info(f"Đã ký: y = {y}", f"n = {tiny.n}, φ(n) = {tiny.phi}, a = {tiny.a} — {nxt}")

    def verify(self) -> None:
        tiny = self._current_key()
        if tiny is None:
            return
        log = StepLogger()
        message, y = self._input(), self.y.value()
        try:
            ok = tiny.verify(message, y, log)
        except ValueError as err:
            self.badge.set_result(False, str(err), bad_text="LỖI")
            return
        self._show(log)
        source = "băm lại từ thông điệp hiện tại" if isinstance(message, bytes) else "nhập trực tiếp"
        self.badge.set_result(ok, self._show_verify(tiny, message, y, ok, log, source))

    def encrypt(self) -> None:
        tiny = self._current_key()
        if tiny is None:
            return
        receiver = self._current_key_b()
        if receiver is None:
            return
        message, y = self._input(), self.y.value()
        log = StepLogger()
        try:
            z = encrypt_pair(receiver, message, y, log)
        except ValueError as err:
            self.badge.set_result(False, str(err), bad_text="KHÔNG MÃ HOÁ ĐƯỢC")
            common.show_warning(self, "Không mã hoá được", str(err))
            return
        self._z, self._z_bytes = z, isinstance(message, bytes)
        self._reset("enc", "dec", "verify")
        self._show(log)
        self._fill(self.sections["enc"][2], self._table(log, "Mã hoá"))
        _, info, _, result = self.sections["enc"]
        info.setText(f"Đầu vào: x = {self._x_text(message)}, y = {y}; khoá công khai của Thủy (e_B, n_B) = "
                     f"({receiver.e}, {receiver.n}). Mỗi khối phải nhỏ hơn n_B.")
        result.setText(f"Kết quả: z = e_B(x, y) = {_blocks(z)}")
        self._select("enc")
        self.badge.set_info("Đã mã hoá z", "Gửi z cho Thủy — bấm Giải mã z rồi kiểm tra")

    def tamper_z(self) -> None:
        if self._z is None or self._key_b is None:
            common.show_info(self, "Chưa có z", "Bấm Mã hoá z trước.")
            return
        old = self._z[0]
        self._z[0] = (old + 1) % self._key_b.n
        self.sections["enc"][3].setText(f"z bị Phương sửa thành {_blocks(self._z)} (khối đầu {old} → {self._z[0]})")
        self.badge.set_info("Phương đã sửa z", f"Khối đầu của z: {old} → {self._z[0]} — bấm Giải mã z rồi kiểm tra")

    def decrypt_verify(self) -> None:
        if self._z is None or self._key_b is None:
            common.show_info(self, "Chưa có z", "Bấm Mã hoá z trước.")
            return
        tiny = self._current_key()
        if tiny is None:
            return
        receiver, z = self._key_b, list(self._z)
        log = StepLogger()
        self._reset("dec", "verify")
        try:
            message, y = decrypt_pair(receiver, z, self._z_bytes, log)
        except ValueError as err:
            self._show(log)
            self._fill(self.sections["dec"][2], self._table(log, "Giải mã"))
            self._select("dec")
            self.badge.set_result(False, str(err), bad_text="GIẢI MÃ THẤT BẠI")
            return
        _, info, _, result = self.sections["dec"]
        info.setText(f"Đầu vào: z = {_blocks(z)}; khoá bí mật của Thủy d_B = {receiver.d}, n_B = {receiver.n}.")
        result.setText(f"Kết quả: x = {self._x_text(message)}, y = {y}")
        try:
            ok = tiny.verify(message, y, log)
        except ValueError as err:
            self._show(log)
            self._fill(self.sections["dec"][2], self._table(log, "Giải mã"))
            self._select("dec")
            self.badge.set_result(False, f"Giải mã ra x không hợp lệ: {err}")
            return
        self._show(log)
        self._fill(self.sections["dec"][2], self._table(log, "Giải mã"))
        self.badge.set_result(ok, self._show_verify(tiny, message, y, ok, log, "giải mã từ z"))

    def clear(self) -> None:
        self.steps.clear()
        self.badge.clear()
        self._reset(*self.sections)
