"""Tab 1 — Tiny RSA: ký / kiểm tra từng bước với số nhỏ (mặc định ví dụ slide p = 17, q = 11, e = 7, h = 88)."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QIntValidator
from PySide6.QtWidgets import (QAbstractItemView, QButtonGroup, QGroupBox, QHeaderView, QLabel, QLineEdit,
                               QRadioButton, QSplitter, QTableWidget, QTableWidgetItem, QVBoxLayout,
                               QWidget)

from core.primality import is_probable_prime
from core.step_logger import StepLogger
from core.tiny_rsa import TinyRSA
from demo.gui.widgets import common
from demo.gui.widgets.common import button, glass, hbox, mono_font
from demo.gui.widgets.result_badge import ResultBadge
from demo.gui.widgets.step_view import StepView


class IntField(QLineEdit):
    """Ô nhập số nguyên không có nút tăng/giảm (QSpinBox bỏ nút thì Fusion + QSS co ô chữ về 1 px)."""

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
    t.setHorizontalHeaderLabels(list(headers))
    t.verticalHeader().setVisible(False)
    t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    t.setShowGrid(False)
    t.setFont(mono_font())
    t.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
    t.verticalHeader().setDefaultSectionSize(t.fontMetrics().height() + 6)
    return t


class TinyTab(QWidget):
    def __init__(self, app) -> None:
        super().__init__()
        self.app = app
        self.signature: int | None = None
        lay = QVBoxLayout(self)

        self.p, self.q, self.e = spin(17, 2), spin(11, 2), spin(7, 2)
        self.h = spin(88)
        self.s = spin(11)
        self.message = QLineEdit("Xin chào RSA")
        self.use_h = QRadioButton("Giá trị băm h =")
        self.use_msg = QRadioButton("Thông điệp M =")
        self.use_h.setChecked(True)
        grp = QButtonGroup(self)
        grp.addButton(self.use_h)
        grp.addButton(self.use_msg)
        lay.addLayout(hbox(QLabel("p ="), self.p, QLabel("q ="), self.q, QLabel("e ="), self.e, None,
                           self.use_h, self.h, self.use_msg, self.message))
        self.next_btn = button("Từng bước ▶", self.next_step)
        lay.addLayout(hbox(button("Ký", self.sign), QLabel("Chữ ký s ="), self.s, button("Kiểm tra", self.verify),
                           None, self.next_btn, button("Hiện tất cả", self.show_all),
                           button("Ví dụ slide", self.slide_example), button("Xoá", self.clear)))
        self.badge = ResultBadge()
        lay.addWidget(self.badge)

        split = QSplitter(Qt.Orientation.Horizontal)
        self.steps = StepView()
        left = QGroupBox("Từng bước tính toán")
        QVBoxLayout(left).addWidget(self.steps)
        split.addWidget(left)
        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0)
        self.euclid = table_widget()
        self.sm_sign = table_widget(("i", "b_i", "c", "f"))
        self.sm_verify = table_widget(("i", "b_i", "c", "f"))
        for title, tbl in (("Euclid mở rộng tìm d", self.euclid), ("Bình phương và nhân: s = h^d mod n", self.sm_sign),
                           ("Bình phương và nhân: s^e mod n", self.sm_verify)):
            box = QGroupBox(title)
            QVBoxLayout(box).addWidget(tbl)
            box.layout().setContentsMargins(6, 6, 6, 6)
            rl.addWidget(box, 1)
        split.addWidget(right)
        split.setSizes([560, 540])
        lay.addWidget(split, 1)

    def _check_primes(self) -> bool:
        """Báo rõ p, q nào không phải số nguyên tố (kèm số nguyên tố gần nhất để gợi ý)."""
        problems = []
        for name, box in (("p", self.p), ("q", self.q)):
            v = box.value()
            if not is_probable_prime(v):
                nxt = v + 1
                while not is_probable_prime(nxt):
                    nxt += 1
                problems.append(f"{name} = {v} không phải số nguyên tố (gợi ý: {nxt})")
        if not problems and self.p.value() == self.q.value():
            problems.append(f"p và q phải khác nhau (đang cùng bằng {self.p.value()})")
        if problems:
            msg = "\n".join(problems)
            self.badge.set_result(False, msg, bad_text="❌ THAM SỐ KHÔNG HỢP LỆ")
            common.show_warning(self, "Tham số không hợp lệ", msg)
            return False
        return True

    def _tiny(self) -> TinyRSA | None:
        if not self._check_primes():
            return None
        try:
            return TinyRSA(self.p.value(), self.q.value(), self.e.value())
        except ValueError as err:
            self.badge.set_result(False, str(err), bad_text="❌ THAM SỐ KHÔNG HỢP LỆ")
            common.show_warning(self, "Tham số không hợp lệ", str(err))
            return None

    def _input(self, tiny: TinyRSA) -> bytes | int:
        if self.use_msg.isChecked():
            return self.message.text().encode("utf-8")
        return self.h.value() % tiny.n

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

    def _show(self, log: StepLogger, reveal_all: bool, signing: bool) -> None:
        """Hiện các bước; bảng Euclid và bảng bình phương và nhân lấy từ các Step có bảng."""
        self.steps.set_steps(log.steps, reveal_all)
        self.next_btn.setEnabled(not reveal_all)
        euclid = next((s for s in log.tables() if s.title.startswith("Euclid")), None)
        powers = [s for s in log.tables() if s.title.startswith("Bình phương")]
        if signing:
            self._fill(self.euclid, euclid)
            self._fill(self.sm_sign, powers[0] if powers else None)
            self._fill(self.sm_verify, None)
        else:
            self._fill(self.sm_verify, powers[-1] if powers else None)

    def sign(self, reveal_all: bool = True) -> None:
        tiny = self._tiny()
        if tiny is None:
            return
        log = StepLogger()
        try:
            s = tiny.sign(self._input(tiny), log)
        except ValueError as err:
            self.badge.set_result(False, str(err), bad_text="❌ LỖI")
            return
        self.signature = s
        self.s.setValue(s)
        self.badge.set_info(f"Đã ký: s = {s}", f"n = {tiny.n}, φ(n) = {tiny.phi}, d = {tiny.d} — bấm Kiểm tra")
        self._show(log, reveal_all, signing=True)

    def verify(self) -> None:
        tiny = self._tiny()
        if tiny is None:
            return
        log = StepLogger()
        ok = tiny.verify(self._input(tiny), self.s.value(), log)
        h = tiny.hash_value(self._input(tiny))
        self.badge.set_result(ok, f"s^e mod n = {self.s.value()}^{tiny.e} mod {tiny.n} "
                                  f"{'=' if ok else '≠'} h = {h}")
        self._show(log, True, signing=False)

    def slide_example(self) -> None:
        """Ví dụ trình chiếu: p=17, q=11, e=7, h=88; hiện từng bước bằng nút Từng bước."""
        self.p.setValue(17)
        self.q.setValue(11)
        self.e.setValue(7)
        self.h.setValue(88)
        self.use_h.setChecked(True)
        self.sign(reveal_all=False)

    def next_step(self) -> None:
        if not self.steps.next_step() or not self.steps.has_next():
            self.next_btn.setEnabled(False)

    def show_all(self) -> None:
        self.steps.show_all()
        self.next_btn.setEnabled(False)

    def clear(self) -> None:
        self.steps.clear()
        self.badge.clear()
        for t in (self.euclid, self.sm_sign, self.sm_verify):
            t.setRowCount(0)
