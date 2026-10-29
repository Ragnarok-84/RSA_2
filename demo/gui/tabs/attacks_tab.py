from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QCheckBox, QComboBox, QGroupBox, QLabel, QListWidget, QListWidgetItem, QSplitter,
                               QVBoxLayout, QWidget)

import attacks
import scenarios
from core.step_logger import StepLogger
from demo.gui.widgets.common import button, glass, hbox
from demo.gui.widgets.result_badge import ResultBadge
from demo.gui.widgets.step_view import StepView

# Nhóm theo tính chất cần phân tích: mỗi nhóm có kịch bản dùng đúng và tấn công khi bỏ một thành phần
GROUPS = (
    ("CHỨNG THỰC - đúng người ký", ("s1_authentication",), ("a6_key_substitution_mitm", "a2_existential_forgery")),
    ("TOÀN VẸN - nội dung không bị sửa", ("s2_integrity_tamper",), ("a1_no_hash_forgery", "a3_hash_collision")),
    ("KHÔNG CHỐI BỎ - người ký không chối được",
     ("s3_non_repudiation_contract", "s4_key_compromise", "s5_hmac_vs_signature"), ()),
    ("BÍ MẬT - ký rồi mã hoá", ("s6_sign_then_encrypt",), ("a8_surreptitious_forwarding", "a7_replay_attack")),
    ("BẢN THÂN RSA - tham số yếu", (), ("a4_small_e_attack", "a5_factorization")),
)


class AttacksTab(QWidget):
    def __init__(self, app) -> None:
        super().__init__()
        self.app = app
        lay = QVBoxLayout(self)
        split = QSplitter(Qt.Orientation.Horizontal)

        left = QGroupBox("Danh sách")
        ll = QVBoxLayout(left)
        self.list = glass(QListWidget())
        scenario_titles, attack_titles = dict(scenarios.REGISTRY), dict(attacks.REGISTRY)
        for header, scenario_mods, attack_mods in GROUPS:
            self._add_header(header)
            for mod in scenario_mods:
                self._add_item(f"  Đúng: {scenario_titles[mod]}", ("scenario", mod), "Kịch bản: kỳ vọng HỢP LỆ")
            for mod in attack_mods:
                self._add_item(f"  Tấn công: {attack_titles[mod]}", ("attack", mod), attacks.load(mod).__doc__ or "")
        self.list.itemDoubleClicked.connect(lambda _i: self.run_selected())
        self.list.currentItemChanged.connect(lambda *_: self._sync())
        ll.addWidget(self.list, 1)
        self.defended = QCheckBox("Bật biện pháp phòng chống")
        self.bits = QComboBox()
        self.bits.addItems(("1024", "2048"))
        ll.addWidget(self.defended)
        ll.addLayout(hbox(QLabel("Khoá cho kịch bản:"), self.bits, None))
        ll.addLayout(hbox(button("Chạy", self.run_selected), button("Chạy tất cả tấn công", self.run_all_attacks), None))
        split.addWidget(left)

        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0)
        self.badge = ResultBadge()
        rl.addWidget(self.badge)
        self.steps = StepView()
        rl.addWidget(self.steps, 1)
        split.addWidget(right)
        split.setSizes([480, 620])
        lay.addWidget(split, 1)
        self.list.setCurrentRow(1)

    def _add_header(self, text: str) -> None:
        item = QListWidgetItem(text)
        item.setFlags(Qt.ItemFlag.NoItemFlags)
        f = item.font()
        f.setBold(True)
        item.setFont(f)
        self.list.addItem(item)

    def _add_item(self, title: str, data: tuple[str, str], tip: str) -> None:
        item = QListWidgetItem(title)
        item.setData(Qt.ItemDataRole.UserRole, data)
        item.setToolTip(tip.strip())
        self.list.addItem(item)

    def _sync(self) -> None:
        item = self.list.currentItem()
        data = item.data(Qt.ItemDataRole.UserRole) if item else None
        self.defended.setEnabled(bool(data) and data[0] == "attack")

    def select(self, module: str) -> None:
        for i in range(self.list.count()):
            d = self.list.item(i).data(Qt.ItemDataRole.UserRole)
            if d and d[1] == module:
                self.list.setCurrentRow(i)
                return

    def run_selected(self) -> None:
        item = self.list.currentItem()
        data = item.data(Qt.ItemDataRole.UserRole) if item else None
        if not data:
            return
        kind, mod = data
        defended, bits = self.defended.isChecked(), int(self.bits.currentText())

        def job():
            log = StepLogger()
            if kind == "attack":
                return kind, attacks.load(mod).run(log, defended=defended), log
            return kind, scenarios.load(mod).run(log, bits=bits), log

        self.badge.set_info("Đang chạy…", item.text().strip())
        self.app.run(job, self._show, status=f"Đang chạy: {item.text().strip()}", owner=self)

    def _show(self, out) -> None:
        kind, result, log = out
        if kind == "attack":
            self.badge.set_result(not result.success, result.summary,
                                  ok_text="TẤN CÔNG THẤT BẠI", bad_text="TẤN CÔNG THÀNH CÔNG")
        else:
            self.badge.set_result(result.valid, result.summary)
        self.steps.set_steps(log.steps)

    def run_all_attacks(self) -> None:
        def job(report):
            log = StepLogger()
            log.head("TỔNG KẾT: MỖI TẤN CÔNG Ở CẤU HÌNH YẾU VÀ KHI BẬT PHÒNG CHỐNG")
            good = 0
            for mod, title in attacks.REGISTRY:
                report(f"Đang chạy {title}…")
                weak = attacks.load(mod).run(None, defended=False).success
                strong = attacks.load(mod).run(None, defended=True).success
                ok = weak and not strong
                good += ok
                log.log(title, None, f"Cấu hình yếu: {'THÀNH CÔNG' if weak else 'thất bại'}  |  "
                                     f"Bật phòng chống: {'thành công' if strong else 'THẤT BẠI'}",
                        level="ok" if ok else "bad")
            return good, log

        def done(out) -> None:
            good, log = out
            n = len(attacks.REGISTRY)
            self.badge.set_result(good == n, f"{good}/{n} tấn công đúng kỳ vọng (thành công khi yếu, thất bại khi phòng chống)",
                                  ok_text="ĐÚNG KỲ VỌNG", bad_text="CÓ TẤN CÔNG SAI KỲ VỌNG")
            self.steps.set_steps(log.steps)

        self.app.run(job, done, status="Đang chạy toàn bộ tấn công…", owner=self)
