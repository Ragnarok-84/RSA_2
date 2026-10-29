from __future__ import annotations

from PySide6.QtWidgets import (QAbstractItemView, QCheckBox, QHeaderView, QLabel, QSpinBox, QTableWidget,
                               QTableWidgetItem, QVBoxLayout, QWidget)

from demo.benchmark import DATA_SIZES, KEY_SIZES, KINDS, BenchRow, fmt_size, run_benchmark
from demo.gui.widgets import common
from demo.gui.widgets.common import button, glass, hbox


class BenchmarkTab(QWidget):
    def __init__(self, app) -> None:
        super().__init__()
        self.app = app
        self.rows: list[BenchRow] = []
        lay = QVBoxLayout(self)

        self.key_boxes = {b: QCheckBox(f"{b} bit") for b in KEY_SIZES}
        self.data_boxes = {s: QCheckBox(fmt_size(s)) for s in DATA_SIZES}
        for b in (512, 1024, 2048):
            self.key_boxes[b].setChecked(True)
        for s in DATA_SIZES[:4]:
            self.data_boxes[s].setChecked(True)
        self.repeats = QSpinBox()
        self.repeats.setRange(1, 20)
        self.repeats.setValue(3)
        self.repeats.setFixedWidth(70)
        lay.addLayout(hbox(QLabel("Khoá:"), *self.key_boxes.values(), None, QLabel("Dữ liệu băm:"),
                           *self.data_boxes.values()))
        lay.addLayout(hbox(QLabel("Số lần lặp (lấy trung vị):"), self.repeats, button("Chạy", self.start), None))

        self.table = glass(QTableWidget(0, 4))
        self.table.setHorizontalHeaderLabels(("Phép đo", "Tham số", "Trung vị", "Số lần lặp"))
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        lay.addWidget(QLabel("Kết quả đo"))
        lay.addWidget(self.table, 1)

    def start(self) -> None:
        keys = [b for b, c in self.key_boxes.items() if c.isChecked()]
        data = [s for s, c in self.data_boxes.items() if c.isChecked()]
        if not keys and not data:
            common.show_info(self, "Chưa chọn", "Chọn ít nhất một kích thước khoá hoặc dữ liệu.")
            return
        repeats = self.repeats.value()
        self.app.run(lambda report: run_benchmark(keys, data, repeats, progress=report), self._done,
                     status="Đang đo…", owner=self)

    def _done(self, rows: list[BenchRow]) -> None:
        self.rows = rows
        self.table.setRowCount(0)
        for r in rows:
            i = self.table.rowCount()
            self.table.insertRow(i)
            param = fmt_size(r.param) if r.kind == "hash" else f"{r.param} bit"
            for c, v in enumerate((KINDS[r.kind], param, f"{r.median_s * 1000:.2f} ms", str(r.repeats))):
                self.table.setItem(i, c, QTableWidgetItem(v))
