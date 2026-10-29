"""Tab 6 — Kiểm thử: chạy bảng đối chiếu từ test/report.py (không gọi pytest), xuất Markdown cho báo cáo."""
from __future__ import annotations

from PySide6.QtGui import QColor
from PySide6.QtWidgets import (QAbstractItemView, QCheckBox, QHeaderView, QLabel, QTableWidget, QTableWidgetItem,
                               QVBoxLayout, QWidget)

from demo import REPORT_DIR
from demo.gui.widgets import common
from demo.gui.widgets.common import GREEN, RED, button, glass, hbox, mono_font

HEADERS = ("Nhóm", "Ca kiểm thử", "Ours", "Reference", "Nguồn", "Khớp")


class TestTab(QWidget):
    def __init__(self, app) -> None:
        super().__init__()
        self.app = app
        self.rows = []
        lay = QVBoxLayout(self)
        self.slow = QCheckBox("Gồm ca chậm (SHA-256 của 1 000 000 ký tự 'a')")
        self.summary = QLabel("Bấm 'Chạy kiểm thử đối chiếu'. Lệnh tương đương cho giảng viên: pytest test/required -v")
        lay.addLayout(hbox(button("Chạy kiểm thử đối chiếu", self.start), self.slow, None,
                           button("Xuất Markdown", self.export)))
        lay.addWidget(self.summary)
        self.table = glass(QTableWidget(0, len(HEADERS)))
        self.table.setHorizontalHeaderLabels(HEADERS)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        header = self.table.horizontalHeader()
        for c, mode in enumerate((QHeaderView.ResizeMode.ResizeToContents, QHeaderView.ResizeMode.Stretch,
                                  QHeaderView.ResizeMode.ResizeToContents, QHeaderView.ResizeMode.ResizeToContents,
                                  QHeaderView.ResizeMode.ResizeToContents, QHeaderView.ResizeMode.ResizeToContents)):
            header.setSectionResizeMode(c, mode)
        lay.addWidget(self.table, 1)

    def start(self) -> None:
        include_slow = self.slow.isChecked()

        def job():
            from test.report import build_report
            return build_report(include_slow=include_slow)

        self.app.run(job, self._show, status="Đang chạy kiểm thử đối chiếu…", owner=self)

    def _show(self, rows) -> None:
        self.rows = rows
        self.table.setRowCount(0)
        for r in rows:
            i = self.table.rowCount()
            self.table.insertRow(i)
            for c, v in enumerate((r.group, r.case, r.ours, r.reference, r.source, "✅" if r.match else "❌")):
                item = QTableWidgetItem(v)
                if c in (2, 3):
                    item.setFont(mono_font())
                    item.setToolTip(v)
                if c == 5:
                    item.setBackground(QColor(GREEN if r.match else RED).lighter(185))
                self.table.setItem(i, c, item)
        good = sum(r.match for r in rows)
        self.summary.setText(f"{good}/{len(rows)} ca khớp")
        self.summary.setStyleSheet(f"color: {GREEN if good == len(rows) else RED}; font-weight: 700; font-size: 15px;")

    def export(self) -> None:
        if not self.rows:
            common.show_info(self, "Chưa có kết quả", "Bấm 'Chạy kiểm thử đối chiếu' trước.")
            return
        from test.report import write_markdown
        path = write_markdown(self.rows, REPORT_DIR / "test_results.md")
        common.show_info(self, "Đã xuất", f"Đã ghi {path}")
