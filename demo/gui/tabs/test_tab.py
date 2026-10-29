from __future__ import annotations

from PySide6.QtWidgets import (QAbstractItemView, QCheckBox, QHeaderView, QLabel, QTableWidget, QTableWidgetItem,
                               QVBoxLayout, QWidget)

from demo.gui.widgets.common import button, glass, hbox, mono_font

HEADERS = ("Nhóm", "Ca kiểm thử", "Kết quả", "Đối chiếu", "Nguồn")


class TestTab(QWidget):
    def __init__(self, app) -> None:
        super().__init__()
        self.app = app
        self.rows = []
        lay = QVBoxLayout(self)
        self.slow = QCheckBox("Gồm ca chậm (SHA-256 của 1 000 000 ký tự 'a')")
        self.summary = QLabel("Bấm Chạy để xem kết quả các ca kiểm thử.")
        lay.addLayout(hbox(button("Chạy kiểm thử", self.start), self.slow, None))
        lay.addWidget(self.summary)
        self.table = glass(QTableWidget(0, len(HEADERS)))
        self.table.setHorizontalHeaderLabels(HEADERS)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        header = self.table.horizontalHeader()
        for c, mode in enumerate((QHeaderView.ResizeMode.ResizeToContents, QHeaderView.ResizeMode.Stretch,
                                  QHeaderView.ResizeMode.ResizeToContents, QHeaderView.ResizeMode.ResizeToContents,
                                  QHeaderView.ResizeMode.ResizeToContents)):
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
            for c, v in enumerate((r.group, r.case, r.ours, r.reference, r.source)):
                item = QTableWidgetItem(v)
                if c in (2, 3):
                    item.setFont(mono_font())
                    item.setToolTip(v)
                self.table.setItem(i, c, item)
        self.summary.setText(f"Đã chạy {len(rows)} ca kiểm thử.")
