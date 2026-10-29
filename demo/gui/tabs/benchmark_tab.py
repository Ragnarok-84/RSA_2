"""Tab 5 — Benchmark: thời gian sinh khoá / ký (CRT, không CRT) / kiểm tra theo kích thước khoá và thời gian băm
theo kích thước dữ liệu; biểu đồ matplotlib nhúng, bảng số liệu, xuất CSV và PNG."""
from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QAbstractItemView, QCheckBox, QFileDialog, QGroupBox, QHeaderView, QLabel, QSpinBox,
                               QSplitter, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget)

from demo import REPORT_DIR
from demo.benchmark import DATA_SIZES, KEY_SIZES, KINDS, BenchRow, fmt_size, run_benchmark, save_csv
from demo.gui.widgets import common
from demo.gui.widgets.common import button, glass, hbox

# Bảng màu phân loại cố định (đã kiểm tra CVD); mỗi phép đo luôn giữ cùng một màu và một dạng marker
SERIES = {"keygen": ("#2a78d6", "o"), "sign_crt": ("#eb6834", "s"), "sign_nocrt": ("#1baf7a", "^"),
          "verify": ("#eda100", "D")}
HASH_COLOR = "#2a78d6"
INK, MUTED, GRID = "#3B2A35", "#7a6a72", "#e6dde2"


class BenchmarkTab(QWidget):
    def __init__(self, app) -> None:
        super().__init__()
        self.app = app
        self.rows: list[BenchRow] = []
        self.figure = None
        lay = QVBoxLayout(self)

        self.key_boxes = {b: QCheckBox(f"{b} bít") for b in KEY_SIZES}
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
        lay.addLayout(hbox(QLabel("Số lần lặp (lấy trung vị):"), self.repeats, button("Chạy", self.start), None,
                           button("Xuất CSV…", self.export_csv), button("Xuất PNG…", self.export_png)))

        split = QSplitter(Qt.Orientation.Vertical)
        self.chart_box = QGroupBox("Biểu đồ")
        self.chart_lay = QVBoxLayout(self.chart_box)
        self.placeholder = QLabel("Bấm Chạy để đo. Khoá 3072 bít và dữ liệu 10 MB mất nhiều thời gian "
                                  "(SHA-256 tự cài bằng Python).")
        self.placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.chart_lay.addWidget(self.placeholder)
        split.addWidget(self.chart_box)
        self.table = glass(QTableWidget(0, 4))
        self.table.setHorizontalHeaderLabels(("Phép đo", "Tham số", "Trung vị", "Số lần lặp"))
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        box = QGroupBox("Bảng số liệu")
        QVBoxLayout(box).addWidget(self.table)
        split.addWidget(box)
        split.setSizes([430, 200])
        lay.addWidget(split, 1)

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
            param = fmt_size(r.param) if r.kind == "hash" else f"{r.param} bít"
            for c, v in enumerate((KINDS[r.kind], param, f"{r.median_s * 1000:.2f} ms", str(r.repeats))):
                self.table.setItem(i, c, QTableWidgetItem(v))
        self._plot()

    def _plot(self) -> None:
        from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg
        from matplotlib.figure import Figure
        from matplotlib.ticker import FuncFormatter, NullFormatter
        fig = Figure(figsize=(9, 3.6), facecolor="white")
        ax1, ax2 = fig.add_subplot(1, 2, 1), fig.add_subplot(1, 2, 2)
        for kind, (color, marker) in SERIES.items():
            pts = [(r.param, r.median_s * 1000) for r in self.rows if r.kind == kind]
            if pts:
                xs, ys = zip(*pts)
                ax1.plot(xs, ys, color=color, marker=marker, markersize=7, linewidth=2, label=KINDS[kind],
                         markeredgecolor="white", markeredgewidth=1.5)
        hashes = [(r.param, r.median_s * 1000) for r in self.rows if r.kind == "hash"]
        if hashes:
            xs, ys = zip(*hashes)
            ax2.plot(xs, ys, color=HASH_COLOR, marker="o", markersize=7, linewidth=2,
                     markeredgecolor="white", markeredgewidth=1.5)
            ax2.set_xscale("log")
            ax2.set_xticks(xs, [fmt_size(x) for x in xs])
            ax2.xaxis.set_minor_formatter(NullFormatter())
        for ax, title, xlabel in ((ax1, "RSA theo kích thước khoá", "Kích thước khoá (bít)"),
                                  (ax2, "Băm SHA-256 theo kích thước dữ liệu", "Kích thước dữ liệu")):
            ax.set_title(title, color=INK, fontsize=11, loc="left")
            ax.set_xlabel(xlabel, color=MUTED, fontsize=9)
            ax.set_ylabel("Thời gian (ms, thang log)", color=MUTED, fontsize=9)
            ax.set_yscale("log")
            ax.yaxis.set_major_formatter(FuncFormatter(lambda v, _pos: f"{v:g}"))
            ax.yaxis.set_minor_formatter(NullFormatter())
            ax.grid(True, color=GRID, linewidth=0.8)
            ax.tick_params(colors=MUTED, labelsize=8)
            for side in ("top", "right"):
                ax.spines[side].set_visible(False)
            for side in ("left", "bottom"):
                ax.spines[side].set_color(GRID)
        if any(r.kind != "hash" for r in self.rows):
            ax1.set_xticks(sorted({r.param for r in self.rows if r.kind != "hash"}))
            ax1.legend(frameon=False, fontsize=8, labelcolor=INK)
        fig.tight_layout()
        self.figure = fig
        while self.chart_lay.count():
            w = self.chart_lay.takeAt(0).widget()
            if w is not None:
                w.deleteLater()
        self.chart_lay.addWidget(FigureCanvasQTAgg(fig))

    def export_csv(self) -> None:
        if not self.rows:
            common.show_info(self, "Chưa có số liệu", "Bấm Chạy trước.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Xuất CSV", str(REPORT_DIR / "benchmark.csv"), "CSV (*.csv)")
        if path:
            save_csv(self.rows, Path(path))
            self.app.set_status(f"Đã ghi {path}")

    def export_png(self) -> None:
        if self.figure is None:
            common.show_info(self, "Chưa có biểu đồ", "Bấm Chạy trước.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Xuất PNG", str(REPORT_DIR / "benchmark.png"), "PNG (*.png)")
        if path:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            self.figure.savefig(path, dpi=150)
            self.app.set_status(f"Đã ghi {path}")
