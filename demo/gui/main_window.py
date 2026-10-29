from __future__ import annotations

import sys
import time
from typing import Callable

from PySide6.QtCore import Qt, QThreadPool
from PySide6.QtGui import QColor, QFont, QPainter, QPixmap
from PySide6.QtWidgets import (QApplication, QLabel, QMainWindow, QProgressBar, QPushButton, QTabWidget,
                               QVBoxLayout, QWidget)

from demo.gui import RESOURCES
from demo.gui.widgets import common
from demo.gui.widgets.common import UI_FONT, UI_PX, amp
from demo.gui.workers import Worker

TITLE = "HỆ CHỮ KÝ ĐIỆN TỬ RSA - NHÓM 11"
MEMBERS = ("Thu Trang", "Thu Thủy", "Mai Phương", "Tuyết Linh")
STYLE_QSS = RESOURCES / "style.qss"
BACKGROUND = RESOURCES / "background.png"


class BackgroundWidget(QWidget):

    def __init__(self) -> None:
        super().__init__()
        self._src = QPixmap(str(BACKGROUND))
        self._scaled: QPixmap | None = None

    def resizeEvent(self, event) -> None:
        self._scaled = None
        super().resizeEvent(event)

    def paintEvent(self, _event) -> None:
        p = QPainter(self)
        if self._src.isNull():
            p.fillRect(self.rect(), QColor("#DDE5F5"))
            return
        if self._scaled is None:
            self._scaled = self._src.scaled(self.size(), Qt.AspectRatioMode.KeepAspectRatioByExpanding,
                                            Qt.TransformationMode.SmoothTransformation)
        p.drawPixmap((self.width() - self._scaled.width()) // 2, (self.height() - self._scaled.height()) // 2,
                     self._scaled)


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        from demo.gui.tabs.attacks_tab import AttacksTab
        from demo.gui.tabs.benchmark_tab import BenchmarkTab
        from demo.gui.tabs.pki_tab import PKITab
        from demo.gui.tabs.sign_encrypt_tab import SignEncryptTab
        from demo.gui.tabs.sign_verify_tab import SignVerifyTab
        from demo.gui.tabs.test_tab import TestTab
        from demo.gui.tabs.tiny_tab import TinyTab

        self.setWindowTitle(TITLE)
        self.setMinimumSize(1100, 750)
        avail = QApplication.primaryScreen().availableGeometry()
        self.resize(max(1100, min(1240, avail.width() - 40)), max(750, min(840, avail.height() - 60)))
        self.pool = QThreadPool.globalInstance()
        self.busy = False
        self._worker: Worker | None = None
        self._disabled: list[QPushButton] = []
        self._t0 = 0.0

        back = BackgroundWidget()
        self.setCentralWidget(back)
        lay = QVBoxLayout(back)
        lay.setContentsMargins(28, 12, 28, 18)
        lay.setSpacing(10)
        lay.addWidget(QLabel(TITLE, objectName="Title"), 0, Qt.AlignmentFlag.AlignHCenter)

        self.tabs = QTabWidget()
        self.tabs.tabBar().setDrawBase(False)
        self.tabs.setUsesScrollButtons(False)         # đủ chỗ cho 7 tab ở 1100 px, không hiện mũi tên cuộn
        self.tabs.setElideMode(Qt.TextElideMode.ElideRight)
        lay.addWidget(self.tabs, 1)
        # Thứ tự theo đường đi của bức điện: ký -> ký rồi mã hoá -> tin khoá công khai (PKI) -> phân tích -> đo, kiểm thử
        self.tiny_tab = TinyTab(self)
        self.sign_tab = SignVerifyTab(self)
        self.encrypt_tab = SignEncryptTab(self)
        self.pki_tab = PKITab(self)
        self.attacks_tab = AttacksTab(self)
        self.bench_tab = BenchmarkTab(self)
        self.test_tab = TestTab(self)
        for tab, name in ((self.tiny_tab, "1. Tiny RSA"), (self.sign_tab, "2. Ký & Kiểm tra"),
                          (self.encrypt_tab, "3. Ký rồi mã hoá"), (self.pki_tab, "4. PKI & Chống chối bỏ"),
                          (self.attacks_tab, "5. Phân tích an toàn"), (self.bench_tab, "6. Hiệu năng"),
                          (self.test_tab, "7. Kiểm thử")):
            self.tabs.addTab(tab, amp(name))

        self.status_label = QLabel("Sẵn sàng")
        self.progress = QProgressBar()
        self.progress.setFixedWidth(180)
        self.progress.setTextVisible(False)
        self.progress.setRange(0, 1)
        self.statusBar().addWidget(self.status_label, 1)
        self.statusBar().addPermanentWidget(self.progress)
        self.statusBar().setSizeGripEnabled(False)

    def set_status(self, text: str) -> None:
        self.status_label.setText(text)

    def run(self, fn: Callable, on_done: Callable | None = None, status: str = "Đang xử lý...",
            owner: QWidget | None = None) -> bool:
        if self.busy:
            common.show_info(self, "Đang bận", "Đang chạy một tác vụ khác, vui lòng đợi.")
            return False
        self.busy = True
        self._t0 = time.perf_counter()
        self.set_status(status)
        self.progress.setRange(0, 0)
        owner = owner or self.tabs.currentWidget()
        self._disabled = [b for b in owner.findChildren(QPushButton) if b.isEnabled()]
        for b in self._disabled:
            b.setEnabled(False)
        w = Worker(fn)
        w.signals.finished.connect(lambda result: self._finish(True, result, on_done))
        w.signals.error.connect(lambda msg, tb: self._finish(False, (msg, tb), None))
        w.signals.progress.connect(self._on_progress)
        w.signals.message.connect(self.set_status)
        self._worker = w
        self.pool.start(w)
        return True

    def _on_progress(self, done: int, total: int) -> None:
        if total > 0:
            self.progress.setRange(0, 1000)
            self.progress.setValue(int(done * 1000 / total))

    def _finish(self, ok: bool, payload, on_done: Callable | None) -> None:
        self.busy = False
        self._worker = None
        self.progress.setRange(0, 1)
        self.progress.setValue(0)
        for b in self._disabled:
            b.setEnabled(True)
        self._disabled = []
        elapsed = time.perf_counter() - self._t0
        if ok:
            self.set_status(f"Hoàn tất ({elapsed:.2f} s)")
            if on_done is not None:
                try:
                    on_done(payload)
                except Exception as err:          # lỗi khi hiển thị cũng không được làm sập ứng dụng
                    common.show_error(self, "Lỗi", f"{type(err).__name__}: {err}")
        else:
            msg, tb = payload
            self.set_status(f"Lỗi: {msg}")
            print(tb, file=sys.stderr)
            common.show_error(self, "Lỗi", msg)


def create_app(argv: list[str] | None = None) -> QApplication:
    app = QApplication.instance() or QApplication(argv or sys.argv)
    # Fusion phải đặt TRƯỚC stylesheet: style gốc Windows/macOS bỏ qua một phần QSS (rgba, bo góc)
    app.setStyle("Fusion")
    font = QFont(UI_FONT)
    font.setPixelSize(UI_PX)
    app.setFont(font)
    # url(RES/...) trong QSS trỏ tới thư mục resources, không phụ thuộc thư mục đang chạy
    app.setStyleSheet(STYLE_QSS.read_text(encoding="utf-8").replace("url(RES/", f"url({RESOURCES.as_posix()}/"))
    return app


def main() -> None:
    app = create_app()
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
