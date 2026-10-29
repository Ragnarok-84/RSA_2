"""Giao diện đồ họa (PySide6 / Qt 6): cửa sổ chính và điểm vào.
Chạy từ thư mục gốc dự án:   python demo/gui/run.py"""
import contextlib
import queue
import sys
import threading
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor, QFont, QPainter, QPixmap
from PySide6.QtWidgets import QApplication, QLabel, QMainWindow, QProgressBar, QTabWidget, QVBoxLayout, QWidget

from core.rsa_math import generate_keypair
from demo.gui import widgets
from demo.gui.widgets import PEOPLE, RESOURCES, UI_FONT, UI_PX, QueueWriter, amp, with_role
from demo.gui.tabs import ConfidentialityTab, KeyTab, MiniTab, ScenarioTab, SignTab, ToolsTab

STYLE_QSS = RESOURCES / "style.qss"
TITLE = "HỆ CHỮ KÝ ĐIỆN TỬ RSA - NHÓM 11"
DEFAULT_BITS = 2048                         # khóa sinh sẵn khi mở chương trình (mức khuyến nghị thực tế)
BACKGROUND = RESOURCES / "background.png"


class BackgroundWidget(QWidget):
    """Vẽ ảnh nền phủ kín cửa sổ (giữ tỉ lệ, căn giữa). Không đặt ảnh qua QSS vì QSS lặp ảnh cho từng widget con."""

    def __init__(self):
        super().__init__()
        self._src = QPixmap(str(BACKGROUND))
        self._scaled = None

    def resizeEvent(self, event):
        self._scaled = None
        super().resizeEvent(event)

    def paintEvent(self, _event):
        p = QPainter(self)
        if self._src.isNull():
            p.fillRect(self.rect(), QColor("#DDE5F5"))
            return
        if self._scaled is None:
            self._scaled = self._src.scaled(self.size(), Qt.AspectRatioMode.KeepAspectRatioByExpanding,
                                            Qt.TransformationMode.SmoothTransformation)
        x = (self.width() - self._scaled.width()) // 2
        y = (self.height() - self._scaled.height()) // 2
        p.drawPixmap(x, y, self._scaled)


class MainWindow(QMainWindow):
    def __init__(self, autostart=False):
        super().__init__()
        self.setWindowTitle(TITLE)
        avail = QApplication.primaryScreen().availableGeometry()
        self.resize(min(1180, avail.width() - 40), min(820, avail.height() - 60))
        self.keys = {}                      # tên -> (khóa riêng, khóa công khai)
        self._q = queue.Queue()
        self._busy = False

        back = BackgroundWidget()
        self.setCentralWidget(back)
        lay = QVBoxLayout(back)
        lay.setContentsMargins(28, 12, 28, 18)
        lay.setSpacing(10)
        lay.addWidget(QLabel(TITLE, objectName="Title"), 0, Qt.AlignmentFlag.AlignHCenter)

        self.nb = QTabWidget()
        self.nb.tabBar().setDrawBase(False)
        lay.addWidget(self.nb, 1)
        self.key_tab = KeyTab(self)
        self.sign_tab = SignTab(self)
        self.conf_tab = ConfidentialityTab(self)
        self.mini_tab = MiniTab(self)
        self.scen_tab = ScenarioTab(self)
        self.tool_tab = ToolsTab(self)
        for tab, name in ((self.key_tab, "1. Khóa"), (self.sign_tab, "2. Ký & Kiểm tra"),
                          (self.conf_tab, "3. Bảo mật (ký rồi mã hóa)"), (self.mini_tab, "4. Tính tay"),
                          (self.scen_tab, "5. Kịch bản & Tấn công"), (self.tool_tab, "6. Kiểm thử & Đánh giá")):
            self.nb.addTab(tab, amp(name))

        self.status_label = QLabel("Sẵn sàng")
        self.progress = QProgressBar()
        self.progress.setFixedWidth(180)
        self.progress.setTextVisible(False)
        self.progress.setRange(0, 1)
        self.statusBar().addWidget(self.status_label, 1)
        self.statusBar().addPermanentWidget(self.progress)
        self.statusBar().setSizeGripEnabled(False)

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._poll)
        self._timer.start(50)
        if autostart:                       # sinh sẵn khóa để tab 2, 3 dùng được ngay, không phải qua tab 1
            self.generate_keys(PEOPLE, DEFAULT_BITS, initial=True)

    def set_status(self, text):
        self.status_label.setText(with_role(text))

    # chạy tác vụ nền
    def run(self, fn, on_done=None, output=None, status="Đang xử lý..."):
        """Chạy fn() ở luồng nền; stdout của fn được chuyển vào ô `output`; on_done(kết quả) chạy ở luồng giao diện."""
        if self._busy:
            widgets.show_info(self, "Đang bận", "Đang chạy một tác vụ khác, vui lòng đợi.")
            return
        self._busy = True
        self.set_status(status)
        self.progress.setRange(0, 0)

        def worker():
            writer = QueueWriter(self._q, output)
            try:
                with contextlib.redirect_stdout(writer):
                    result = fn()
                self._q.put(("done", on_done, result, output))
            except Exception as err:
                self._q.put(("error", err, traceback.format_exc(), output))

        threading.Thread(target=worker, daemon=True).start()

    def _poll(self):
        try:
            while True:
                item = self._q.get_nowait()
                kind = item[0]
                if kind == "out":
                    item[1].stream(item[2])
                elif kind in ("done", "error"):
                    self._busy = False
                    self.progress.setRange(0, 1)
                    output = item[3]
                    if output is not None:
                        output.flush()
                    if kind == "done":
                        self.set_status("Hoàn tất")
                        if item[1]:
                            item[1](item[2])
                    else:
                        self.set_status(f"Lỗi: {item[1]}")
                        if output is not None:
                            output.append(f"[Lỗi] {type(item[1]).__name__}: {item[1]}\n", "bad")
                        else:
                            widgets.show_error(self, "Lỗi", f"{type(item[1]).__name__}: {item[1]}")
        except queue.Empty:
            pass

    # khóa
    def generate_keys(self, names, bits, initial=False):
        def job():
            return {n: generate_keypair(keysize=bits) for n in names}

        def done(new):
            self.keys.update(new)
            self.key_tab.refresh()
            self.set_status(f"Đã sinh khóa {bits} bit cho: {', '.join(names)}")
            if initial:
                self.key_tab.out.append(f"Đã sinh sẵn khóa {bits} bit cho {', '.join(names)}.\n"
                                        "Có thể sang tab 2, 3 dùng ngay; muốn đổi khóa thì sinh lại ở đây.\n", "ok")

        self.run(job, done, status=f"Đang sinh khóa {bits} bit cho {', '.join(names)}..."
                 + (" (khóa mặc định khi khởi động)" if initial else ""))

    def key(self, name, min_bits=0, purpose=""):
        pair = self.keys.get(name)
        if pair is None:
            if self._busy:
                widgets.show_info(self, "Đang sinh khóa", "Đang sinh khóa cho 4 người, đợi vài giây rồi bấm lại.")
            else:
                widgets.show_warning(self, "Thiếu khóa", f"Chưa có khóa của {name}. Hãy sinh khóa ở tab 1.")
            return None
        if pair[1][1].bit_length() < min_bits:
            widgets.show_warning(self, "Khóa quá ngắn",
                                 f"Khóa của {name} chỉ {pair[1][1].bit_length()} bit; {purpose} cần >= {min_bits} bit.\n"
                                 "Hãy sinh lại khóa lớn hơn ở tab 1 (bản số nhỏ dùng tab 4. Tính tay).")
            return None
        return pair


def create_app(argv=None):
    app = QApplication.instance() or QApplication(argv or sys.argv)
    # Fusion phải đặt TRƯỚC stylesheet: style gốc Windows/macOS bỏ qua một phần QSS (rgba, bo góc)
    app.setStyle("Fusion")
    font = QFont(UI_FONT)
    font.setPixelSize(UI_PX)
    app.setFont(font)
    app.setStyleSheet(STYLE_QSS.read_text(encoding="utf-8"))
    return app


def main():
    app = create_app()
    window = MainWindow(autostart=True)
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
