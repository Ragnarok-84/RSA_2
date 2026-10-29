"""Hằng số, hàm tiện ích, hộp thoại và widget dùng chung cho các tab."""
import io
import os
import re
import sys
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont, QTextCharFormat, QTextCursor
from PySide6.QtWidgets import (QButtonGroup, QFileDialog, QHBoxLayout, QInputDialog, QLabel, QLineEdit,
                               QMessageBox, QPlainTextEdit, QPushButton, QRadioButton, QVBoxLayout, QWidget)

ROOT = Path(__file__).resolve().parents[2]
RESOURCES = Path(__file__).resolve().parent / "resources"

# Phông chữ theo hệ điều hành (macOS không có Consolas / Segoe UI). Cỡ chữ tính bằng pixel độc lập thiết bị,
# Qt tự nhân theo DPI nên Windows và macOS hiển thị cùng tỉ lệ.
if sys.platform == "darwin":
    UI_FONT, MONO_FONT, MONO_PX = "Helvetica Neue", "Menlo", 12
elif sys.platform.startswith("win"):
    UI_FONT, MONO_FONT, MONO_PX = "Segoe UI", "Consolas", 13    # Consolas hẹp hơn Menlo nên lớn hơn 1 px
else:
    UI_FONT, MONO_FONT, MONO_PX = "DejaVu Sans", "DejaVu Sans Mono", 12
UI_PX = 13

GREEN, RED, BLUE, GREY = "#1b7f3b", "#c62828", "#1f4e9c", "#666666"
PEOPLE = ("Thu Trang", "Thu Thủy", "Mai Phương", "Tuyết Linh")
ROLES = {"Thu Trang": "Người ký", "Thu Thủy": "Người nhận (mã hóa)", "Mai Phương": "Kẻ tấn công", "Tuyết Linh": "Người thứ ba"}
# Vai trò ghi kèm tên khi HIỂN THỊ; mã định danh (khóa dict, chủ thể chứng thư, tên tệp) vẫn là tên trần
ROLE_TAGS = {"Thu Trang": "Sender", "Thu Thủy": "Receiver", "Mai Phương": "Attacker", "Tuyết Linh": "Third party"}
_NAME_RE = re.compile(f"({'|'.join(PEOPLE)})" + r"(?! \((?:" + "|".join(ROLE_TAGS.values()) + r")\))")


def with_role(text):
    """'Thu Trang ký' -> 'Thu Trang (Sender) ký'. Tên đã có vai trò thì giữ nguyên."""
    return _NAME_RE.sub(lambda m: f"{m[1]} ({ROLE_TAGS[m[1]]})", text)


# Hộp thoại (bộ test thay các hàm này để không bật cửa sổ)
def show_info(parent, title, text):
    QMessageBox.information(parent, title, with_role(text))


def show_warning(parent, title, text):
    QMessageBox.warning(parent, title, with_role(text))


def show_error(parent, title, text):
    QMessageBox.critical(parent, title, with_role(text))


def ask_password(parent, prompt):
    text, ok = QInputDialog.getText(parent, "Mật khẩu", prompt, QLineEdit.EchoMode.Password)
    return text if ok else None


def mono_font(bold=False):
    f = QFont(MONO_FONT)
    f.setStyleHint(QFont.StyleHint.Monospace)
    f.setPixelSize(MONO_PX)
    f.setBold(bold)
    return f


def short_int(x, head=28, tail=12):
    h = format(x, "x")
    body = h if len(h) <= head + tail + 3 else f"{h[:head]}…{h[-tail:]}"
    return f"0x{body}  ({x.bit_length()} bit)"


def parse_int(text):
    """Đọc số nguyên từ ô nhập (chấp nhận hex có/không có 0x hoặc thập phân)."""
    t = "".join(text.split()).lower()
    if t.startswith("0x"):
        return int(t[2:], 16)
    return int(t, 16) if any(c in "abcdef" for c in t) else int(t)


def amp(text):
    """Qt coi '&' là phím tắt; nhân đôi để hiện đúng ký tự."""
    return text.replace("&", "&&")


def hbox(*widgets, spacing=6):
    """Hàng ngang; phần tử None là khoảng giãn."""
    lay = QHBoxLayout()
    lay.setContentsMargins(0, 0, 0, 0)
    lay.setSpacing(spacing)
    for w in widgets:
        if w is None:
            lay.addStretch(1)
        else:
            lay.addWidget(w)
    return lay


def button(text, slot):
    b = QPushButton(amp(with_role(text)))
    b.setCursor(Qt.CursorShape.PointingHandCursor)
    b.clicked.connect(lambda _=False: slot())
    return b


def bold_label(text):
    label = QLabel(with_role(text))
    label.setStyleSheet("font-weight: 700;")
    return label


def labeled_entry(text, width=80):
    label, entry = QLabel(text), QLineEdit()
    entry.setFixedWidth(width)
    return label, entry


def glass(widget):
    """Bỏ nền đặc của viewport (bảng, ô văn bản) để ảnh nền lộ qua."""
    widget.viewport().setAutoFillBackground(False)
    return widget


def text_box(lines=None, read_only=False):
    box = glass(QPlainTextEdit())
    box.setFont(mono_font())
    box.setReadOnly(read_only)
    if lines:
        box.setFixedHeight(box.fontMetrics().lineSpacing() * lines + 16)
    return box


class OutputBox(QPlainTextEdit):
    """Ô hiển thị kết quả: tự tô màu dòng ✓ / ✗ / SUCCESS / FAILED."""
    COLORS = {"ok": GREEN, "bad": RED, "head": BLUE, "dim": GREY}

    def __init__(self):
        super().__init__()
        self.setReadOnly(True)
        self.setFont(mono_font())
        glass(self)
        self._buf = ""

    @staticmethod
    def _tag_for(line):
        s = line.rstrip()
        if s.startswith("[FAILED]") or "LỆCH" in s or "Traceback" in s or s.endswith(("... FAIL", "... ERROR")) \
                or "| LỖI" in s:
            return "bad"
        if s.startswith("[SUCCESS]") or s.endswith("KHỚP") or s.endswith("... ok") or "| ĐẠT" in s \
                or s.startswith("OK"):
            return "ok"
        if line.startswith("===") or line.startswith("---") or "KỊCH BẢN" in line:
            return "head"
        return None

    def append(self, text, tag=None, roles=True):
        """roles=False: chèn nguyên văn (nội dung người dùng nhập), không ghi vai trò sau tên."""
        if roles:
            text = with_role(text)
        cur = self.textCursor()
        cur.movePosition(QTextCursor.MoveOperation.End)
        for line in text.splitlines(keepends=True):
            fmt = QTextCharFormat()
            t = tag or self._tag_for(line)
            if t:
                fmt.setForeground(QColor(self.COLORS[t]))
                if t == "head":
                    fmt.setFontWeight(QFont.Weight.Bold)
            cur.insertText(line, fmt)
        self.setTextCursor(cur)
        self.ensureCursorVisible()

    def stream(self, chunk):
        """Nhận từng mẩu stdout, chỉ chèn khi đủ dòng để tô màu đúng."""
        self._buf += chunk
        if "\n" in self._buf:
            done, self._buf = self._buf.rsplit("\n", 1)
            self.append(done + "\n")

    def flush(self):
        if self._buf:
            self.append(self._buf + "\n")
            self._buf = ""

    def text(self):
        return self.toPlainText()


class QueueWriter(io.TextIOBase):
    """Chuyển stdout của luồng nền vào hàng đợi để luồng giao diện in ra ô kết quả."""

    def __init__(self, q, target):
        self.q, self.target = q, target

    def write(self, s):
        if self.target is not None:
            self.q.put(("out", self.target, s))
        return len(s)


class DataSource(QWidget):
    """Khung chọn dữ liệu: gõ văn bản hoặc chọn tệp thật."""

    def __init__(self, title, lines=5):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        self.text_mode = QRadioButton("Văn bản")
        self.file_mode = QRadioButton("Tệp")
        self.text_mode.setChecked(True)
        group = QButtonGroup(self)
        group.addButton(self.text_mode)
        group.addButton(self.file_mode)
        self.path = QLineEdit()
        self.browse_btn = button("Chọn tệp...", self._browse)
        lay.addLayout(hbox(bold_label(title), self.text_mode, self.file_mode, self.path, self.browse_btn, None))
        self.text = text_box(lines)
        lay.addWidget(self.text)
        self.file_mode.toggled.connect(self._mode)
        self._mode()

    def _mode(self):
        file = self.file_mode.isChecked()
        self.path.setVisible(file)
        self.browse_btn.setVisible(file)
        self.text.setEnabled(not file)

    def _browse(self):
        p, _ = QFileDialog.getOpenFileName(self, "Chọn tệp", str(ROOT / "samples"))
        if p:
            self.path.setText(p)

    def get(self):
        """:return: (dữ liệu bytes, tên tệp hoặc None). ValueError nếu chưa nhập gì, OSError nếu không đọc được tệp."""
        if self.file_mode.isChecked():
            if not self.path.text().strip():
                raise ValueError("Hãy chọn tệp trước.")
            with open(self.path.text(), "rb") as f:
                return f.read(), os.path.basename(self.path.text())
        text = self.text.toPlainText()
        if not text.strip():
            raise ValueError("Hãy nhập thông điệp trước.")
        return text.encode("utf-8"), None

    def read(self):
        """Như get() nhưng hiện thông báo thay vì ném lỗi. :return: (dữ liệu, tên) hoặc None"""
        try:
            return self.get()
        except ValueError as err:
            show_warning(self, "Thiếu dữ liệu", str(err))
        except OSError as err:
            show_error(self, "Không đọc được tệp", str(err))
        return None
