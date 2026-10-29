from __future__ import annotations

import sys
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont, QFontDatabase, QTextCharFormat, QTextCursor
from PySide6.QtWidgets import (QButtonGroup, QFileDialog, QHBoxLayout, QLabel, QLineEdit, QMessageBox,
                               QPlainTextEdit, QPushButton, QRadioButton, QVBoxLayout, QWidget)

from core.step_logger import StepLogger
from demo.gui import ROOT

# Phông chữ theo hệ điều hành; cỡ chữ tính bằng pixel độc lập thiết bị nên Windows và macOS cùng tỉ lệ
if sys.platform == "darwin":
    UI_FONT, MONO_PX = "Helvetica Neue", 12
elif sys.platform.startswith("win"):
    UI_FONT, MONO_PX = "Segoe UI", 13
else:
    UI_FONT, MONO_PX = "DejaVu Sans", 12
UI_PX = 13

GREEN, RED, BLUE, GREY, ROSE, PLUM = "#1b7f3b", "#c62828", "#1f4e9c", "#666666", "#C2185B", "#5A1A3C"
LEVEL_COLORS = {"ok": GREEN, "bad": RED, "head": BLUE, "dim": GREY}
SAMPLE = ROOT / "sample"
def show_info(parent, title: str, text: str) -> None:
    QMessageBox.information(parent, title, text)


def show_warning(parent, title: str, text: str) -> None:
    QMessageBox.warning(parent, title, text)


def show_error(parent, title: str, text: str) -> None:
    QMessageBox.critical(parent, title, text)
def mono_font(bold: bool = False) -> QFont:
    f = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
    f.setPixelSize(MONO_PX)
    f.setBold(bold)
    return f


def amp(text: str) -> str:
    return text.replace("&", "&&")


def hbox(*widgets, spacing: int = 6) -> QHBoxLayout:
    lay = QHBoxLayout()
    lay.setContentsMargins(0, 0, 0, 0)
    lay.setSpacing(spacing)
    for w in widgets:
        if w is None:
            lay.addStretch(1)
        elif isinstance(w, QHBoxLayout):
            lay.addLayout(w)
        else:
            lay.addWidget(w)
    return lay


def button(text: str, slot) -> QPushButton:
    b = QPushButton(amp(text))
    b.setCursor(Qt.CursorShape.PointingHandCursor)
    b.clicked.connect(lambda _=False: slot())
    return b


def bold_label(text: str) -> QLabel:
    label = QLabel(text)
    label.setStyleSheet("font-weight: 700;")
    return label


def glass(widget):
    widget.viewport().setAutoFillBackground(False)
    return widget


def text_box(lines: int | None = None, read_only: bool = False) -> QPlainTextEdit:
    box = glass(QPlainTextEdit())
    box.setFont(mono_font())
    box.setReadOnly(read_only)
    if lines:
        box.setFixedHeight(box.fontMetrics().lineSpacing() * lines + 16)
    return box


class OutputBox(QPlainTextEdit):

    def __init__(self) -> None:
        super().__init__()
        self.setReadOnly(True)
        self.setFont(mono_font())
        glass(self)

    @staticmethod
    def _tag_for(line: str) -> str | None:
        s = line.rstrip()
        if s.startswith(("❌", "[LỖI]")) or "KHÔNG HỢP LỆ" in s:
            return "bad"
        if s.startswith("✅") or s.endswith("HỢP LỆ"):
            return "ok"
        if s.startswith(("===", "---", ">>>")):
            return "head"
        return None

    def append(self, text: str, tag: str | None = None) -> None:
        cur = self.textCursor()
        cur.movePosition(QTextCursor.MoveOperation.End)
        for line in text.splitlines(keepends=True):
            fmt = QTextCharFormat()
            t = tag or self._tag_for(line)
            if t:
                fmt.setForeground(QColor(LEVEL_COLORS[t]))
                if t == "head":
                    fmt.setFontWeight(QFont.Weight.Bold)
            cur.insertText(line, fmt)
        self.setTextCursor(cur)
        self.ensureCursorVisible()

    def append_steps(self, log: StepLogger) -> None:
        for step in log:
            lines = step.to_text().splitlines()
            self.append(lines[0] + "\n", step.level or None)
            if len(lines) > 1:
                self.append("\n".join(lines[1:]) + "\n", "dim" if step.level == "dim" else None)

    def text(self) -> str:
        return self.toPlainText()


class DataSource(QWidget):

    def __init__(self, title: str, lines: int = 5) -> None:
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
        self.path.setPlaceholderText("Chọn tệp hoặc kéo-thả tệp vào cửa sổ")
        self.browse_btn = button("Chọn tệp...", self._browse)
        lay.addLayout(hbox(bold_label(title), self.text_mode, self.file_mode, self.path, self.browse_btn, None))
        self.text = text_box(lines)
        lay.addWidget(self.text)
        self.file_mode.toggled.connect(self._mode)
        self._mode()

    def _mode(self) -> None:
        file = self.file_mode.isChecked()
        self.path.setVisible(file)
        self.browse_btn.setVisible(file)
        self.text.setEnabled(not file)

    def _browse(self) -> None:
        p, _ = QFileDialog.getOpenFileName(self, "Chọn tệp", str(SAMPLE / "messages"))
        if p:
            self.set_file(Path(p))

    def set_file(self, path: Path) -> None:
        self.file_mode.setChecked(True)
        self.path.setText(str(path))

    def set_text(self, text: str) -> None:
        self.text_mode.setChecked(True)
        self.text.setPlainText(text)

    def file(self) -> Path | None:
        return Path(self.path.text()) if self.file_mode.isChecked() and self.path.text().strip() else None

    def get(self) -> tuple[bytes, Path | None]:
        if self.file_mode.isChecked():
            if not self.path.text().strip():
                raise ValueError("Hãy chọn tệp trước.")
            p = Path(self.path.text())
            return p.read_bytes(), p
        text = self.text.toPlainText()
        if not text:
            raise ValueError("Hãy nhập thông điệp trước.")
        return text.encode("utf-8"), None

    def read(self) -> tuple[bytes, Path | None] | None:
        try:
            return self.get()
        except ValueError as err:
            show_warning(self, "Thiếu dữ liệu", str(err))
        except OSError as err:
            show_error(self, "Không đọc được tệp", str(err))
        return None
