"""Nhãn kết quả lớn: ✅ HỢP LỆ / ❌ KHÔNG HỢP LỆ + lý do."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel, QVBoxLayout, QWidget

from demo.gui.widgets.common import BLUE, GREEN, GREY, RED


class ResultBadge(QWidget):
    def __init__(self) -> None:
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 4, 0, 4)
        lay.setSpacing(2)
        self.title = QLabel()
        self.title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.reason = QLabel()
        self.reason.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.reason.setWordWrap(True)
        lay.addWidget(self.title)
        lay.addWidget(self.reason)
        self.clear()

    def _show(self, title: str, reason: str, color: str) -> None:
        self.title.setText(title)
        self.title.setStyleSheet(f"color: {color}; font-size: 18px; font-weight: 700;")
        self.reason.setText(reason)
        self.reason.setStyleSheet(f"color: {color};")

    def set_result(self, ok: bool, reason: str = "", ok_text: str = "✅ HỢP LỆ",
                   bad_text: str = "❌ KHÔNG HỢP LỆ") -> None:
        self._show(ok_text if ok else bad_text, reason, GREEN if ok else RED)

    def set_info(self, text: str, reason: str = "") -> None:
        self._show(text, reason, BLUE)

    def clear(self) -> None:
        self._show("", "", GREY)

    def text(self) -> str:
        return self.title.text()
