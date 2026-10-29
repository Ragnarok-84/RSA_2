from __future__ import annotations

from PySide6.QtGui import QGuiApplication, QTextOption
from PySide6.QtWidgets import QHBoxLayout, QLabel, QPlainTextEdit, QPushButton, QVBoxLayout, QWidget

from demo.gui.widgets.common import glass, mono_font


class HexView(QWidget):
    def __init__(self, title: str, lines: int = 3) -> None:
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(2)
        self.title = QLabel(title)
        self.copy_btn = QPushButton("Copy")
        self.copy_btn.setFixedWidth(64)
        self.copy_btn.clicked.connect(self.copy)
        head = QHBoxLayout()
        head.addWidget(self.title, 1)
        head.addWidget(self.copy_btn)
        lay.addLayout(head)
        self.box = glass(QPlainTextEdit())
        self.box.setReadOnly(True)
        self.box.setFont(mono_font())
        self.box.setWordWrapMode(QTextOption.WrapMode.WrapAnywhere)
        self.box.setFixedHeight(self.box.fontMetrics().lineSpacing() * lines + 16)
        lay.addWidget(self.box)

    def set_hex(self, value: bytes | str) -> None:
        self.box.setPlainText(value.hex() if isinstance(value, bytes) else value)

    def value(self) -> str:
        return self.box.toPlainText()

    def clear(self) -> None:
        self.box.clear()

    def copy(self) -> None:
        QGuiApplication.clipboard().setText(self.value())
