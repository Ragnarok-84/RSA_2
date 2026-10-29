from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import QLabel

from core.step_logger import latex_to_plain
from demo.gui.widgets.common import PLUM, UI_FONT, UI_PX


class FormulaLabel(QLabel):
    def __init__(self, latex: str | None = None, plain: str | None = None) -> None:
        super().__init__()
        self.setTextFormat(Qt.TextFormat.PlainText)
        self.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.setWordWrap(True)
        font = QFont(UI_FONT)
        font.setPixelSize(UI_PX + 1)
        self.setFont(font)
        self.setStyleSheet(f"color: {PLUM}; background: transparent;")
        if latex or plain:
            self.set_formula(latex, plain)

    def set_formula(self, latex: str | None, plain: str | None = None) -> None:
        text = plain if plain is not None else latex_to_plain(latex or "")
        self.setText(text)
        self.setToolTip(text)
