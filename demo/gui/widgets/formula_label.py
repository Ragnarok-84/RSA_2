"""Render công thức LaTeX bằng matplotlib mathtext thành QPixmap (có bộ nhớ đệm).

Nếu matplotlib không có hoặc công thức không render được thì hiện bản Unicode (formula_plain).
"""
from __future__ import annotations

import io
import re

from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication, QPixmap
from PySide6.QtWidgets import QLabel

from demo.gui.widgets.common import PLUM, mono_font

_CACHE: dict[tuple[str, float, str], QPixmap | None] = {}


def render_formula(latex: str, ratio: float = 1.0, color: str = PLUM, size: float = 13) -> QPixmap | None:
    # mathtext không tự chèn khoảng trắng quanh "mod" như \bmod của LaTeX
    latex = re.sub(r"\s*\\mathrm\{mod\}(\\ )?", lambda _m: r"\ \mathrm{mod}\ ", latex)
    key = (latex, ratio, color)
    if key in _CACHE:
        return _CACHE[key]
    pix = None
    try:
        from matplotlib.font_manager import FontProperties
        from matplotlib.mathtext import math_to_image
        buf = io.BytesIO()
        math_to_image(f"${latex}$", buf, prop=FontProperties(size=size), dpi=100 * ratio, format="png", color=color)
        pix = QPixmap()
        if pix.loadFromData(buf.getvalue(), "PNG"):
            pix.setDevicePixelRatio(ratio)
        else:
            pix = None
    except Exception:          # cú pháp mathtext không hỗ trợ, thiếu matplotlib…
        pix = None
    _CACHE[key] = pix
    return pix


class FormulaLabel(QLabel):
    def __init__(self, latex: str | None = None, plain: str | None = None) -> None:
        super().__init__()
        self.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.setStyleSheet("background: transparent;")
        if latex or plain:
            self.set_formula(latex, plain)

    def set_formula(self, latex: str | None, plain: str | None = None) -> None:
        screen = QGuiApplication.primaryScreen()
        ratio = screen.devicePixelRatio() if screen else 1.0
        pix = render_formula(latex, ratio) if latex else None
        if pix is not None:
            self.setPixmap(pix)
            self.setToolTip(plain or latex)
        else:
            self.setFont(mono_font())
            self.setText(plain or latex or "")
