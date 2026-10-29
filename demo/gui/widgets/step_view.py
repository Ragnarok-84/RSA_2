"""Hiển thị danh sách Step: tiêu đề (tô màu theo mức), công thức render bằng FormulaLabel, giá trị monospace.

Hỗ trợ trình chiếu từng bước: set_steps(steps, reveal_all=False) rồi gọi next_step().
"""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFrame, QLabel, QScrollArea, QVBoxLayout, QWidget

from core.step_logger import Step, format_table
from demo.gui.widgets.common import LEVEL_COLORS, PLUM, glass, mono_font
from demo.gui.widgets.formula_label import FormulaLabel


class StepCard(QFrame):
    def __init__(self, index: int, step: Step) -> None:
        super().__init__()
        self.setObjectName("StepCard")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(10, 6, 10, 6)
        lay.setSpacing(3)
        color = LEVEL_COLORS.get(step.level, PLUM)
        numbered = step.level != "head" and not step.title.lstrip().startswith("[")   # kịch bản tự đánh số [n]
        title = QLabel(f"{index}. {step.title}" if numbered else step.title)
        title.setWordWrap(True)
        title.setStyleSheet(f"color: {color}; font-weight: 700;")
        title.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        lay.addWidget(title)
        if step.formula_latex or step.formula_plain:
            lay.addWidget(FormulaLabel(step.formula_latex, step.formula_plain))
        body = step.value_str
        if step.table:
            body = (body + "\n" if body else "") + format_table(*step.table)
        if body:
            value = QLabel(body)
            value.setFont(mono_font())
            value.setWordWrap(True)
            value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            if step.level == "dim":
                value.setStyleSheet(f"color: {LEVEL_COLORS['dim']};")
            lay.addWidget(value)


class StepView(QScrollArea):
    def __init__(self) -> None:
        super().__init__()
        self.setObjectName("StepView")            # style.qss: nền trắng, viền hồng
        glass(self)
        self.setWidgetResizable(True)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setFrameShape(QFrame.Shape.NoFrame)
        self._inner = QWidget()
        self._lay = QVBoxLayout(self._inner)
        self._lay.setContentsMargins(4, 4, 4, 4)
        self._lay.setSpacing(6)
        self._lay.addStretch(1)
        self.setWidget(self._inner)
        self._steps: list[Step] = []
        self.shown = 0

    def clear(self) -> None:
        while self._lay.count() > 1:
            item = self._lay.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self._steps, self.shown = [], 0

    def set_steps(self, steps: list[Step], reveal_all: bool = True) -> None:
        self.clear()
        self._steps = list(steps)
        if reveal_all:
            self.show_all()

    def has_next(self) -> bool:
        return self.shown < len(self._steps)

    def next_step(self) -> bool:
        if not self.has_next():
            return False
        step = self._steps[self.shown]
        number = sum(1 for s in self._steps[:self.shown + 1] if s.level != "head")
        self._lay.insertWidget(self._lay.count() - 1, StepCard(number, step))
        self.shown += 1
        bar = self.verticalScrollBar()
        bar.rangeChanged.connect(lambda _a, mx, b=bar: b.setValue(mx), Qt.ConnectionType.SingleShotConnection)
        return True

    def show_all(self) -> None:
        while self.next_step():
            pass

    def card_texts(self) -> list[str]:
        """Toàn bộ chữ trong các thẻ (dùng cho test)."""
        out = []
        for i in range(self._lay.count() - 1):
            w = self._lay.itemAt(i).widget()
            out += [lbl.text() for lbl in w.findChildren(QLabel) if lbl.text()]
        return out
