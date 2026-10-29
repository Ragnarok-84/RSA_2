from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QPushButton, QScrollArea, QVBoxLayout, QWidget

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
        if step.title == "Băm thu nhỏ" and self._add_hash_details(lay, body):
            return
        if body:
            value = QLabel(body)
            value.setFont(mono_font())
            value.setWordWrap(True)
            value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            if step.level == "dim":
                value.setStyleSheet(f"color: {LEVEL_COLORS['dim']};")
            lay.addWidget(value)

    @staticmethod
    def _add_hash_details(lay: QVBoxLayout, body: str) -> bool:
        lines = body.splitlines()
        if len(lines) != 3:
            return False
        symbol = next((symbol for symbol in ("x", "M")
                       if lines[0].startswith(f"SHA-256({symbol}) (hex) = ")
                       and lines[1].startswith(f"OS2IP(SHA-256({symbol})) = ")), None)
        if symbol is None:
            return False
        hex_value = lines[0].split(" = ", 1)[1]
        integer_value = lines[1].split(" = ", 1)[1]
        if not integer_value.isdigit():
            return False
        grouped_hex = " ".join(hex_value[i:i + 8] for i in range(0, len(hex_value), 8))
        grouped_integer = format(int(integer_value), ",").replace(",", " ")
        lay.setSpacing(8)
        for caption, display, raw in (
                (f"SHA-256({symbol}) · Hex, nhóm 8 ký tự", grouped_hex, hex_value),
                ("OS2IP · Số nguyên thập phân, nhóm 3 chữ số", grouped_integer, integer_value),
                ("Giá trị băm thu nhỏ", lines[2], lines[2])):
            panel = QFrame()
            panel.setObjectName("HashValuePanel")
            panel.setStyleSheet("""
                QFrame#HashValuePanel {
                    background: #FFF7FB;
                    border: 1px solid #F4D5E5;
                    border-radius: 8px;
                }
            """)
            panel_layout = QVBoxLayout(panel)
            panel_layout.setContentsMargins(8, 5, 8, 6)
            panel_layout.setSpacing(3)
            header = QHBoxLayout()
            label = QLabel(caption)
            label.setWordWrap(True)
            label.setStyleSheet("color: #666666; font-size: 12px;")
            header.addWidget(label, 1)
            copy_btn = QPushButton("Sao chép")
            copy_btn.setToolTip("Sao chép giá trị đầy đủ, không có khoảng trắng phân nhóm")
            copy_btn.clicked.connect(lambda _=False, text=raw: QGuiApplication.clipboard().setText(text))
            header.addWidget(copy_btn)
            panel_layout.addLayout(header)
            value = QLabel(display)
            value.setTextFormat(Qt.TextFormat.PlainText)
            value.setFont(mono_font())
            value.setWordWrap(True)
            value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            if caption == "Giá trị băm thu nhỏ":
                value.setStyleSheet(f"color: {LEVEL_COLORS['ok']}; font-weight: 700;")
            panel_layout.addWidget(value)
            lay.addWidget(panel)
        return True


class StepView(QScrollArea):
    def __init__(self) -> None:
        super().__init__()
        self.setObjectName("StepView")
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
        out = []
        for i in range(self._lay.count() - 1):
            w = self._lay.itemAt(i).widget()
            out += [lbl.text() for lbl in w.findChildren(QLabel) if lbl.text()]
        return out
