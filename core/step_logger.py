from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator, Sequence

LEVELS = ("", "head", "ok", "bad", "dim")

@dataclass
class Step:
    """Một bước: tiêu đề, công thức (LaTeX + Unicode), giá trị; có thể kèm bảng (tiêu đề cột, các dòng)."""
    title: str
    formula_latex: str | None = None
    formula_plain: str | None = None
    value_str: str = ""
    level: str = ""
    table: tuple[tuple[str, ...], list[tuple[object, ...]]] | None = None

    def to_text(self) -> str:
        parts = [self.title]
        if self.formula_plain:
            parts.append(f"    {self.formula_plain}")
        if self.value_str:
            parts.extend(f"    {line}" for line in self.value_str.splitlines())
        if self.table:
            parts.extend(f"    {line}" for line in format_table(*self.table).splitlines())
        return "\n".join(parts)


def format_table(headers: Sequence[str], rows: Sequence[Sequence[object]]) -> str:
    """Bảng căn cột dạng văn bản."""
    cells = [[str(h) for h in headers]] + [["" if v is None else str(v) for v in r] for r in rows]
    widths = [max(len(r[i]) for r in cells) for i in range(len(headers))]
    lines = [" | ".join(c.rjust(w) for c, w in zip(r, widths)) for r in cells]
    lines.insert(1, "-+-".join("-" * w for w in widths))
    return "\n".join(lines)


class StepLogger:
    """Danh sách các Step theo thứ tự thực hiện."""

    def __init__(self) -> None:
        self.steps: list[Step] = []

    def log(self, title: str, formula: str | None = None, value: object = None, *,
            plain: str | None = None, level: str = "",
            table: tuple[Sequence[str], Sequence[Sequence[object]]] | None = None) -> Step:
        if level not in LEVELS:
            raise ValueError(f"level phải thuộc {LEVELS}")
        if formula is not None and plain is None:
            plain = formula
        tbl = (tuple(table[0]), [tuple(r) for r in table[1]]) if table else None
        step = Step(title, formula, plain, "" if value is None else str(value), level, tbl)
        self.steps.append(step)
        return step

    # Các dạng viết tắt cho câu chuyện trong kịch bản / tấn công
    def head(self, title: str) -> Step:
        return self.log(title, level="head")

    def note(self, title: str, value: object = None) -> Step:
        return self.log(title, value=value)

    def ok(self, title: str, value: object = None) -> Step:
        return self.log(title, value=value, level="ok")

    def bad(self, title: str, value: object = None) -> Step:
        return self.log(title, value=value, level="bad")

    def table(self, title: str, headers: Sequence[str], rows: Sequence[Sequence[object]],
              formula: str | None = None) -> Step:
        return self.log(title, formula, table=(headers, rows))

    def tables(self) -> list[Step]:
        return [s for s in self.steps if s.table]

    def clear(self) -> None:
        self.steps.clear()

    def to_text(self) -> str:
        return "\n".join(s.to_text() for s in self.steps)

    def __iter__(self) -> Iterator[Step]:
        return iter(self.steps)

    def __len__(self) -> int:
        return len(self.steps)
