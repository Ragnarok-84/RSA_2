"""Chạy tác vụ chậm (sinh khoá, băm tệp lớn, benchmark, tấn công e = 3) ngoài luồng giao diện.

QThreadPool + QRunnable; kết quả / lỗi / tiến độ báo về luồng giao diện qua Signal.
"""
from __future__ import annotations

import inspect
import traceback
from typing import Callable

from PySide6.QtCore import QObject, QRunnable, Signal


class WorkerSignals(QObject):
    finished = Signal(object)
    error = Signal(str, str)              # thông báo, traceback
    progress = Signal(int, int)           # đã xong, tổng
    message = Signal(str)


class Worker(QRunnable):
    """Chạy fn(). Nếu fn có tham số `progress` thì nhận progress(done, total);
    nếu có tham số `report` thì nhận report(text) để hiện trên thanh trạng thái."""

    def __init__(self, fn: Callable) -> None:
        super().__init__()
        self.fn = fn
        self.signals = WorkerSignals()
        self.setAutoDelete(True)

    def run(self) -> None:
        kwargs = {}
        try:
            params = inspect.signature(self.fn).parameters
        except (TypeError, ValueError):
            params = {}
        if "progress" in params:
            kwargs["progress"] = lambda done, total: self.signals.progress.emit(int(done), int(total))
        if "report" in params:
            kwargs["report"] = self.signals.message.emit
        try:
            result = self.fn(**kwargs)
        except Exception as err:
            self.signals.error.emit(f"{type(err).__name__}: {err}", traceback.format_exc())
        else:
            self.signals.finished.emit(result)
