"""Kịch bản sN_*: chứng minh một thuộc tính an toàn khi hệ chữ ký được dùng ĐÚNG (kỳ vọng valid == True).

Mỗi module có `run(logger=None, bits=...) -> ScenarioResult`. REGISTRY liệt kê theo đúng thứ tự số,
dùng cho GUI, CLI và thứ tự chương mục trong báo cáo.
"""
from __future__ import annotations

import importlib
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType

SAMPLE_DIR = Path(__file__).resolve().parents[1] / "sample"


@dataclass
class ScenarioResult:
    name: str
    valid: bool
    summary: str
    details: dict = field(default_factory=dict)


REGISTRY: tuple[tuple[str, str], ...] = (
    ("s1_authentication", "S1: Chứng thực nguồn gốc"),
    ("s2_integrity_tamper", "S2: Toàn vẹn: sửa 1 byte → FAIL"),
    ("s3_non_repudiation_contract", "S3: Chống chối bỏ hợp đồng (CA + timestamp + trọng tài)"),
    ("s4_key_compromise", "S4: Lộ khoá → thu hồi → timestamp phân định"),
    ("s5_hmac_vs_signature", "S5: HMAC không chống chối bỏ được"),
    ("s6_sign_then_encrypt", "S6: Ký rồi mã hoá (phong bì số)"),
)


def load(module_name: str) -> ModuleType:
    return importlib.import_module(f"scenarios.{module_name}")


def sample_bytes(relative: str, fallback: bytes) -> bytes:
    """Đọc tệp mẫu trong sample/ (nhị phân); thiếu tệp thì dùng nội dung dự phòng."""
    path = SAMPLE_DIR / relative
    return path.read_bytes() if path.is_file() else fallback
