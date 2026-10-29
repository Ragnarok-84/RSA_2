from __future__ import annotations

import importlib
from dataclasses import dataclass, field
from types import ModuleType


@dataclass
class AttackResult:
    name: str
    success: bool
    summary: str
    details: dict = field(default_factory=dict)


REGISTRY: tuple[tuple[str, str], ...] = (
    ("a1_no_hash_forgery", "A1: Ký không băm → giả mạo nhờ tính nhân"),
    ("a2_existential_forgery", "A2: Giả mạo tồn tại: chọn s, tính m = s^e"),
    ("a3_hash_collision", "A3: Va chạm hàm băm yếu (nghịch lý ngày sinh)"),
    ("a4_small_e_attack", "A4: e = 3 + kiểm tra lỏng (Bleichenbacher 2006)"),
    ("a5_factorization", "A5: n nhỏ → phân tích (Pollard rho) → lộ d"),
    ("a6_key_substitution_mitm", "A6: Thay khoá công khai (MITM)"),
    ("a7_replay_attack", "A7: Phát lại thông điệp đã ký"),
    ("a8_surreptitious_forwarding", "A8: Chuyển tiếp lén"),
)


def load(module_name: str) -> ModuleType:
    return importlib.import_module(f"attacks.{module_name}")
