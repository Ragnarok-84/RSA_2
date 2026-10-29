"""Tấn công aN_*: chỉ ra hệ chữ ký bị phá khi bỏ đi một thành phần.

Mỗi module có `run(logger=None, defended=False, ...) -> AttackResult`:
  - defended=False (cấu hình yếu)  → kỳ vọng success == True;
  - defended=True  (bật phòng chống) → kỳ vọng success == False.
Docstring mỗi module nêu: mục tiêu, điều kiện tấn công, cách phòng chống.
"""
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
    ("a6_crt_fault_attack", "A6: Lỗi khi ký CRT → lộ p, q"),
    ("a7_key_substitution_mitm", "A7: Thay khoá công khai (MITM)"),
    ("a8_replay_attack", "A8: Phát lại thông điệp đã ký"),
    ("a9_surreptitious_forwarding", "A9: Chuyển tiếp lén"),
)


def load(module_name: str) -> ModuleType:
    return importlib.import_module(f"attacks.{module_name}")
