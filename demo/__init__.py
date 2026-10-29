"""Giao diện người dùng (CLI, GUI PySide6, benchmark). Không chứa logic mật mã: chỉ gọi core/, pki/, attacks/,
scenarios/ và test/report.py."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "sample"
REPORT_DIR = ROOT / "docs" / "report"
