"""Tiêu chí nghiệm thu về ràng buộc: lõi tự cài, không dùng thư viện mật mã / pow built-in, tách lớp đúng."""
import ast
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
CORE_DIRS = ("core", "pki", "attacks", "scenarios")
FORBIDDEN_MODULES = {"hashlib", "hmac", "cryptography", "Crypto", "pycryptodome", "rsa", "gmpy2", "OpenSSL", "random"}
ALLOWED = {("scenarios/s6_sign_then_encrypt.py", "cryptography")}


def _py_files(*dirs: str):
    for d in dirs:
        yield from sorted((ROOT / d).rglob("*.py"))


def _imports(path: Path):
    tree = ast.parse(path.read_bytes().decode("utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                yield a.name.split(".")[0], node
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            yield node.module.split(".")[0], node


@pytest.mark.parametrize("path", list(_py_files(*CORE_DIRS)), ids=lambda p: p.relative_to(ROOT).as_posix())
def test_no_forbidden_imports(path):
    rel = path.relative_to(ROOT).as_posix()
    bad = {m for m, _ in _imports(path) if m in FORBIDDEN_MODULES and (rel, m) not in ALLOWED}
    assert not bad, f"{rel} import {bad}"


@pytest.mark.parametrize("path", list(_py_files(*CORE_DIRS)), ids=lambda p: p.relative_to(ROOT).as_posix())
def test_no_builtin_pow_and_no_print(path):
    tree = ast.parse(path.read_bytes().decode("utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id != "pow", f"{path.name}:{node.lineno} dùng pow() built-in"
            assert node.func.id != "print", f"{path.name}:{node.lineno} gọi print (chỉ ghi vào StepLogger)"


def test_core_does_not_import_upper_layers():
    for path in _py_files("core"):
        bad = {m for m, _ in _imports(path) if m in ("pki", "attacks", "scenarios", "demo", "test")}
        assert not bad, f"{path.name} import {bad}"


def test_demo_has_no_crypto_logic():
    for path in _py_files("demo"):
        bad = {m for m, _ in _imports(path) if m in FORBIDDEN_MODULES - {"random"}}
        assert not bad, f"{path.relative_to(ROOT)} import {bad}"
        assert not re.search(r"\bpow\(", path.read_bytes().decode("utf-8")), path.name
