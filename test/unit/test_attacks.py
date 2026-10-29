"""Mỗi tấn công a1 → a8: success == True ở cấu hình yếu, success == False khi bật phòng chống."""
import pytest

from attacks import REGISTRY, load
from core.step_logger import StepLogger

FAST = {
    "a4_small_e_attack": {"bits": 2048},
    "a5_factorization": {},
}
FAST_DEFENDED = {
    "a4_small_e_attack": {"bits": 2048},
    "a5_factorization": {"bits": 512, "max_steps": 20_000},
}


def _run(name: str, defended: bool, **kw):
    log = StepLogger()
    result = load(name).run(log, defended=defended, **kw)
    return result, log


def test_registry_order():
    assert [m for m, _ in REGISTRY] == [f"a{i}_" + m.split("_", 1)[1] for i, (m, _) in enumerate(REGISTRY, 1)]
    assert len(REGISTRY) == 8


@pytest.mark.parametrize("name", [m for m, _ in REGISTRY])
def test_attack_succeeds_when_weak(name):
    result, log = _run(name, False, **FAST.get(name, {}))
    assert result.success, log.to_text()


@pytest.mark.parametrize("name", [m for m, _ in REGISTRY])
def test_attack_fails_when_defended(name):
    result, log = _run(name, True, **FAST_DEFENDED.get(name, {}))
    assert not result.success, log.to_text()


def test_a3_hash_collision():
    r, _ = _run("a3_hash_collision", False)
    assert r.details["hashes"] < 2 ** 12


@pytest.mark.slow
def test_a4_small_e_attack_3072():
    r, log = _run("a4_small_e_attack", False, bits=3072)
    assert r.success, log.to_text()


@pytest.mark.slow
def test_a5_factorization_2048_defended():
    r, _ = _run("a5_factorization", True, bits=2048, max_steps=50_000)
    assert not r.success
