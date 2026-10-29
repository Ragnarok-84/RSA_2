"""Tab 3 Ký rồi mã hoá: y = sig_A(h(x)) -> z = e_B(x, y) -> (x, y) = d_B(z) -> ver_A(x, y)."""
import json

import pytest

pytest.importorskip("PySide6")
pytest.importorskip("pytestqt")

from demo.gui.main_window import MainWindow, create_app
from demo.gui.widgets import common


@pytest.fixture
def window(qtbot, monkeypatch):
    create_app(["test"])
    messages = []
    for name in ("show_info", "show_warning", "show_error"):
        monkeypatch.setattr(common, name, lambda *args: messages.append(args))
    w = MainWindow()
    qtbot.addWidget(w)
    w.messages = messages
    return w


def wait(qtbot, window):
    qtbot.waitUntil(lambda: not window.busy, timeout=120_000)


@pytest.mark.parametrize("scheme", ["Mặc định", "PKCS#1 v1.5"])
def test_encrypted_workflow(window, qtbot, tmp_path, scheme):
    tab = window.encrypt_tab
    tab.scheme.setCurrentText(scheme)
    tab.src.set_text("Hợp đồng của Trang gửi Thủy")
    tab.sign_and_seal()
    wait(qtbot, window)
    assert tab.envelope is not None and tab.received is None
    tab.verify()
    assert "Cần giải mã z" in window.messages[-1]
    # Lưu và nạp lại qua đường đọc tệp thực.
    path = tmp_path / "message.enc.json"
    path.write_text(json.dumps(tab.envelope), encoding="utf-8")
    tab._load_encrypted(path)
    tab.decrypt_received()
    wait(qtbot, window)
    assert tab.received is not None
    tab.verify()
    assert tab.badge.text() == "HỢP LỆ"


def test_tampered_z_and_wrong_receiver_key(window, qtbot, tmp_path):
    tab = window.encrypt_tab
    message = bytes(range(256))
    path = tmp_path / "message.bin"
    path.write_bytes(message)
    tab.src.set_file(path)
    tab.sign_and_seal()
    wait(qtbot, window)
    receiver = tab.receiver_priv
    tab._set_receiver_key(window.sign_tab.priv, "sai khoá")
    tab.decrypt_received()
    wait(qtbot, window)
    assert tab.received is None and tab.badge.text() == "GIẢI MÃ THẤT BẠI"
    tab._set_receiver_key(receiver, "đúng khoá")
    tab.decrypt_received()
    wait(qtbot, window)
    assert tab.received[0] == message and "khớp từng byte" in tab.match_label.text()
    tab.verify()
    assert tab.badge.text() == "HỢP LỆ"
    tab.tamper_z()
    tab.decrypt_received()
    wait(qtbot, window)
    assert tab.received is None and tab.badge.text() == "GIẢI MÃ THẤT BẠI"


def test_save_reload_envelope_and_receiver_key(window, qtbot, tmp_path, monkeypatch):
    from core.key_io import load_private_key
    from PySide6.QtWidgets import QFileDialog
    tab = window.encrypt_tab
    tab.src.set_text("Lưu bản mã và khoá")
    tab.sign_and_seal()
    wait(qtbot, window)
    key_path = tmp_path / "thuy.json"
    envelope_path = tmp_path / "message.enc.json"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *a: (str(key_path), ""))
    tab.save_receiver_key()
    assert load_private_key(key_path) == tab.receiver_priv
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *a: (str(envelope_path), ""))
    tab.save_encrypted()
    tab._load_encrypted(envelope_path)
    tab.decrypt_received()
    wait(qtbot, window)
    tab.verify()
    assert tab.badge.text() == "HỢP LỆ"


def test_missing_key_and_message_limit(window):
    tab = window.encrypt_tab
    tab.src.set_text("x" * (16 * 1024 + 1))
    tab.sign_and_seal()
    assert not window.busy
    assert tab.envelope is None
    assert window.messages[-1][1] == "Không mã hoá được"
    tab.receiver_pub = None
    tab.src.set_text("Thông điệp")
    tab.sign_and_seal()
    assert window.messages[-1][1] == "Thiếu khoá Thủy"


def test_forwarding_button_runs_a8(window, qtbot):
    tab = window.encrypt_tab
    tab.show_forwarding()
    wait(qtbot, window)
    assert window.tabs.currentWidget() is window.attacks_tab
    assert "TẤN CÔNG" in window.attacks_tab.badge.text()
