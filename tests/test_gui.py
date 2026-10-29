import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")    # chạy được cả khi không có màn hình (máy chủ CI)

try:
    from PySide6.QtWidgets import QApplication
    from demo.gui import widgets
    from demo.gui.run import MainWindow, create_app
except ImportError:                     # chưa cài PySide6
    widgets = None

from core.rsa_math import generate_keypair


@unittest.skipIf(widgets is None, "chưa cài PySide6 (pip install -r requirements-gui.txt)")
class TestGui(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        create_app()
        cls.app = MainWindow(autostart=False)
        cls.dialogs = []
        for name in ("show_info", "show_warning", "show_error"):
            setattr(widgets, name, lambda *a, **k: cls.dialogs.append(a))
        for n in widgets.PEOPLE:
            cls.app.keys[n] = generate_keypair(keysize=1024)

    @classmethod
    def tearDownClass(cls):
        cls.app.close()

    def wait(self):
        deadline = time.time() + 120
        while time.time() < deadline:
            QApplication.processEvents()
            self.app._poll()
            if not self.app._busy and self.app._q.empty():
                QApplication.processEvents()
                return
            time.sleep(0.02)
        self.fail("tác vụ nền không kết thúc")

    def test_a_starts_empty(self):              # tên bắt đầu bằng "a" để chạy trước các ca điền dữ liệu
        self.assertEqual(self.app.mini_tab.vars["p"].text(), "")
        self.assertEqual(self.app.key_tab.p.text(), "")
        self.assertEqual(self.app.conf_tab.src.path.text(), "")
        self.assertEqual(self.app.conf_tab.src.text.toPlainText(), "")
        self.assertEqual(self.app.sign_tab.result.text(), "")

    def test_empty_input_warns(self):
        mt = self.app.mini_tab
        mt.compute()
        self.assertIn("Hãy nhập đủ p, q, e, M", mt.out.text())
        before = len(self.dialogs)
        self.assertIsNone(self.app.sign_tab.src.read())
        self.assertEqual(len(self.dialogs), before + 1)

    def test_mini_tab_class_example(self):
        mt = self.app.mini_tab
        for k, v in (("p", "17"), ("q", "11"), ("e", "7"), ("M", "88")):
            mt.vars[k].setText(v)
        mt.compute()
        out = mt.out.text()
        self.assertIn("=> C = 11", out)
        self.assertIn("=> S = 11", out)

    def test_key_table_lists_people(self):
        kt = self.app.key_tab
        kt.refresh()
        self.assertEqual(kt.table.rowCount(), len(widgets.PEOPLE))
        kt.table.selectRow(2)
        self.assertEqual(kt.who.currentData(), widgets.PEOPLE[2])
        self.assertIn(f"Khóa của {widgets.PEOPLE[2]}", kt.out.text())

    def test_small_manual_key_keeps_current_keys(self):
        kt = self.app.key_tab
        before = dict(self.app.keys)
        kt.who.setCurrentText("Tất cả")
        for w, v in ((kt.p, "17"), (kt.q, "11"), (kt.e, "7")):
            w.setText(v)
        kt.gen_manual()
        self.assertEqual(self.app.keys, before)
        self.assertIn("KHÔNG thay khóa đang dùng", kt.out.text())

    def test_startup_generates_keys_for_everyone(self):
        win = MainWindow(autostart=True)
        deadline = time.time() + 120
        while (win._busy or not win._q.empty()) and time.time() < deadline:
            QApplication.processEvents()
            win._poll()
            time.sleep(0.02)
        self.assertEqual(set(win.keys), set(widgets.PEOPLE))
        self.assertTrue(all(pub[1].bit_length() >= 2047 for _, pub in win.keys.values()))
        win.close()

    def test_sign_then_tamper(self):
        st = self.app.sign_tab
        st.src.text.setPlainText("Hợp đồng số 01: Thu Trang bán lô hàng A cho Thu Thủy.")
        st.sign(); self.wait()
        st.verify(); self.wait()
        self.assertEqual(st.result.text(), "CHỮ KÝ HỢP LỆ")
        st.recv.setPlainText(st.recv.toPlainText() + "!")
        st.verify(); self.wait()
        self.assertEqual(st.result.text(), "CHỮ KÝ KHÔNG HỢP LỆ")

    def test_seal_open_and_eve_blocked(self):
        ct = self.app.conf_tab
        ct.src.text.setPlainText("Mã khóa két sắt: 7-3-9-1.")
        self.dialogs.clear()
        ct.seal(); self.wait()
        ct.bob_open(); self.wait()
        ct.eve_open(); self.wait()
        log = ct.log.text()
        self.assertIn("giống hệt bản gốc: True", log)
        self.assertIn("(tấn công bị chặn)", log)
        self.assertEqual(self.dialogs, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
