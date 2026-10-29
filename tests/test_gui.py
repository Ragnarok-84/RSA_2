# Tệp: tests/test_gui.py   [bổ sung - Báo cáo 6.1: giao diện đồ họa dựng được và gọi đúng thuật toán]
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import tkinter as tk
    from tkinter import messagebox
    from demo import gui
except ImportError:                     # Python không kèm Tk
    gui = None

from core.rsa_math import generate_keypair


@unittest.skipIf(gui is None, "Python này không có tkinter")
class TestGui(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            cls.app = gui.App(autostart=False)
        except tk.TclError as err:      # không có màn hình (máy chủ CI)
            raise unittest.SkipTest(f"không mở được cửa sổ: {err}")
        cls.app.withdraw()
        cls.dialogs = []
        for name in ("showinfo", "showwarning", "showerror"):
            setattr(messagebox, name, lambda *a, **k: cls.dialogs.append(a))
        for n in gui.PEOPLE:
            cls.app.keys[n] = generate_keypair(keysize=1024)

    @classmethod
    def tearDownClass(cls):
        cls.app.destroy()

    def wait(self):
        deadline = time.time() + 120
        while time.time() < deadline:
            self.app.update()
            if not self.app._busy and self.app._q.empty():
                self.app.update()
                return
            time.sleep(0.02)
        self.fail("tác vụ nền không kết thúc")

    def test_a_starts_empty(self):              # tên bắt đầu bằng "a" để chạy trước các ca điền dữ liệu
        self.assertEqual(self.app.mini_tab.vars["p"].get(), "")
        self.assertEqual(self.app.key_tab.p.get(), "")
        self.assertEqual(self.app.conf_tab.src.path.get(), "")
        self.assertEqual(self.app.conf_tab.src.text.get("1.0", "end-1c"), "")
        self.assertEqual(self.app.sign_tab.result.cget("text"), "")

    def test_empty_input_warns(self):
        mt = self.app.mini_tab
        mt.compute()
        self.assertIn("Hãy nhập đủ p, q, e, M", mt.out.get("1.0", "end"))
        before = len(self.dialogs)
        self.assertIsNone(self.app.sign_tab.src.read())
        self.assertEqual(len(self.dialogs), before + 1)

    def test_mini_tab_class_example(self):
        mt = self.app.mini_tab
        for k, v in (("p", "17"), ("q", "11"), ("e", "7"), ("M", "88")):
            mt.vars[k].set(v)
        mt.compute()
        out = mt.out.get("1.0", "end")
        self.assertIn("=> C = 11", out)
        self.assertIn("=> S = 11", out)

    def test_sign_then_tamper(self):
        st = self.app.sign_tab
        st.src.text.insert("1.0", "Hợp đồng số 01: Thu Trang bán lô hàng A cho Thu Thủy.")
        st.sign(); self.wait()
        st.verify(); self.wait()
        self.assertEqual(st.result.cget("text"), "CHỮ KÝ HỢP LỆ")
        st.recv.insert("end", "!")
        st.verify(); self.wait()
        self.assertEqual(st.result.cget("text"), "CHỮ KÝ KHÔNG HỢP LỆ")

    def test_seal_open_and_eve_blocked(self):
        ct = self.app.conf_tab
        ct.src.text.insert("1.0", "Mã khóa két sắt: 7-3-9-1.")
        self.dialogs.clear()
        ct.seal(); self.wait()
        ct.bob_open(); self.wait()
        ct.eve_open(); self.wait()
        log = ct.log.get("1.0", "end")
        self.assertIn("giống hệt bản gốc: True", log)
        self.assertIn("(tấn công bị chặn)", log)
        self.assertEqual(self.dialogs, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
