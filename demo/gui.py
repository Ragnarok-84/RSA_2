"""
demo/gui.py
[Báo cáo 6.1 - Kịch bản demo; 6.2 - Dữ liệu thật]
Giao diện đồ họa (Tkinter - thư viện chuẩn của Python) cho hệ chữ ký điện tử RSA.
Giao diện chỉ gọi các module trong core/, pki/, scenarios/, attacks/, demo/ — không chứa thuật toán.

    python demo/gui.py

Các tab:
  1. Khóa              : sinh / lưu / nạp khóa của Alice (ký), Bob (mã hóa), Eve, Charlie
  2. Ký & Kiểm tra     : ký văn bản hoặc tệp (PKCS#1 v1.5 / PSS), sửa nội dung hoặc chữ ký rồi kiểm tra
  3. Bảo mật           : ký rồi mã hóa gửi Bob, các tình huống tấn công của Eve
  4. Tính tay          : RSA thu nhỏ với p, q, e, M tự nhập, in từng bước bình phương và nhân
  5. Kịch bản & Tấn công: chạy S1-S6 và các tấn công minh họa
  6. Kiểm thử          : đối chiếu chuẩn, benchmark, hiệu ứng thác lũ, bộ test
"""
import contextlib
import io
import json
import os
import queue
import subprocess
import sys
import threading
import traceback
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
from tkinter.scrolledtext import ScrolledText

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)

from core.rsa_math import generate_keypair, explain_keygen, byte_length, mod_exp
from core.sha256 import hash_sha256
from core import rsa_full, rsa_mini, padding
from core import secure_message as sm
from scenarios.s1_authentication import run_scenario_s1
from scenarios.s2_nonrepudiation import run_scenario_s2
from scenarios.s3_revocation import run_scenario_s3
from scenarios.s4_replay import run_scenario_s4
from scenarios.s5_key_substitution import run_scenario_s5
from scenarios.s6_confidentiality import run_scenario_s6
from scenarios.run_all import run_all
from attacks import small_n, forgery_no_padding, bleichenbacher_e3, confidentiality
from demo import avalanche, file_signer

# Phông chữ theo hệ điều hành (macOS không có Consolas / Segoe UI)
if sys.platform == "darwin":
    MONO, UI = ("Menlo", 12), "Helvetica Neue"
elif sys.platform.startswith("win"):
    MONO, UI = ("Consolas", 10), "Segoe UI"
else:
    MONO, UI = ("DejaVu Sans Mono", 10), "DejaVu Sans"
UI_SIZE = 13 if sys.platform == "darwin" else 10
GREEN, RED, BLUE, GREY = "#1b7f3b", "#c62828", "#1f4e9c", "#666666"
PEOPLE = ("Alice", "Bob", "Eve", "Charlie")
ROLES = {"Alice": "người ký", "Bob": "người nhận (mã hóa)", "Eve": "kẻ tấn công", "Charlie": "người thứ ba"}
DEFAULT_TEXT = "Hợp đồng số 2026/HĐ-001: Alice đồng ý bán lô hàng A cho Bob, giá 100.000.000 VNĐ."


def short_int(x, head=28, tail=12):
    h = format(x, "x")
    body = h if len(h) <= head + tail + 3 else f"{h[:head]}…{h[-tail:]}"
    return f"0x{body}  ({x.bit_length()} bit)"


def parse_int(text):
    """Đọc số nguyên từ ô nhập (chấp nhận hex có/không có 0x hoặc thập phân)."""
    t = "".join(text.split()).lower()
    if t.startswith("0x"):
        return int(t[2:], 16)
    return int(t, 16) if any(c in "abcdef" for c in t) else int(t)


# ====================================================================== #
# Thành phần dùng chung
# ====================================================================== #
class OutputBox(ScrolledText):
    """Ô hiển thị kết quả: tự tô màu dòng có / / SUCCESS / FAILED."""

    def __init__(self, master, **kw):
        super().__init__(master, font=MONO, wrap="word", **kw)
        self.tag_config("ok", foreground=GREEN)
        self.tag_config("bad", foreground=RED)
        self.tag_config("head", foreground=BLUE, font=(MONO[0], MONO[1], "bold"))
        self.tag_config("dim", foreground=GREY)
        self._buf = ""
        self.configure(state="disabled")

    @staticmethod
    def _tag_for(line):
        s = line.rstrip()
        if s.startswith("[FAILED]") or "LỆCH" in s or "Traceback" in s or s.endswith(("... FAIL", "... ERROR")) \
                or "| LỖI" in s:
            return "bad"
        if s.startswith("[SUCCESS]") or s.endswith("KHỚP") or s.endswith("... ok") or "| ĐẠT" in s \
                or s.startswith("OK"):
            return "ok"
        if line.startswith("===") or line.startswith("---") or "KỊCH BẢN" in line:
            return "head"
        return None

    def append(self, text, tag=None):
        self.configure(state="normal")
        for line in text.splitlines(keepends=True):
            self.insert("end", line, tag or self._tag_for(line))
        self.see("end")
        self.configure(state="disabled")

    def stream(self, chunk):
        """Nhận từng mẩu stdout, chỉ chèn khi đủ dòng để tô màu đúng."""
        self._buf += chunk
        if "\n" in self._buf:
            done, self._buf = self._buf.rsplit("\n", 1)
            self.append(done + "\n")

    def flush(self):
        if self._buf:
            self.append(self._buf + "\n")
            self._buf = ""

    def clear(self):
        self.configure(state="normal")
        self.delete("1.0", "end")
        self.configure(state="disabled")


class _QueueWriter(io.TextIOBase):
    def __init__(self, q, target):
        self.q, self.target = q, target

    def write(self, s):
        if self.target is not None:
            self.q.put(("out", self.target, s))
        return len(s)


def labeled_entry(parent, text, width=12, default=""):
    frame = ttk.Frame(parent)
    ttk.Label(frame, text=text).pack(side="left")
    var = tk.StringVar(value=default)
    ttk.Entry(frame, textvariable=var, width=width).pack(side="left", padx=(4, 10))
    return frame, var


# ====================================================================== #
# Ứng dụng chính
# ====================================================================== #
class App(tk.Tk):
    def __init__(self, autostart=True):
        super().__init__()
        self.title("Hệ chữ ký điện tử RSA — Demo An toàn bảo mật thông tin")
        self.geometry("1180x760")
        self.minsize(960, 640)
        self.keys = {}                          # tên -> (khóa riêng, khóa công khai)
        self._q = queue.Queue()
        self._busy = False

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=6, pady=(6, 0))
        self.key_tab = KeyTab(self, nb)
        self.sign_tab = SignTab(self, nb)
        self.conf_tab = ConfidentialityTab(self, nb)
        self.mini_tab = MiniTab(self, nb)
        self.scen_tab = ScenarioTab(self, nb)
        self.tool_tab = ToolsTab(self, nb)
        for tab, name in ((self.key_tab, " 1. Khóa "), (self.sign_tab, " 2. Ký & Kiểm tra "),
                          (self.conf_tab, " 3. Bảo mật (ký rồi mã hóa) "), (self.mini_tab, " 4. Tính tay "),
                          (self.scen_tab, " 5. Kịch bản & Tấn công "), (self.tool_tab, " 6. Kiểm thử & Đánh giá ")):
            nb.add(tab, text=name)

        bar = ttk.Frame(self)
        bar.pack(fill="x", padx=6, pady=4)
        self.status = tk.StringVar(value="Sẵn sàng")
        ttk.Label(bar, textvariable=self.status).pack(side="left")
        self.progress = ttk.Progressbar(bar, mode="indeterminate", length=180)
        self.progress.pack(side="right")

        self.after(50, self._poll)
        if autostart:
            self.generate_keys(PEOPLE, 1024, initial=True)

    # ---------- chạy tác vụ nền ----------
    def run(self, fn, on_done=None, output=None, status="Đang xử lý..."):
        """Chạy fn() ở luồng nền; stdout của fn được chuyển vào ô `output`; on_done(kết quả) chạy ở luồng giao diện."""
        if self._busy:
            messagebox.showinfo("Đang bận", "Đang chạy một tác vụ khác, vui lòng đợi.")
            return
        self._busy = True
        self.status.set(status)
        self.progress.start(12)

        def worker():
            writer = _QueueWriter(self._q, output)
            try:
                with contextlib.redirect_stdout(writer):
                    result = fn()
                self._q.put(("done", on_done, result, output))
            except Exception as err:
                self._q.put(("error", err, traceback.format_exc(), output))

        threading.Thread(target=worker, daemon=True).start()

    def _poll(self):
        try:
            while True:
                item = self._q.get_nowait()
                kind = item[0]
                if kind == "out":
                    item[1].stream(item[2])
                elif kind in ("done", "error"):
                    self._busy = False
                    self.progress.stop()
                    output = item[3]
                    if output is not None:
                        output.flush()
                    if kind == "done":
                        self.status.set("Hoàn tất")
                        if item[1]:
                            item[1](item[2])
                    else:
                        self.status.set(f"Lỗi: {item[1]}")
                        if output is not None:
                            output.append(f"[Lỗi] {type(item[1]).__name__}: {item[1]}\n", "bad")
                        else:
                            messagebox.showerror("Lỗi", f"{type(item[1]).__name__}: {item[1]}")
        except queue.Empty:
            pass
        self.after(50, self._poll)

    # ---------- khóa ----------
    def generate_keys(self, names, bits, initial=False):
        def job():
            return {n: generate_keypair(keysize=bits) for n in names}

        def done(new):
            self.keys.update(new)
            self.key_tab.refresh()
            self.status.set(f"Đã sinh khóa {bits} bit cho: {', '.join(names)}")

        self.run(job, done, status=f"Đang sinh khóa {bits} bit cho {', '.join(names)}..."
                 + (" (khóa mặc định khi khởi động)" if initial else ""))

    def key(self, name, min_bits=0, purpose=""):
        pair = self.keys.get(name)
        if pair is None:
            messagebox.showwarning("Thiếu khóa", f"Chưa có khóa của {name}. Hãy sinh khóa ở tab 1.")
            return None
        if pair[1][1].bit_length() < min_bits:
            messagebox.showwarning("Khóa quá ngắn",
                                   f"Khóa của {name} chỉ {pair[1][1].bit_length()} bit; {purpose} cần >= {min_bits} bit.\n"
                                   "Hãy sinh lại khóa lớn hơn ở tab 1 (bản số nhỏ dùng tab 4. Tính tay).")
            return None
        return pair


# ====================================================================== #
# Tab 1: Khóa
# ====================================================================== #
class KeyTab(ttk.Frame):
    def __init__(self, app, parent):
        super().__init__(parent, padding=8)
        self.app = app

        ctl = ttk.LabelFrame(self, text="Sinh khóa", padding=8)
        ctl.pack(fill="x")
        ttk.Label(ctl, text="Người:").pack(side="left")
        self.who = ttk.Combobox(ctl, values=PEOPLE + ("Tất cả",), width=10, state="readonly")
        self.who.set("Tất cả")
        self.who.pack(side="left", padx=(4, 12))
        ttk.Label(ctl, text="Độ dài khóa:").pack(side="left")
        self.bits = ttk.Combobox(ctl, values=("512", "1024", "2048", "3072"), width=6, state="readonly")
        self.bits.set("2048")
        self.bits.pack(side="left", padx=(4, 12))
        ttk.Button(ctl, text="Sinh khóa ngẫu nhiên", command=self.gen_random).pack(side="left")
        ttk.Separator(ctl, orient="vertical").pack(side="left", fill="y", padx=12)
        f, self.p = labeled_entry(ctl, "p", 8, "61"); f.pack(side="left")
        f, self.q = labeled_entry(ctl, "q", 8, "53"); f.pack(side="left")
        f, self.e = labeled_entry(ctl, "e", 8, "17"); f.pack(side="left")
        ttk.Button(ctl, text="Sinh từ p, q, e", command=self.gen_manual).pack(side="left")

        io_ = ttk.Frame(self)
        io_.pack(fill="x", pady=6)
        ttk.Button(io_, text="Lưu khóa của người đang chọn...", command=self.save).pack(side="left")
        ttk.Button(io_, text="Nạp khóa riêng từ tệp JSON...", command=self.load).pack(side="left", padx=6)
        self.protect = tk.BooleanVar(value=False)
        ttk.Checkbutton(io_, text="Mã hóa khóa riêng bằng mật khẩu khi lưu (PBKDF2)",
                        variable=self.protect).pack(side="left", padx=6)

        cols = ("role", "bits", "e", "N")
        self.tree = ttk.Treeview(self, columns=cols, height=5)
        self.tree.heading("#0", text="Người")
        for c, t, w in (("role", "Vai trò", 150), ("bits", "Số bit N", 80), ("e", "e", 80), ("N", "N (hex)", 560)):
            self.tree.heading(c, text=t)
            self.tree.column(c, width=w, anchor="w")
        self.tree.column("#0", width=90)
        self.tree.pack(fill="x")
        self.tree.bind("<<TreeviewSelect>>", self.show_detail)

        self.out = OutputBox(self, height=16)
        self.out.pack(fill="both", expand=True, pady=(6, 0))
        self.out.append("Khóa mặc định 1024 bit được sinh tự động khi khởi động. Chọn một dòng để xem chi tiết.\n"
                        "Lưu ý: N nhỏ (tự nhập p, q) chỉ dùng được ở tab 4 — đệm PKCS#1/PSS/OAEP cần N >= 528-1024 bit.\n",
                        "dim")

    def _targets(self):
        return PEOPLE if self.who.get() == "Tất cả" else (self.who.get(),)

    def gen_random(self):
        self.app.generate_keys(self._targets(), int(self.bits.get()))

    def gen_manual(self):
        try:
            p, q, e = int(self.p.get()), int(self.q.get()), int(self.e.get())
            pair = generate_keypair(p=p, q=q, e=e)
        except ValueError as err:
            messagebox.showerror("Tham số không hợp lệ", str(err))
            return
        for n in self._targets():
            self.app.keys[n] = pair
        self.refresh()
        self.out.clear()
        self.out.append(f"=== Sinh khóa từ p={p}, q={q}, e={e} ===\n")
        self.out.append("\n".join(explain_keygen(p, q, e)) + "\n")

    def refresh(self):
        self.tree.delete(*self.tree.get_children())
        for n in PEOPLE:
            if n in self.app.keys:
                (_, N), (e, _) = self.app.keys[n]
                self.tree.insert("", "end", iid=n, text=n, values=(ROLES[n], N.bit_length(), e, short_int(N, 60, 16)))

    def show_detail(self, _=None):
        sel = self.tree.selection()
        if not sel:
            return
        n = sel[0]
        self.who.set(n)
        (d, N), (e, _) = self.app.keys[n]
        self.out.clear()
        self.out.append(f"=== Khóa của {n} ({ROLES[n]}) ===\n")
        self.out.append(f"Khóa công khai (e, N):\n  e = {e}\n  N = {N}\n\n")
        self.out.append(f"Khóa riêng d (bí mật, chỉ {n} giữ):\n  d = {d}\n", "dim")
        self.out.append(f"\nKiểm tra: (2^e)^d mod N = 2 ? {mod_exp(mod_exp(2, e, N), d, N) == 2}\n")

    def save(self):
        n = self.who.get()
        if n not in self.app.keys:
            messagebox.showinfo("Chọn người", "Chọn một người (không phải 'Tất cả') đã có khóa.")
            return
        folder = filedialog.askdirectory(title=f"Chọn thư mục lưu khóa của {n}")
        if not folder:
            return
        pw = None
        if self.protect.get():
            pw = simpledialog.askstring("Mật khẩu", "Đặt mật khẩu bảo vệ khóa riêng:", show="*", parent=self)
            if not pw:
                return
        usage = "encryption" if n == "Bob" else "signature"
        priv, pub = self.app.keys[n]
        paths = file_signer.save_keypair(n.lower(), priv, pub, folder, usage, pw)
        self.out.append(f"Đã lưu: {paths[0]}\n       {paths[1]}\n", "ok")

    def load(self):
        path = filedialog.askopenfilename(title="Chọn tệp khóa riêng (*.private.json)",
                                          filetypes=[("Khóa riêng", "*.private.json"), ("JSON", "*.json")])
        if not path:
            return
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            pw = None
            if "protected" in data:
                pw = simpledialog.askstring("Mật khẩu", "Nhập mật khẩu của khóa riêng:", show="*", parent=self)
                if pw is None:
                    return
            priv = file_signer.load_private_key(path, password=pw)
            pub = (data["e"], priv[1])
        except (ValueError, KeyError, OSError) as err:
            messagebox.showerror("Không nạp được khóa", str(err))
            return
        n = self.who.get() if self.who.get() in PEOPLE else data.get("owner", "Alice").capitalize()
        if n not in PEOPLE:
            n = "Alice"
        self.app.keys[n] = (priv, pub)
        self.refresh()
        self.out.append(f"Đã nạp khóa từ {path} cho {n}\n", "ok")


# ====================================================================== #
# Nguồn dữ liệu: văn bản hoặc tệp
# ====================================================================== #
class DataSource(ttk.Frame):
    """Khung chọn dữ liệu: gõ văn bản hoặc chọn tệp thật."""

    def __init__(self, parent, title, default=DEFAULT_TEXT, height=5):
        super().__init__(parent)
        top = ttk.Frame(self)
        top.pack(fill="x")
        ttk.Label(top, text=title, font=(UI, UI_SIZE, "bold")).pack(side="left")
        self.mode = tk.StringVar(value="text")
        ttk.Radiobutton(top, text="Văn bản", variable=self.mode, value="text", command=self._mode).pack(side="left", padx=8)
        ttk.Radiobutton(top, text="Tệp", variable=self.mode, value="file", command=self._mode).pack(side="left")
        self.path = tk.StringVar(value=file_signer.DEFAULT_SAMPLE)
        self.path_entry = ttk.Entry(top, textvariable=self.path, width=60)
        self.browse_btn = ttk.Button(top, text="Chọn tệp...", command=self._browse)
        self.text = tk.Text(self, height=height, width=40, font=MONO, wrap="word")
        self.text.insert("1.0", default)
        self.text.pack(fill="x", pady=4)
        self._mode()

    def _mode(self):
        if self.mode.get() == "file":
            self.path_entry.pack(side="left", padx=8)
            self.browse_btn.pack(side="left")
            self.text.configure(state="disabled", background="#eeeeee")
        else:
            self.path_entry.pack_forget()
            self.browse_btn.pack_forget()
            self.text.configure(state="normal", background="white")

    def _browse(self):
        p = filedialog.askopenfilename(title="Chọn tệp", initialdir=os.path.join(ROOT, "samples"))
        if p:
            self.path.set(p)

    def get(self):
        """:return: (dữ liệu bytes, tên tệp hoặc None)"""
        if self.mode.get() == "file":
            with open(self.path.get(), "rb") as f:
                return f.read(), os.path.basename(self.path.get())
        return self.text.get("1.0", "end-1c").encode("utf-8"), None


# ====================================================================== #
# Tab 2: Ký & Kiểm tra
# ====================================================================== #
class SignTab(ttk.Frame):
    def __init__(self, app, parent):
        super().__init__(parent, padding=8)
        self.app = app
        self.recv_data = None

        left = ttk.LabelFrame(self, text="BÊN KÝ — Alice (dùng khóa riêng)", padding=8)
        left.pack(side="left", fill="both", expand=True)
        self.src = DataSource(left, "Thông điệp cần ký")
        self.src.pack(fill="x")
        row = ttk.Frame(left)
        row.pack(fill="x", pady=4)
        ttk.Label(row, text="Lược đồ đệm:").pack(side="left")
        self.scheme = ttk.Combobox(row, values=("PKCS#1 v1.5", "PSS"), width=12, state="readonly")
        self.scheme.set("PKCS#1 v1.5")
        self.scheme.pack(side="left", padx=6)
        ttk.Button(row, text="Ký", command=self.sign).pack(side="left", padx=6)

        ttk.Label(left, text="[1] SHA-256(M)").pack(anchor="w", pady=(8, 0))
        self.hash_var = tk.StringVar()
        ttk.Entry(left, textvariable=self.hash_var, font=MONO, state="readonly").pack(fill="x")
        ttk.Label(left, text="[2] Khối đệm EM (đưa vào lũy thừa)").pack(anchor="w", pady=(8, 0))
        self.em = tk.Text(left, height=5, width=40, font=MONO, wrap="char", background="#f6f6f6")
        self.em.pack(fill="x")
        ttk.Label(left, text="[3] Chữ ký S = EM^d mod N (hex) — có thể sửa để thử giả mạo").pack(anchor="w", pady=(8, 0))
        self.sig = tk.Text(left, height=5, width=40, font=MONO, wrap="char")
        self.sig.pack(fill="both", expand=True)

        right = ttk.LabelFrame(self, text="BÊN NHẬN — Bob (dùng khóa công khai của Alice)", padding=8)
        right.pack(side="left", fill="both", expand=True, padx=(8, 0))
        ttk.Label(right, text="Thông điệp nhận được (sửa thử rồi bấm Kiểm tra)",
                  font=(UI, UI_SIZE, "bold")).pack(anchor="w")
        self.recv = tk.Text(right, height=6, width=40, font=MONO, wrap="word")
        self.recv.pack(fill="x", pady=4)
        row2 = ttk.Frame(right)
        row2.pack(fill="x")
        ttk.Button(row2, text="Kiểm tra chữ ký", command=self.verify).pack(side="left")
        self.flip_btn = ttk.Button(row2, text="Eve đổi 1 bit của tệp", command=self.flip_bit, state="disabled")
        self.flip_btn.pack(side="left", padx=6)
        ttk.Button(row2, text="Thử khóa của Eve", command=lambda: self.verify("Eve")).pack(side="left")
        self.result = tk.Label(right, text="Chưa kiểm tra", font=(UI, UI_SIZE + 5, "bold"), fg=GREY, pady=10)
        self.result.pack(fill="x", pady=8)
        self.detail = OutputBox(right, height=14, width=40)
        self.detail.pack(fill="both", expand=True)

    def _scheme(self):
        return "pss" if self.scheme.get() == "PSS" else "pkcs1v15"

    def sign(self):
        pair = self.app.key("Alice", 1024 if self._scheme() == "pss" else 512, "Chữ ký có đệm")
        if not pair:
            return
        try:
            data, name = self.src.get()
        except OSError as err:
            messagebox.showerror("Không đọc được tệp", str(err))
            return
        priv, _ = pair
        scheme = self._scheme()

        def job():
            h = hash_sha256(data)
            if scheme == "pkcs1v15":
                em = padding.pkcs1_v15_encode(bytes.fromhex(h), byte_length(priv[1])).hex()
            else:
                em = "(PSS: EM = maskedDB || H || BC, chứa salt ngẫu nhiên nên mỗi lần ký ra khối khác nhau)"
            return h, em, rsa_full.sign_hash(h, priv, scheme)

        def done(res):
            h, em, s = res
            self.hash_var.set(h)
            for w, v in ((self.em, em), (self.sig, format(s, "x"))):
                w.configure(state="normal")
                w.delete("1.0", "end")
                w.insert("1.0", v)
            self.em.configure(state="disabled")
            self.recv_data = data
            self.recv.configure(state="normal")
            self.recv.delete("1.0", "end")
            if name:
                self.recv.insert("1.0", f"[Tệp nhận được: {name}, {len(data):,} byte — dùng nút 'Eve đổi 1 bit' để sửa]")
                self.recv.configure(state="disabled")
                self.flip_btn.configure(state="normal")
            else:
                self.recv.insert("1.0", data.decode("utf-8"))
                self.flip_btn.configure(state="disabled")
            self.result.configure(text="Đã ký — bấm Kiểm tra", fg=BLUE)
            self.detail.clear()
            self.detail.append(f"Alice ký {'tệp ' + name if name else 'văn bản'} ({len(data):,} byte) "
                               f"bằng {self.scheme.get()}, khóa {priv[1].bit_length()} bit.\n")

        self.app.run(job, done, status="Đang băm và ký...")

    def flip_bit(self):
        if self.recv_data:
            b = bytearray(self.recv_data)
            b[len(b) // 2] ^= 0x01
            self.recv_data = bytes(b)
            self.detail.append(f"Eve đổi 1 bit ở byte thứ {len(b) // 2:,} của tệp.\n", "bad")

    def verify(self, signer="Alice"):
        pair = self.app.key(signer)
        if not pair:
            return
        try:
            s = parse_int(self.sig.get("1.0", "end"))
        except ValueError:
            messagebox.showerror("Chữ ký không hợp lệ", "Ô chữ ký phải là số hex.")
            return
        if str(self.recv.cget("state")) == "normal":
            data = self.recv.get("1.0", "end-1c").encode("utf-8")
        else:
            data = self.recv_data or b""
        _, pub = pair
        scheme = self._scheme()

        def job():
            h = hash_sha256(data)
            ok = rsa_full.verify_hash(h, s, pub, scheme)
            recovered = rsa_full.verify_signature(s, pub) if scheme == "pkcs1v15" else None
            return ok, h, recovered

        def done(res):
            ok, h, recovered = res
            self.result.configure(text="CHỮ KÝ HỢP LỆ" if ok else "CHỮ KÝ KHÔNG HỢP LỆ", fg=GREEN if ok else RED)
            self.detail.append(f"\n--- Kiểm tra bằng khóa công khai của {signer} ---\n", "head")
            self.detail.append(f"Băm A (tự tính từ thông điệp nhận) : {h}\n")
            if scheme == "pkcs1v15":
                self.detail.append(f"Băm B (gỡ từ chữ ký S^e mod N)     : {recovered or '(khối đệm sai cấu trúc)'}\n")
            self.detail.append(("Khớp: đúng người ký, nội dung nguyên vẹn.\n" if ok else
                                "Không khớp: nội dung bị sửa, chữ ký bị sửa, hoặc sai người ký.\n"),
                               "ok" if ok else "bad")

        self.app.run(job, done, status="Đang kiểm tra...")


# ====================================================================== #
# Tab 3: Bảo mật — ký rồi mã hóa
# ====================================================================== #
class ConfidentialityTab(ttk.Frame):
    def __init__(self, app, parent):
        super().__init__(parent, padding=8)
        self.app = app
        self.env = None
        self.plain = None
        self.opened = None

        top = ttk.Frame(self)
        top.pack(fill="x")
        self.src = DataSource(top, "Thông điệp / tệp bí mật Alice gửi Bob",
                              "Mã khóa két sắt phòng tài vụ: 7-3-9-1. Đổi mã sau ngày 30/10.", height=3)
        self.src.pack(fill="x")

        btns = ttk.LabelFrame(self, text="Thao tác", padding=6)
        btns.pack(fill="x", pady=4)
        actions = [
            ("1. Chỉ ký (không mã hóa) — Eve thấy gì?", self.only_sign),
            ("2. Alice KÝ RỒI MÃ HÓA gửi Bob", self.seal),
            ("3. Bob mở", self.bob_open),
            ("4. Eve mở bằng khóa của Eve", self.eve_open),
            ("5. Eve sửa 1 byte bản mã", self.tamper),
            ("6. Eve giả thư nhân danh Alice", self.forge),
            ("7. Bob chuyển tiếp lén cho Charlie", self.forward),
            ("Lưu tệp Bob đã giải mã...", self.save_plain),
        ]
        for i, (t, cmd) in enumerate(actions):
            ttk.Button(btns, text=t, command=cmd).grid(row=i // 4, column=i % 4, sticky="ew", padx=3, pady=2)
        for c in range(4):
            btns.columnconfigure(c, weight=1)

        body = ttk.PanedWindow(self, orient="horizontal")
        body.pack(fill="both", expand=True)
        f1 = ttk.LabelFrame(body, text="Gói tin trên đường truyền (Eve nhìn thấy)", padding=4)
        self.wire = OutputBox(f1)
        self.wire.pack(fill="both", expand=True)
        f2 = ttk.LabelFrame(body, text="Nhật ký", padding=4)
        self.log = OutputBox(f2)
        self.log.pack(fill="both", expand=True)
        body.add(f1, weight=1)
        body.add(f2, weight=1)
        self.log.append("Ký rồi mã hóa = chữ ký RSA của Alice + khóa phiên bọc bằng RSA-OAEP (khóa công khai của Bob)\n"
                        "+ dữ liệu mã bằng SHA256-CTR + HMAC. Thứ tự gợi ý: bấm 1 → 2 → 3 → 4 → 5 → 6 → 7.\n", "dim")

    def _keys(self):
        need = 1024
        pairs = [self.app.key(n, need, "Mã hóa OAEP") for n in PEOPLE]
        return None if None in pairs else dict(zip(PEOPLE, pairs))

    def _show_env(self, env, title):
        view = {k: (v[:64] + f"… ({len(v):,} ký tự)") if len(v) > 70 else v for k, v in env.items()}
        self.wire.clear()
        self.wire.append(f"=== {title} ===\n")
        self.wire.append(json.dumps(view, indent=2, ensure_ascii=False) + "\n")
        self.wire.append("\nKhông có nội dung rõ, không có tên người gửi, không có chữ ký ở dạng rõ.\n", "ok")

    def only_sign(self):
        k = self._keys()
        if not k:
            return
        data, name = self.src.get()

        def job():
            return rsa_full.sign_message(data, k["Alice"][0])

        def done(s):
            self.wire.clear()
            self.wire.append("=== Chỉ ký: gói (M, S) ===\n")
            preview = data[:600].decode("utf-8", "replace") if not name else f"<tệp {name}, {len(data):,} byte — gửi nguyên văn>"
            self.wire.append(f"M = {preview}\n", "bad")
            self.wire.append(f"S = {short_int(s)}\n")
            ok = rsa_full.verify_message(data, s, k["Alice"][1])
            self.log.append(f"\n[Chỉ ký] Eve đọc được toàn bộ nội dung; Eve còn tự kiểm tra được chữ ký: {ok}\n"
                            "=> Chữ ký số KHÔNG cung cấp tính bảo mật.\n", "bad")

        self.app.run(job, done, status="Đang ký...")

    def seal(self):
        k = self._keys()
        if not k:
            return
        try:
            data, name = self.src.get()
        except OSError as err:
            messagebox.showerror("Không đọc được tệp", str(err))
            return

        def job():
            return sm.seal(data, "Alice", k["Alice"][0], "Bob", k["Bob"][1], filename=name)

        def done(env):
            self.env, self.plain, self.opened = env, data, None
            self._show_env(env, "Alice → Bob: phong bì đã ký rồi mã hóa")
            self.log.append(f"\n[Alice] Đã ký và mã hóa {len(data):,} byte gửi Bob\n", "ok")

        self.app.run(job, done, status="Đang ký rồi mã hóa...")

    def _open(self, env, me, label, expect_ok):
        k = self._keys()
        if not k or env is None:
            if env is None:
                messagebox.showinfo("Chưa có phong bì", "Bấm '2. Alice KÝ RỒI MÃ HÓA' trước.")
            return

        def job():
            try:
                return True, sm.open_sealed(env, me, k[me][0], {"Alice": k["Alice"][1]}.get)
            except sm.SecureMessageError as err:
                return False, err.reason

        def done(res):
            ok, val = res
            self.log.append(f"\n[{label}]\n", "head")
            if ok:
                msg = val["message"]
                same = msg == self.plain
                self.opened = val
                body = msg.decode("utf-8", "replace") if not val["meta"].get("filename") else \
                    f"<tệp {val['meta']['filename']}, {len(msg):,} byte>"
                self.log.append(f"{me} mở được: {body[:500]}\n")
                self.log.append(f"Chữ ký hợp lệ, người gửi: {val['sender']} lúc {val['meta']['time']}; "
                                f"giống hệt bản gốc: {same}\n", "ok" if expect_ok else "bad")
            else:
                self.log.append(f"{me}: {val}" + ("\n" if expect_ok else " (tấn công bị chặn)\n"),
                                "bad" if expect_ok else "ok")

        self.app.run(job, done, status=f"{me} đang mở phong bì...")

    def bob_open(self):
        self._open(self.env, "Bob", "Bob mở bằng khóa riêng của Bob", True)

    def eve_open(self):
        self._open(self.env, "Eve", "Eve chặn được phong bì, mở bằng khóa riêng của Eve", False)

    def tamper(self):
        if self.env is None:
            return self._open(None, "Bob", "", False)
        import base64
        ct = bytearray(base64.b64decode(self.env["ct"]))
        ct[len(ct) // 2] ^= 0x01
        bad = dict(self.env, ct=base64.b64encode(bytes(ct)).decode())
        self._show_env(bad, "Phong bì đã bị Eve sửa 1 bit trong bản mã")
        self._open(bad, "Bob", "Eve sửa 1 bit bản mã rồi chuyển tiếp cho Bob", False)

    def forge(self):
        k = self._keys()
        if not k:
            return
        fake = "Alice: chuyển ngay 200 triệu vào tài khoản 0123 của Eve."

        def job():
            return sm.seal(fake, "Alice", k["Eve"][0], "Bob", k["Bob"][1])

        def done(env):
            self._show_env(env, "Phong bì giả do Eve tạo (mã hóa bằng khóa CÔNG KHAI của Bob)")
            self.log.append("\n[Eve] Ai cũng có khóa công khai của Bob nên Eve tự mã hóa thư giả, ký bằng khóa của Eve.\n")
            self._open(env, "Bob", "Bob mở thư giả", False)

        self.app.run(job, done, status="Eve đang tạo thư giả...")

    def forward(self):
        k = self._keys()
        if not k or self.env is None:
            return self._open(None, "Bob", "", False)
        env = self.env

        def job():
            inner = sm.decrypt_envelope(env, k["Bob"][0])
            return sm.encrypt_for(inner, "Charlie", k["Charlie"][1])

        def done(fwd):
            self._show_env(fwd, "Bob giải mã rồi mã hóa lại thư của Alice gửi Charlie")
            self._open(fwd, "Charlie", "Charlie mở thư Bob chuyển tiếp (chữ ký Alice vẫn nguyên)", False)

        self.app.run(job, done, status="Bob đang chuyển tiếp...")

    def save_plain(self):
        if not self.opened:
            messagebox.showinfo("Chưa có", "Bấm '3. Bob mở' thành công trước.")
            return
        name = self.opened["meta"].get("filename") or "thong_diep.txt"
        path = filedialog.asksaveasfilename(initialfile="giai_ma_" + name)
        if path:
            with open(path, "wb") as f:
                f.write(self.opened["message"])
            self.log.append(f"Đã lưu tệp giải mã: {path}\n", "ok")


# ====================================================================== #
# Tab 4: Tính tay
# ====================================================================== #
class MiniTab(ttk.Frame):
    def __init__(self, app, parent):
        super().__init__(parent, padding=8)
        self.app = app
        row = ttk.Frame(self)
        row.pack(fill="x")
        self.vars = {}
        for name, default in (("p", "17"), ("q", "11"), ("e", "7"), ("M", "88")):
            f, v = labeled_entry(row, name, 8, default)
            f.pack(side="left")
            self.vars[name] = v
        ttk.Button(row, text="Tính từng bước", command=self.compute).pack(side="left", padx=6)
        ttk.Button(row, text="Ví dụ trên lớp đầy đủ (3 phần, có ký rồi mã hóa)", command=self.class_demo).pack(side="left")
        ttk.Button(row, text="Xóa", command=lambda: self.out.clear()).pack(side="right")
        self.out = OutputBox(self)
        self.out.pack(fill="both", expand=True, pady=(6, 0))
        self.compute()

    def compute(self):
        self.out.clear()
        try:
            p, q, e, M = (int(self.vars[k].get()) for k in ("p", "q", "e", "M"))
            priv, pub = generate_keypair(p=p, q=q, e=e)
        except ValueError as err:
            self.out.append(f"[Lỗi] {err}\n", "bad")
            return
        d, N = priv
        if not 0 <= M < N:
            self.out.append(f"[Lỗi] Cần 0 <= M < N = {N}\n", "bad")
            return
        say = lambda *a: self.out.append(" ".join(str(x) for x in a) + "\n")
        say(f"=== Sinh khóa: p={p}, q={q}, e={e} ===")
        for line in explain_keygen(p, q, e):
            say("  " + line)
        say(f"\n=== Mã hóa C = M^e mod N ===")
        C = rsa_mini.show_mod_exp(M, e, N, "C", say)
        say(f"\n=== Giải mã M = C^d mod N ===")
        M2 = rsa_mini.show_mod_exp(C, d, N, "M", say)
        say("  Giải mã đúng bản rõ" if M2 == M else "  Sai")
        say(f"\n=== Ký S = M^d mod N ===")
        S = rsa_mini.show_mod_exp(M, d, N, "S", say)
        say(f"\n=== Kiểm tra S^e mod N ===")
        V = rsa_mini.show_mod_exp(S, e, N, "V", say)
        say(f"  V = {V} " + ("= M -> chữ ký hợp lệ" if V == M else "≠ M"))
        bad = (M + 1) % N
        say(f"  Với M bị sửa thành {bad}: " + ("chấp nhận" if rsa_mini.verify(bad, S, pub) else "bị từ chối"))

    def class_demo(self):
        self.out.clear()
        self.app.run(lambda: rsa_mini.run_demo(), output=self.out, status="Đang chạy ví dụ trên lớp...")


# ====================================================================== #
# Tab 5: Kịch bản & Tấn công
# ====================================================================== #
class ScenarioTab(ttk.Frame):
    def __init__(self, app, parent):
        super().__init__(parent, padding=8)
        self.app = app
        left = ttk.Frame(self)
        left.pack(side="left", fill="y")
        row = ttk.Frame(left)
        row.pack(fill="x", pady=(0, 6))
        ttk.Label(row, text="Độ dài khóa:").pack(side="left")
        self.bits = ttk.Combobox(row, values=("512", "1024", "2048"), width=6, state="readonly")
        self.bits.set("1024")
        self.bits.pack(side="left", padx=4)

        ks = lambda: int(self.bits.get())
        groups = [
            ("Kịch bản an toàn", [
                ("S1  Xác thực người dùng", lambda: run_scenario_s1(keysize=ks())),
                ("S2  Chống chối bỏ (CA + TSA, HMAC)", lambda: run_scenario_s2(keysize=ks())),
                ("S3  Khóa bị lộ, thu hồi, dấu thời gian", lambda: run_scenario_s3(keysize=ks())),
                ("S4  Tấn công phát lại (nonce)", lambda: run_scenario_s4(keysize=ks())),
                ("S5  Thay thế khóa công khai", lambda: run_scenario_s5(keysize=ks())),
                ("S6  Tính bảo mật", lambda: run_scenario_s6(keysize=max(ks(), 1024))),
                ("Chạy tất cả S1-S6", lambda: run_all(keysize=max(ks(), 1024))),
            ]),
            ("Tấn công vào chữ ký", [
                ("Phân tích N nhỏ (n = 3233)", lambda: small_n.demo_small_n()),
                ("Giả mạo khi không có đệm", lambda: forgery_no_padding.demo_no_padding_forgery()),
                ("Bleichenbacher e = 3", lambda: bleichenbacher_e3.demo_bleichenbacher(keysize=max(ks(), 1536))),
            ]),
            ("Tấn công vào tính bảo mật", [
                ("Từ điển: sách giáo khoa vs OAEP", lambda: confidentiality.demo_dictionary(keysize=max(ks(), 1024))),
                ("Ký song song mã hóa", lambda: confidentiality.demo_encrypt_and_sign_leak(keysize=max(ks(), 1024))),
                ("Håstad broadcast (e = 3)", lambda: confidentiality.demo_hastad(keysize=1024)),
                ("Dùng chung khóa ký & giải mã", lambda: confidentiality.demo_same_key_sign_decrypt()),
            ]),
        ]
        for title, items in groups:
            box = ttk.LabelFrame(left, text=title, padding=6)
            box.pack(fill="x", pady=4)
            for label, fn in items:
                ttk.Button(box, text=label, width=38, command=lambda f=fn, l=label: self.launch(f, l)).pack(fill="x", pady=1)
        ttk.Button(left, text="Xóa kết quả", command=lambda: self.out.clear()).pack(fill="x", pady=6)

        self.out = OutputBox(self)
        self.out.pack(side="left", fill="both", expand=True, padx=(8, 0))

    def launch(self, fn, label):
        self.out.append(f"\n>>> {label}\n", "head")
        self.app.run(fn, output=self.out, status=f"Đang chạy: {label}")


# ====================================================================== #
# Tab 6: Kiểm thử & Đánh giá
# ====================================================================== #
class ToolsTab(ttk.Frame):
    def __init__(self, app, parent):
        super().__init__(parent, padding=8)
        self.app = app
        row = ttk.Frame(self)
        row.pack(fill="x")
        for label, fn in (("Đối chiếu NIST / RFC / thư viện", self.doi_chieu),
                          ("Hiệu ứng thác lũ (lý do ký trên băm)", self.avalanche),
                          ("Benchmark (nhanh)", self.benchmark),
                          ("Chạy bộ test (tests/)", self.tests)):
            ttk.Button(row, text=label, command=fn).pack(side="left", padx=(0, 6))
        ttk.Button(row, text="Xóa", command=lambda: self.out.clear()).pack(side="right")
        self.out = OutputBox(self)
        self.out.pack(fill="both", expand=True, pady=(6, 0))

    def _go(self, fn, label):
        self.out.append(f"\n>>> {label}\n", "head")
        self.app.run(fn, output=self.out, status=f"Đang chạy: {label}")

    def doi_chieu(self):
        def job():
            sys.path.insert(0, os.path.join(ROOT, "tests"))
            import doi_chieu
            return doi_chieu.run()
        self._go(job, "Đối chiếu chuẩn")

    def avalanche(self):
        self._go(lambda: avalanche.run_demo(), "Hiệu ứng thác lũ")

    def benchmark(self):
        def job():
            from demo import benchmark
            benchmark.run_benchmark(real=False)
        self._go(job, "Benchmark")

    def tests(self):
        def job():
            env = dict(os.environ, PYTHONIOENCODING="utf-8")
            proc = subprocess.Popen([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"], cwd=ROOT,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                    encoding="utf-8", errors="replace", env=env,
                                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            for line in proc.stdout:
                print(line.rstrip("\n"))
            return proc.wait()
        self._go(job, "Bộ test")


def enable_high_dpi():
    """Windows: báo hệ điều hành rằng ứng dụng tự xử lý DPI để chữ không bị mờ khi màn hình phóng to 125-150%."""
    try:
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except (AttributeError, OSError):
        pass


def main():
    enable_high_dpi()
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
