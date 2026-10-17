#!/usr/bin/env python3
"""Hash Checker (GUI) - calculate and verify file hashes.

Run:  python hashcheck_gui.py
Requires only the Python standard library (tkinter ships with Python;
on some Linux distros install it with: sudo apt install python3-tk).
"""
import hashlib
import hmac
import os
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

CHUNK_SIZE = 1024 * 1024  # 1 MB

AUTO = "Auto-detect"
ALGORITHMS = {"MD5": "md5", "SHA-1": "sha1", "SHA-256": "sha256", "SHA-512": "sha512"}

# Hex digest length -> algorithm
LENGTH_TO_ALGORITHM = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}

GREEN, RED, ORANGE, GRAY = "#1a8f3c", "#c62828", "#e08600", "#666666"


# --------------------------------------------------------------------------
# Core logic (no GUI code here)
# --------------------------------------------------------------------------
class Cancelled(Exception):
    """Raised inside a worker when the user presses Cancel."""


def detect_algorithm(hash_value):
    """Guess the algorithm from the hex digest length, or return None."""
    return LENGTH_TO_ALGORITHM.get(len(hash_value.strip()))


def hash_file(path, algorithm, progress=None, cancel=None):
    """Hash a file in chunks. Calls progress(done, total) and honours a cancel Event."""
    h = hashlib.new(algorithm)
    total = os.path.getsize(path)
    done = 0
    with open(path, "rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            if cancel is not None and cancel.is_set():
                raise Cancelled()
            h.update(chunk)
            done += len(chunk)
            if progress:
                progress(done, total)
    return h.hexdigest()


def hashes_match(a, b):
    """Case- and whitespace-insensitive, timing-safe comparison."""
    return hmac.compare_digest(a.strip().lower(), b.strip().lower())


def human_size(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


# --------------------------------------------------------------------------
# GUI
# --------------------------------------------------------------------------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Hash Checker")
        self.geometry("740x500")
        self.minsize(660, 440)

        self.events = queue.Queue()      # worker thread -> GUI thread
        self.cancel = threading.Event()  # GUI thread -> worker thread
        self.computed = ""               # last computed hash

        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=10, pady=10)
        self.file_tab = ttk.Frame(notebook, padding=14)
        self.list_tab = ttk.Frame(notebook, padding=14)
        notebook.add(self.file_tab, text="  Verify File  ")
        notebook.add(self.list_tab, text="  Verify Checksum List  ")

        self._build_file_tab()
        self._build_list_tab()
        self.after(50, self._poll_events)

    # ---------- thread plumbing ----------
    def post(self, fn, *args):
        """Called from worker threads: schedule fn(*args) on the GUI thread."""
        self.events.put((fn, args))

    def _poll_events(self):
        try:
            while True:
                fn, args = self.events.get_nowait()
                fn(*args)
        except queue.Empty:
            pass
        self.after(50, self._poll_events)

    def _start_job(self, target, *args):
        self.cancel.clear()
        self._set_busy(True)

        def runner():
            try:
                target(*args)
            finally:
                self.post(self._set_busy, False)

        threading.Thread(target=runner, daemon=True).start()

    def _set_busy(self, busy):
        for btn in (self.start_btn, self.list_start_btn):
            btn.config(state="disabled" if busy else "normal")
        for btn in (self.cancel_btn, self.list_cancel_btn):
            btn.config(state="normal" if busy else "disabled")

    # ---------- common handlers ----------
    def _on_cancelled(self, status_label):
        status_label.config(text="Cancelled.")

    def _on_error(self, status_label, message):
        status_label.config(text="Error.")
        messagebox.showerror("Error", message)

    # ======================================================================
    # Tab 1: Verify a single file
    # ======================================================================
    def _build_file_tab(self):
        t = self.file_tab
        t.columnconfigure(1, weight=1)

        self.path_var = tk.StringVar()
        self.algo_var = tk.StringVar(value=AUTO)
        self.expected_var = tk.StringVar()
        self.computed_var = tk.StringVar()

        ttk.Label(t, text="File:").grid(row=0, column=0, sticky="w", pady=6)
        ttk.Entry(t, textvariable=self.path_var).grid(row=0, column=1, sticky="ew", padx=8)
        ttk.Button(t, text="Browse...", command=self._browse_file).grid(row=0, column=2)

        ttk.Label(t, text="Algorithm:").grid(row=1, column=0, sticky="w", pady=6)
        ttk.Combobox(t, textvariable=self.algo_var, state="readonly", width=16,
                     values=[AUTO] + list(ALGORITHMS)).grid(row=1, column=1, sticky="w", padx=8)

        ttk.Label(t, text="Expected hash:").grid(row=2, column=0, sticky="w", pady=6)
        ttk.Entry(t, textvariable=self.expected_var).grid(row=2, column=1, sticky="ew", padx=8)
        ttk.Button(t, text="Paste", command=self._paste_expected).grid(row=2, column=2)
        # Re-compare automatically if the expected hash is edited after calculating
        self.expected_var.trace_add("write", lambda *_: self._update_result())

        buttons = ttk.Frame(t)
        buttons.grid(row=3, column=0, columnspan=3, sticky="w", pady=(14, 8))
        self.start_btn = ttk.Button(buttons, text="Calculate & Verify",
                                    command=self._start_file)
        self.start_btn.pack(side="left")
        self.cancel_btn = ttk.Button(buttons, text="Cancel", state="disabled",
                                     command=self.cancel.set)
        self.cancel_btn.pack(side="left", padx=8)

        self.progress = ttk.Progressbar(t, maximum=100)
        self.progress.grid(row=4, column=0, columnspan=3, sticky="ew", pady=4)
        self.status = ttk.Label(t, text="Ready.", foreground=GRAY)
        self.status.grid(row=5, column=0, columnspan=3, sticky="w")

        self.result = tk.Label(t, text="", font=("TkDefaultFont", 13, "bold"), anchor="w")
        self.result.grid(row=6, column=0, columnspan=3, sticky="ew", pady=(18, 8))

        ttk.Label(t, text="Computed hash:").grid(row=7, column=0, sticky="w", pady=6)
        ttk.Entry(t, textvariable=self.computed_var, state="readonly").grid(
            row=7, column=1, sticky="ew", padx=8)
        ttk.Button(t, text="Copy", command=self._copy_computed).grid(row=7, column=2)

    def _browse_file(self):
        path = filedialog.askopenfilename(title="Select a file")
        if path:
            self.path_var.set(path)

    def _paste_expected(self):
        try:
            self.expected_var.set(self.clipboard_get().strip())
        except tk.TclError:
            pass  # clipboard empty or not text

    def _copy_computed(self):
        if self.computed:
            self.clipboard_clear()
            self.clipboard_append(self.computed)
            self.status.config(text="Hash copied to clipboard.")

    def _start_file(self):
        path = self.path_var.get().strip().strip('"')
        if not path:
            messagebox.showwarning("No file", "Please select a file first.")
            return
        if not os.path.isfile(path):
            messagebox.showerror("File not found", f"Cannot find the file:\n{path}")
            return

        expected = self.expected_var.get().strip()
        choice = self.algo_var.get()
        if choice == AUTO:
            if expected:
                algorithm = detect_algorithm(expected)
                if not algorithm:
                    messagebox.showerror(
                        "Unknown hash length",
                        "The expected hash length doesn't match MD5, SHA-1, SHA-256 or "
                        "SHA-512.\nCheck for typos or pick an algorithm manually.")
                    return
            else:
                algorithm = "sha256"
        else:
            algorithm = ALGORITHMS[choice]

        self.computed = ""
        self.computed_var.set("")
        self.result.config(text="")
        self.progress["value"] = 0
        self.status.config(text=f"Calculating {algorithm.upper()}...")
        self._start_job(self._file_worker, path, algorithm)

    def _file_worker(self, path, algorithm):
        try:
            digest = hash_file(
                path, algorithm,
                progress=lambda done, total: self.post(self._file_progress, done, total),
                cancel=self.cancel)
            self.post(self._file_done, digest, algorithm)
        except Cancelled:
            self.post(self._on_cancelled, self.status)
        except OSError as e:
            self.post(self._on_error, self.status, f"Could not read the file:\n{e}")

    def _file_progress(self, done, total):
        pct = (done / total * 100) if total else 100
        self.progress["value"] = pct
        self.status.config(text=f"{human_size(done)} / {human_size(total)}  ({pct:.0f}%)")

    def _file_done(self, digest, algorithm):
        self.progress["value"] = 100
        self.status.config(text=f"Done ({algorithm.upper()}).")
        self.computed = digest
        self.computed_var.set(digest)
        self._update_result()

    def _update_result(self):
        if not self.computed:
            return
        expected = self.expected_var.get().strip()
        if not expected:
            self.result.config(text="Hash calculated (no expected value to compare).",
                               fg=GRAY)
        elif len(expected) != len(self.computed):
            self.result.config(
                text="Expected hash has a different length than the computed one.", fg=ORANGE)
        elif hashes_match(self.computed, expected):
            self.result.config(text="\u2714  MATCH - the file is intact.", fg=GREEN)
        else:
            self.result.config(
                text="\u2718  MISMATCH - the file may be corrupted or modified!", fg=RED)

    # ======================================================================
    # Tab 2: Verify a checksum list (sha256sum-style file)
    # ======================================================================
    def _build_list_tab(self):
        t = self.list_tab
        t.columnconfigure(1, weight=1)
        t.rowconfigure(4, weight=1)

        self.list_path_var = tk.StringVar()

        ttk.Label(t, text="Checksum file:").grid(row=0, column=0, sticky="w", pady=6)
        ttk.Entry(t, textvariable=self.list_path_var).grid(row=0, column=1, sticky="ew", padx=8)
        ttk.Button(t, text="Browse...", command=self._browse_list).grid(row=0, column=2)

        ttk.Label(
            t, foreground=GRAY,
            text="Format: one '<hash>  <filename>' per line (e.g. SHA256SUMS). "
                 "Files are looked up next to the list."
        ).grid(row=1, column=0, columnspan=3, sticky="w")

        buttons = ttk.Frame(t)
        buttons.grid(row=2, column=0, columnspan=3, sticky="w", pady=(10, 6))
        self.list_start_btn = ttk.Button(buttons, text="Verify List", command=self._start_list)
        self.list_start_btn.pack(side="left")
        self.list_cancel_btn = ttk.Button(buttons, text="Cancel", state="disabled",
                                          command=self.cancel.set)
        self.list_cancel_btn.pack(side="left", padx=8)

        status_row = ttk.Frame(t)
        status_row.grid(row=3, column=0, columnspan=3, sticky="ew")
        status_row.columnconfigure(0, weight=1)
        self.list_progress = ttk.Progressbar(status_row, maximum=100)
        self.list_progress.grid(row=0, column=0, sticky="ew", pady=4)
        self.list_status = ttk.Label(status_row, text="Ready.", foreground=GRAY)
        self.list_status.grid(row=1, column=0, sticky="w")

        tree_frame = ttk.Frame(t)
        tree_frame.grid(row=4, column=0, columnspan=3, sticky="nsew", pady=(8, 4))
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)
        self.tree = ttk.Treeview(tree_frame, columns=("file", "status"),
                                 show="headings", height=8)
        self.tree.heading("file", text="File")
        self.tree.heading("status", text="Status")
        self.tree.column("file", width=420)
        self.tree.column("status", width=200)
        self.tree.tag_configure("ok", foreground=GREEN)
        self.tree.tag_configure("bad", foreground=RED)
        self.tree.tag_configure("warn", foreground=ORANGE)
        scroll = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        scroll.grid(row=0, column=1, sticky="ns")

        self.summary = tk.Label(t, text="", font=("TkDefaultFont", 11, "bold"), anchor="w")
        self.summary.grid(row=5, column=0, columnspan=3, sticky="ew", pady=(6, 0))

    def _browse_list(self):
        path = filedialog.askopenfilename(
            title="Select a checksum file",
            filetypes=[("Checksum files", "*.sha256 *.sha1 *.md5 *.txt *SUMS"),
                       ("All files", "*.*")])
        if path:
            self.list_path_var.set(path)

    def _start_list(self):
        path = self.list_path_var.get().strip().strip('"')
        if not path:
            messagebox.showwarning("No file", "Please select a checksum file first.")
            return
        if not os.path.isfile(path):
            messagebox.showerror("File not found", f"Cannot find the file:\n{path}")
            return

        self.tree.delete(*self.tree.get_children())
        self.summary.config(text="")
        self.list_progress["value"] = 0
        self.list_status.config(text="Starting...")
        self._start_job(self._list_worker, path)

    def _list_worker(self, list_path):
        try:
            with open(list_path, "r", encoding="utf-8") as f:
                lines = [(no, ln.strip()) for no, ln in enumerate(f, 1)]
        except (OSError, UnicodeDecodeError) as e:
            self.post(self._on_error, self.list_status, f"Could not read the list:\n{e}")
            return

        entries = [(no, ln) for no, ln in lines if ln and not ln.startswith("#")]
        base = os.path.dirname(os.path.abspath(list_path))
        ok = bad = problems = 0

        for index, (no, line) in enumerate(entries, 1):
            if self.cancel.is_set():
                self.post(self._on_cancelled, self.list_status)
                return

            parts = line.split(None, 1)
            if len(parts) != 2:
                self.post(self._list_row, f"(line {no})", "Unreadable line", "warn")
                problems += 1
                continue

            expected, name = parts[0], parts[1].lstrip("*")
            algorithm = detect_algorithm(expected)
            if not algorithm:
                self.post(self._list_row, name, "Unknown hash length", "warn")
                problems += 1
                continue

            self.post(self._list_progress, index - 1, len(entries), name)
            try:
                actual = hash_file(os.path.join(base, name), algorithm, cancel=self.cancel)
            except Cancelled:
                self.post(self._on_cancelled, self.list_status)
                return
            except FileNotFoundError:
                self.post(self._list_row, name, "Missing", "warn")
                problems += 1
                continue
            except PermissionError:
                self.post(self._list_row, name, "Permission denied", "warn")
                problems += 1
                continue
            except OSError as e:
                self.post(self._list_row, name, f"Error: {e.strerror or e}", "warn")
                problems += 1
                continue

            if hashes_match(actual, expected):
                self.post(self._list_row, name, f"OK ({algorithm.upper()})", "ok")
                ok += 1
            else:
                self.post(self._list_row, name, "MISMATCH", "bad")
                bad += 1

        self.post(self._list_done, len(entries), ok, bad, problems)

    def _list_progress(self, done, total, current_name):
        self.list_progress["value"] = (done / total * 100) if total else 100
        self.list_status.config(text=f"Checking {current_name}  ({done + 1}/{total})")

    def _list_row(self, name, status, tag):
        self.tree.insert("", "end", values=(name, status), tags=(tag,))
        self.tree.yview_moveto(1)

    def _list_done(self, total, ok, bad, problems):
        self.list_progress["value"] = 100
        self.list_status.config(text="Done.")
        text = f"{ok} OK, {bad} mismatched, {problems} missing/unreadable (of {total})"
        color = GREEN if (bad == 0 and problems == 0 and total > 0) else RED
        self.summary.config(text=text, fg=color)


if __name__ == "__main__":
    App().mainloop()
