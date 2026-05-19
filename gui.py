"""
MFCIPHER GUI - Ternary Huffman Cipher
Antarmuka grafis berbasis CustomTkinter.

Dependensi: pip install customtkinter
"""

import heapq
import os
from tkinter import filedialog, messagebox
from typing import Optional

import customtkinter as ctk

FREQ: list[float] = [
    1,1,1,1,1,1,1,1,1,2,5,1,1,2,1,1,
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
    15,2,3,1,1,1,2,2,2,2,1,1,3,2,3,1,
    4,3,3,3,3,3,3,3,3,3,2,2,1,1,1,1,
    1,6,3,4,4,7,3,3,4,6,2,2,4,4,6,6,
    4,1,5,6,5,4,3,3,2,3,1,1,1,1,1,1,
    1,9,2,5,6,12,3,3,5,9,1,1,6,4,8,8,
    4,1,7,8,7,5,3,3,2,3,1,1,1,1,1,1,
]

# --- Pohon Huffman ---

class Node:
    __slots__ = ("freq", "order", "symbol", "children")
    def __init__(self, freq: float, order: int, symbol: int = -1):
        self.freq     = freq
        self.order    = order
        self.symbol   = symbol
        self.children: list[Optional["Node"]] = [None, None, None]
    def __lt__(self, other: "Node") -> bool:
        return (self.freq, self.order) < (other.freq, other.order)


def build_tree() -> Node:
    counter = 0
    pq: list[Node] = []
    for i in range(128):
        heapq.heappush(pq, Node(FREQ[i], counter, i)); counter += 1
    while (len(pq) - 1) % 2 != 0:
        heapq.heappush(pq, Node(0.0, counter, -2)); counter += 1
    while len(pq) > 1:
        children = [heapq.heappop(pq) for _ in range(3)]
        parent = Node(sum(c.freq for c in children), counter)
        parent.children = children; counter += 1
        heapq.heappush(pq, parent)
    return heapq.heappop(pq)


def extract_codes(node: Node, path: list[int], codes: dict[int, list[int]]) -> None:
    if node.symbol >= 0 and node.symbol < 128:
        codes[node.symbol] = path[:]; return
    for d, child in enumerate(node.children):
        if child is not None:
            path.append(d); extract_codes(child, path, codes); path.pop()


_D2C = ("m", "f", " ")
_C2D: dict[int, int] = {ord("m"): 0, ord("f"): 1, ord(" "): 2}


def encode(src: bytes, codes: dict[int, list[int]]) -> bytes:
    parts: list[str] = []
    for b in src:
        sym = b if b < 128 else ord("?")
        parts.append("".join(_D2C[d] for d in codes[sym]))
    return "".join(parts).encode("ascii")


def decode(src: bytes, root: Node) -> bytes:
    out = bytearray()
    cur = root
    for b in src:
        d = _C2D.get(b)
        if d is None: continue
        cur = cur.children[d]
        if cur is None:
            raise ValueError("Data korup atau format file tidak valid.")
        if cur.symbol >= 0 and cur.symbol < 128:
            out.append(cur.symbol); cur = root
    return bytes(out)


# --- Warna & Konstanta Desain ---

BG_DEEP    = "#0a0a0a"   # latar utama
BG_PANEL   = "#111111"   # panel / card
BG_INPUT   = "#0f0f0f"   # area input
BORDER     = "#1e3a5f"   # garis biru dingin
ACCENT     = "#2563eb"   # biru aksen tombol
ACCENT_HVR = "#1d4ed8"
RED_BASE   = "#7f1d1d"
RED_HVR    = "#991b1b"
GREEN_BASE = "#14532d"
GREEN_HVR  = "#166534"
TEXT_PRI   = "#f0f0f0"   # teks utama
TEXT_SEC   = "#4a5568"   # teks sekunder / placeholder
TEXT_DIM   = "#2d3748"   # teks sangat redup

FONT_MONO  = "Courier New"


# --- Komponen Kustom ---

class Separator(ctk.CTkFrame):
    """Garis horizontal tipis berwarna biru dingin."""
    def __init__(self, parent, **kwargs):
        super().__init__(
            parent,
            height=1,
            fg_color=BORDER,
            **kwargs,
        )


class StatusBar(ctk.CTkFrame):
    """Bar status di bagian bawah layar."""
    def __init__(self, parent, **kwargs):
        super().__init__(parent, fg_color=BG_PANEL, height=32, corner_radius=0, **kwargs)
        self._label = ctk.CTkLabel(
            self, text="SIAP", font=(FONT_MONO, 10),
            text_color=TEXT_SEC, anchor="w",
        )
        self._label.pack(side="left", padx=12, pady=6)

        self._right = ctk.CTkLabel(
            self, text="MFCIPHER v1.0", font=(FONT_MONO, 10),
            text_color=TEXT_DIM, anchor="e",
        )
        self._right.pack(side="right", padx=12, pady=6)

    def set(self, text: str, color: str = TEXT_SEC) -> None:
        self._label.configure(text=text, text_color=color)


# --- Aplikasi Utama ---

class MFCipherApp(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()

        # Konfigurasi jendela
        self.title("MFCIPHER")
        self.geometry("520x440")
        self.minsize(520, 440)
        self.resizable(False, False)
        self.configure(fg_color=BG_DEEP)
        ctk.set_appearance_mode("dark")

        self._selected_path: str = ""

        self._build_ui()

    def _build_ui(self) -> None:
        # --- Header ---
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=24, pady=(28, 0))

        ctk.CTkLabel(
            header, text="MFCIPHER",
            font=(FONT_MONO, 28, "bold"),
            text_color=TEXT_PRI,
            anchor="w",
        ).pack(side="left")

        # Badge versi di kanan header
        ctk.CTkLabel(
            header, text="v1.0",
            font=(FONT_MONO, 10),
            text_color=TEXT_SEC,
            anchor="e",
        ).pack(side="right", pady=(8, 0))

        # Separator bawah header
        Separator(self).pack(fill="x", padx=24, pady=(12, 0))

        # --- Panel Pemilihan File ---
        file_panel = ctk.CTkFrame(
            self, fg_color=BG_PANEL,
            corner_radius=0,
            border_width=1,
            border_color=BORDER,
        )
        file_panel.pack(fill="x", padx=24, pady=(16, 0))

        # Label header panel
        ctk.CTkLabel(
            file_panel, text="TARGET FILE",
            font=(FONT_MONO, 9, "bold"),
            text_color=TEXT_SEC,
            anchor="w",
        ).pack(anchor="w", padx=14, pady=(10, 4))

        # Baris path + tombol
        row = ctk.CTkFrame(file_panel, fg_color="transparent")
        row.pack(fill="x", padx=14, pady=(0, 12))
        row.columnconfigure(0, weight=1)

        self._path_var = ctk.StringVar(value="")
        self._path_entry = ctk.CTkEntry(
            row,
            textvariable=self._path_var,
            placeholder_text="Belum ada file dipilih...",
            font=(FONT_MONO, 11),
            fg_color=BG_INPUT,
            border_color=BORDER,
            border_width=1,
            text_color=TEXT_PRI,
            placeholder_text_color=TEXT_DIM,
            corner_radius=0,
            state="readonly",
            height=34,
        )
        self._path_entry.grid(row=0, column=0, sticky="ew", padx=(0, 8))

        ctk.CTkButton(
            row,
            text="BROWSE",
            font=(FONT_MONO, 10, "bold"),
            fg_color="transparent",
            hover_color=BORDER,
            border_color=BORDER,
            border_width=1,
            text_color=TEXT_SEC,
            corner_radius=0,
            width=80,
            height=34,
            command=self._select_file,
        ).grid(row=0, column=1)

        Separator(self).pack(fill="x", padx=24, pady=(16, 0))

        # --- Panel Aksi ---
        action_label = ctk.CTkFrame(self, fg_color="transparent")
        action_label.pack(fill="x", padx=24, pady=(14, 0))
        ctk.CTkLabel(
            action_label, text="OPERASI",
            font=(FONT_MONO, 9, "bold"),
            text_color=TEXT_SEC,
        ).pack(anchor="w")

        btn_row = ctk.CTkFrame(self, fg_color="transparent")
        btn_row.pack(fill="x", padx=24, pady=(8, 0))
        btn_row.columnconfigure((0, 1), weight=1)

        ctk.CTkButton(
            btn_row,
            text="ENKRIPSI",
            font=(FONT_MONO, 12, "bold"),
            fg_color=RED_BASE,
            hover_color=RED_HVR,
            text_color=TEXT_PRI,
            corner_radius=0,
            height=44,
            border_width=0,
            command=lambda: self._run("enc"),
        ).grid(row=0, column=0, sticky="ew", padx=(0, 6))

        ctk.CTkButton(
            btn_row,
            text="DEKRIPSI",
            font=(FONT_MONO, 12, "bold"),
            fg_color=GREEN_BASE,
            hover_color=GREEN_HVR,
            text_color=TEXT_PRI,
            corner_radius=0,
            height=44,
            border_width=0,
            command=lambda: self._run("dec"),
        ).grid(row=0, column=1, sticky="ew", padx=(6, 0))

        Separator(self).pack(fill="x", padx=24, pady=(20, 0))

        # --- Panel Log Output ---
        log_label_row = ctk.CTkFrame(self, fg_color="transparent")
        log_label_row.pack(fill="x", padx=24, pady=(12, 0))
        ctk.CTkLabel(
            log_label_row, text="OUTPUT",
            font=(FONT_MONO, 9, "bold"),
            text_color=TEXT_SEC,
        ).pack(anchor="w")

        self._log_box = ctk.CTkTextbox(
            self,
            font=(FONT_MONO, 11),
            fg_color=BG_PANEL,
            border_color=BORDER,
            border_width=1,
            text_color=TEXT_PRI,
            corner_radius=0,
            height=90,
            wrap="word",
            state="disabled",
        )
        self._log_box.pack(fill="x", padx=24, pady=(6, 0))

        # --- Status Bar ---
        Separator(self).pack(fill="x", pady=(16, 0))
        self._status = StatusBar(self)
        self._status.pack(fill="x", side="bottom")

    def _log(self, text: str, color: str = TEXT_PRI) -> None:
        self._log_box.configure(state="normal")
        self._log_box.delete("1.0", "end")
        self._log_box.insert("end", text)
        self._log_box.configure(state="disabled", text_color=color)

    def _select_file(self) -> None:
        path = filedialog.askopenfilename()
        if path:
            self._selected_path = path
            self._path_var.set(path)
            self._status.set(f"File dipilih: {os.path.basename(path)}", TEXT_SEC)

    def _run(self, mode: str) -> None:
        if not self._selected_path:
            self._log("[-] Tidak ada file yang dipilih.", "#ef4444")
            self._status.set("GAGAL — pilih file terlebih dahulu.", "#ef4444")
            return
        try:
            self._status.set("Memproses...", ACCENT)
            self.update_idletasks()

            with open(self._selected_path, "rb") as f:
                data = f.read()

            root  = build_tree()
            codes: dict[int, list[int]] = {}
            extract_codes(root, [], codes)

            if mode == "enc":
                result   = encode(data, codes)
                out_path = os.path.splitext(self._selected_path)[0] + ".mfc"
            else:
                result   = decode(data, root)
                base     = self._selected_path.replace(".mfc", "")
                out_path = base + "_recovered.txt"

            with open(out_path, "wb") as f:
                f.write(result)

            label    = "ENKRIPSI" if mode == "enc" else "DEKRIPSI"
            in_size  = len(data)
            out_size = len(result)
            msg = (
                f"[+] {label} selesai.\n"
                f"    Input  : {os.path.basename(self._selected_path)} ({in_size} bytes)\n"
                f"    Output : {os.path.basename(out_path)} ({out_size} bytes)"
            )
            self._log(msg, "#4ade80")
            self._status.set(f"SELESAI — {os.path.basename(out_path)}", "#4ade80")

        except Exception as exc:
            self._log(f"[-] Kesalahan: {exc}", "#ef4444")
            self._status.set("GAGAL — lihat output untuk detail.", "#ef4444")


if __name__ == "__main__":
    app = MFCipherApp()
    app.mainloop()