"""
MFCIPHER - Ternary Huffman Cipher dengan Secret Key
Alfabet output: 'm' (0), 'f' (1), ' ' (2)

Alur enkripsi:
  1. Build FREQ dari key (FNV-1a + Fisher-Yates) untuk 256 simbol byte
  2. Bangun pohon Huffman terner dari FREQ
  3. Prepend header (magic + ekstensi asli) ke plaintext
  4. Encode byte stream -> digit terner (via Huffman)
  5. XOR terner: (digit + keystream) mod 3   <- stream cipher

Penggunaan: python mfcipher.py [enc/dec] [input] [output] [key]
"""

import heapq
import sys
import os
from typing import Optional

# Frekuensi dasar untuk 256 simbol byte
FREQ_BASE: list[float] = [
    # 0x00-0x0F
    1,1,1,1,1,1,1,1,1,2,5,1,1,2,1,1,
    # 0x10-0x1F
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
    # 0x20-0x2F
    15,2,3,1,1,1,2,2,2,2,1,1,3,2,3,1,
    # 0x30-0x3F
    4,3,3,3,3,3,3,3,3,3,2,2,1,1,1,1,
    # 0x40-0x4F
    1,6,3,4,4,7,3,3,4,6,2,2,4,4,6,6,
    # 0x50-0x5F
    4,1,5,6,5,4,3,3,2,3,1,1,1,1,1,1,
    # 0x60-0x6F
    1,9,2,5,6,12,3,3,5,9,1,1,6,4,8,8,
    # 0x70-0x7F
    4,1,7,8,7,5,3,3,2,3,1,1,1,1,1,1,
    # 0x80-0xFF: byte biner, distribusi flat
    2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
    2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
    2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
    2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
    2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
    2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
    2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
    2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
]

# Header yang disisipkan sebelum enkripsi agar ekstensi asli bisa dipulihkan
HEADER_MAGIC   = b"MFCI"
HEADER_VERSION = 1


# ========== PRNG ==========

def fnv1a_hash(key: str) -> int:
    h = 14695981039346656037
    for ch in key.encode("utf-8"):
        h ^= ch
        h = (h * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return h


def xorshift64(state: int) -> tuple[int, int]:
    state &= 0xFFFFFFFFFFFFFFFF
    state ^= (state << 13) & 0xFFFFFFFFFFFFFFFF
    state ^= (state >> 7)  & 0xFFFFFFFFFFFFFFFF
    state ^= (state << 17) & 0xFFFFFFFFFFFFFFFF
    return state, state


def build_freq(key: str) -> list[float]:
    freq  = FREQ_BASE[:]
    state = fnv1a_hash(key) or 1
    for i in range(255, 0, -1):
        state, val = xorshift64(state)
        j = val % (i + 1)
        freq[i], freq[j] = freq[j], freq[i]
    return freq


def ks_init(key: str) -> int:
    seed = (fnv1a_hash(key) ^ 0xDEADBEEFCAFE) & 0xFFFFFFFFFFFFFFFF
    return seed or 0xDEADBEEFCAFE


# ========== Pohon Huffman ==========

class Node:
    __slots__ = ("freq", "order", "symbol", "children")

    def __init__(self, freq: float, order: int, symbol: int = -1):
        self.freq     = freq
        self.order    = order
        self.symbol   = symbol
        self.children: list[Optional["Node"]] = [None, None, None]

    def __lt__(self, other: "Node") -> bool:
        return (self.freq, self.order) < (other.freq, other.order)


def build_tree(freq: list[float]) -> Node:
    counter = 0
    pq: list[Node] = []
    for i in range(256):
        heapq.heappush(pq, Node(freq[i], counter, i))
        counter += 1
    while (len(pq) - 1) % 2 != 0:
        heapq.heappush(pq, Node(0.0, counter, -2))
        counter += 1
    while len(pq) > 1:
        children = [heapq.heappop(pq) for _ in range(3)]
        parent = Node(sum(c.freq for c in children), counter)
        parent.children = children
        counter += 1
        heapq.heappush(pq, parent)
    return heapq.heappop(pq)


def extract_codes(node: Node, path: list[int], codes: dict[int, list[int]]) -> None:
    if 0 <= node.symbol < 256:
        codes[node.symbol] = path[:]
        return
    for d, child in enumerate(node.children):
        if child is not None:
            path.append(d)
            extract_codes(child, path, codes)
            path.pop()


# ========== Header ==========

def build_header(ext: str) -> bytes:
    """Buat header yang menyimpan ekstensi asli file.
    Format: MAGIC(4) | VERSION(1) | EXT_LEN(1) | EXT(n)
    """
    ext_bytes = ext.lstrip(".").lower().encode("utf-8")[:31]
    return HEADER_MAGIC + bytes([HEADER_VERSION, len(ext_bytes)]) + ext_bytes


def parse_header(data: bytes) -> tuple[str, bytes]:
    """Ekstrak ekstensi asli dan payload dari hasil dekripsi.
    Return ("", data) jika header tidak ditemukan (file lama tanpa header).
    """
    if not data.startswith(HEADER_MAGIC):
        return "", data
    if len(data) < 6:
        return "", data
    if data[4] != HEADER_VERSION:
        return "", data
    ext_len = data[5]
    if len(data) < 6 + ext_len:
        return "", data
    ext     = data[6:6 + ext_len].decode("utf-8", errors="replace")
    payload = data[6 + ext_len:]
    return ext, payload


# ========== Encoder & Decoder ==========

_D2C = ("m", "f", " ")
_C2D: dict[int, int] = {ord("m"): 0, ord("f"): 1, ord(" "): 2}


def encode(src: bytes, codes: dict[int, list[int]], key: str) -> bytes:
    ks    = ks_init(key)
    parts: list[str] = []
    for b in src:
        for d in codes[b]:
            ks, kd = xorshift64(ks)
            cd = (d + kd % 3) % 3
            parts.append(_D2C[cd])
    return "".join(parts).encode("ascii")


def decode(src: bytes, root: Node, key: str) -> bytes:
    ks  = ks_init(key)
    out = bytearray()
    cur = root
    for i, b in enumerate(src):
        raw = _C2D.get(b)
        if raw is None:
            continue
        ks, kd = xorshift64(ks)
        d = (raw - kd % 3 + 3) % 3
        cur = cur.children[d]
        if cur is None:
            print(f"[-] Data korup pada posisi {i}.", file=sys.stderr)
            return bytes(out)
        if 0 <= cur.symbol < 256:
            out.append(cur.symbol)
            cur = root
    return bytes(out)


# ========== Entry Point ==========

def main() -> None:
    if len(sys.argv) != 5:
        print(
            f"MFCIPHER - Ternary Huffman Cipher\n"
            f"Penggunaan: python {sys.argv[0]} [enc/dec] [input] [output] [key]",
            file=sys.stderr,
        )
        sys.exit(1)

    _, mode, in_path, out_path, key = sys.argv
    if mode not in ("enc", "dec"):
        print("[-] Mode tidak valid. Gunakan 'enc' atau 'dec'.", file=sys.stderr)
        sys.exit(1)

    with open(in_path, "rb") as f:
        data = f.read()

    freq  = build_freq(key)
    root  = build_tree(freq)
    codes: dict[int, list[int]] = {}
    extract_codes(root, [], codes)

    if mode == "enc":
        ext     = os.path.splitext(in_path)[1]
        payload = build_header(ext) + data
        result  = encode(payload, codes, key)
        print(f"[+] Enkripsi selesai -> {out_path}", file=sys.stderr)
    else:
        raw      = decode(data, root, key)
        ext, result = parse_header(raw)
        if ext:
            base, given_ext = os.path.splitext(out_path)
            if not given_ext:
                out_path = base + "." + ext
            print(f"[+] Ekstensi asli dipulihkan: .{ext}", file=sys.stderr)
        print(f"[+] Dekripsi selesai -> {out_path}", file=sys.stderr)

    with open(out_path, "wb") as f:
        f.write(result)


if __name__ == "__main__":
    main()