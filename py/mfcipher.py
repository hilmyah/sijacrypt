"""
MFCIPHER - Ternary Huffman Cipher dengan Secret Key
Alfabet output: 'm' (0), 'f' (1), ' ' (2)

Alur enkripsi:
  1. Build FREQ dari key (FNV-1a + Fisher-Yates)
  2. Bangun pohon Huffman terner dari FREQ
  3. Encode plaintext -> digit terner (via Huffman)
  4. XOR terner: (digit + keystream) mod 3   <- stream cipher

Penggunaan: python mfcipher.py [enc/dec] [input] [output] [key]
"""

import heapq
import sys
from typing import Optional

FREQ_BASE: list[float] = [
    1,1,1,1,1,1,1,1,1,2,5,1,1,2,1,1,
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
    15,2,3,1,1,1,2,2,2,2,1,1,3,2,3,1,
    4,3,3,3,3,3,3,3,3,3,2,2,1,1,1,1,
    1,6,3,4,4,7,3,3,4,6,2,2,4,4,6,6,
    4,1,5,6,5,4,3,3,2,3,1,1,1,1,1,1,
    1,9,2,5,6,12,3,3,5,9,1,1,6,4,8,8,
    4,1,7,8,7,5,3,3,2,3,1,1,1,1,1,1,
]

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
    for i in range(127, 0, -1):
        state, val = xorshift64(state)
        j = val % (i + 1)
        freq[i], freq[j] = freq[j], freq[i]
    return freq


def ks_init(key: str) -> int:
    """Seed keystream — independen dari shuffle seed."""
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
    for i in range(128):
        heapq.heappush(pq, Node(freq[i], counter, i)); counter += 1
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


# ========== Encoder & Decoder ==========

_D2C = ("m", "f", " ")
_C2D: dict[int, int] = {ord("m"): 0, ord("f"): 1, ord(" "): 2}


def encode(src: bytes, codes: dict[int, list[int]], key: str) -> bytes:
    ks    = ks_init(key)
    parts: list[str] = []
    for b in src:
        sym = b if b < 128 else ord("?")
        for d in codes[sym]:
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
        if cur.symbol >= 0 and cur.symbol < 128:
            out.append(cur.symbol); cur = root
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
        result = encode(data, codes, key)
        print(f"[+] Enkripsi selesai -> {out_path}", file=sys.stderr)
    else:
        result = decode(data, root, key)
        print(f"[+] Dekripsi selesai -> {out_path}", file=sys.stderr)

    with open(out_path, "wb") as f:
        f.write(result)


if __name__ == "__main__":
    main()