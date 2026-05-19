"""
MFCIPHER - Ternary Huffman Cipher
Alfabet output: 'm' (0), 'f' (1), ' ' (2)

Pohon dibangun dengan tie-breaking (freq, insertion_order) untuk hasil
deterministik dan kompatibel lintas bahasa.

Penggunaan: python mfcipher.py [enc/dec] [input] [output]
"""

import heapq
import sys
from typing import Optional

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
        heapq.heappush(pq, Node(FREQ[i], counter, i))
        counter += 1

    # Tambahkan dummy agar (N-1) % 2 == 0 (syarat Huffman terner)
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
    if node.symbol >= 0 and node.symbol < 128:
        codes[node.symbol] = path[:]
        return
    for d, child in enumerate(node.children):
        if child is not None:
            path.append(d)
            extract_codes(child, path, codes)
            path.pop()


# --- Encoder ---

_D2C = ("m", "f", " ")

def encode(src: bytes, codes: dict[int, list[int]]) -> bytes:
    parts: list[str] = []
    for b in src:
        sym = b if b < 128 else ord("?")
        parts.append("".join(_D2C[d] for d in codes[sym]))
    return "".join(parts).encode("ascii")


# --- Decoder ---

_C2D: dict[int, int] = {ord("m"): 0, ord("f"): 1, ord(" "): 2}

def decode(src: bytes, root: Node) -> bytes:
    out = bytearray()
    cur = root
    for i, b in enumerate(src):
        d = _C2D.get(b)
        if d is None:
            continue
        cur = cur.children[d]
        if cur is None:
            print(f"[-] Data korup pada posisi {i}.", file=sys.stderr)
            return bytes(out)
        if cur.symbol >= 0 and cur.symbol < 128:
            out.append(cur.symbol)
            cur = root
    return bytes(out)


# --- Entry Point ---

def main() -> None:
    if len(sys.argv) != 4:
        print(
            f"MFCIPHER - Ternary Huffman Cipher\n"
            f"Penggunaan: python {sys.argv[0]} [enc/dec] [input] [output]",
            file=sys.stderr,
        )
        sys.exit(1)

    _, mode, in_path, out_path = sys.argv
    if mode not in ("enc", "dec"):
        print("[-] Mode tidak valid. Gunakan 'enc' atau 'dec'.", file=sys.stderr)
        sys.exit(1)

    with open(in_path, "rb") as f:
        data = f.read()

    root  = build_tree()
    codes: dict[int, list[int]] = {}
    extract_codes(root, [], codes)

    if mode == "enc":
        result = encode(data, codes)
        print(f"[+] Enkripsi selesai -> {out_path}", file=sys.stderr)
    else:
        result = decode(data, root)
        print(f"[+] Dekripsi selesai -> {out_path}", file=sys.stderr)

    with open(out_path, "wb") as f:
        f.write(result)


if __name__ == "__main__":
    main()
