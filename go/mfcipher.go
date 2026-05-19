// MFCIPHER - Ternary Huffman Cipher
// Alfabet output: 'm' (0), 'f' (1), ' ' (2)
//
// Tie-breaking (freq, insertion_order) untuk kompatibilitas lintas bahasa.
// Penggunaan: ./mfcipher [enc/dec] [input] [output]

package main

import (
	"container/heap"
	"fmt"
	"os"
)

var freq = [128]float64{
	1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 5, 1, 1, 2, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	15, 2, 3, 1, 1, 1, 2, 2, 2, 2, 1, 1, 3, 2, 3, 1,
	4, 3, 3, 3, 3, 3, 3, 3, 3, 3, 2, 2, 1, 1, 1, 1,
	1, 6, 3, 4, 4, 7, 3, 3, 4, 6, 2, 2, 4, 4, 6, 6,
	4, 1, 5, 6, 5, 4, 3, 3, 2, 3, 1, 1, 1, 1, 1, 1,
	1, 9, 2, 5, 6, 12, 3, 3, 5, 9, 1, 1, 6, 4, 8, 8,
	4, 1, 7, 8, 7, 5, 3, 3, 2, 3, 1, 1, 1, 1, 1, 1,
}

// --- Pohon Huffman ---

type node struct {
	symbol int
	freq   float64
	order  int64
	child  [3]*node
}

type nodeHeap []*node

func (h nodeHeap) Len() int { return len(h) }
func (h nodeHeap) Less(i, j int) bool {
	if h[i].freq != h[j].freq {
		return h[i].freq < h[j].freq
	}
	return h[i].order < h[j].order
}
func (h nodeHeap) Swap(i, j int)       { h[i], h[j] = h[j], h[i] }
func (h *nodeHeap) Push(x interface{}) { *h = append(*h, x.(*node)) }
func (h *nodeHeap) Pop() interface{} {
	old := *h; n := len(old); x := old[n-1]; *h = old[:n-1]; return x
}

func buildTree() *node {
	h := &nodeHeap{}
	heap.Init(h)
	var counter int64

	for i := 0; i < 128; i++ {
		heap.Push(h, &node{symbol: i, freq: freq[i], order: counter})
		counter++
	}
	for (h.Len()-1)%2 != 0 {
		heap.Push(h, &node{symbol: -2, freq: 0, order: counter})
		counter++
	}
	for h.Len() > 1 {
		p := &node{symbol: -1, order: counter}
		counter++
		for d := 0; d < 3; d++ {
			child := heap.Pop(h).(*node)
			p.child[d] = child
			p.freq += child.freq
		}
		heap.Push(h, p)
	}
	return heap.Pop(h).(*node)
}

var codes [128][]int8

func extractCodes(n *node, path []int8) {
	if n == nil { return }
	if n.symbol >= 0 && n.symbol < 128 {
		cp := make([]int8, len(path)); copy(cp, path); codes[n.symbol] = cp; return
	}
	for d := 0; d < 3; d++ {
		extractCodes(n.child[d], append(path, int8(d)))
	}
}

// --- Encoder ---

func encode(src []byte) []byte {
	out := make([]byte, 0, len(src)*5)
	for _, b := range src {
		sym := int(b); if sym >= 128 { sym = int('?') }
		for _, d := range codes[sym] {
			switch d { case 0: out = append(out, 'm'); case 1: out = append(out, 'f'); default: out = append(out, ' ') }
		}
	}
	return out
}

// --- Decoder ---

func decode(src []byte, root *node) []byte {
	out := make([]byte, 0, len(src)/5)
	cur := root
	for i, b := range src {
		var d int
		switch b { case 'm': d=0; case 'f': d=1; case ' ': d=2; default: continue }
		cur = cur.child[d]
		if cur == nil {
			fmt.Fprintf(os.Stderr, "[-] Data korup pada posisi %d.\n", i); return out
		}
		if cur.symbol >= 0 && cur.symbol < 128 {
			out = append(out, byte(cur.symbol)); cur = root
		}
	}
	return out
}

// --- Entry Point ---

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintf(os.Stderr, "MFCIPHER - Ternary Huffman Cipher\nPenggunaan: %s [enc/dec] [input] [output]\n", os.Args[0])
		os.Exit(1)
	}
	mode, inPath, outPath := os.Args[1], os.Args[2], os.Args[3]
	if mode != "enc" && mode != "dec" {
		fmt.Fprintln(os.Stderr, "[-] Mode tidak valid. Gunakan 'enc' atau 'dec'."); os.Exit(1)
	}

	data, err := os.ReadFile(inPath)
	if err != nil { fmt.Fprintln(os.Stderr, "[-] Gagal membaca input:", err); os.Exit(1) }

	root := buildTree()
	extractCodes(root, nil)

	var result []byte
	if mode == "enc" {
		result = encode(data)
		fmt.Fprintf(os.Stderr, "[+] Enkripsi selesai -> %s\n", outPath)
	} else {
		result = decode(data, root)
		fmt.Fprintf(os.Stderr, "[+] Dekripsi selesai -> %s\n", outPath)
	}

	if err := os.WriteFile(outPath, result, 0644); err != nil {
		fmt.Fprintln(os.Stderr, "[-] Gagal menulis output:", err); os.Exit(1)
	}
}
