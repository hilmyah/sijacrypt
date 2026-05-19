// MFCIPHER - Ternary Huffman Cipher dengan Secret Key
// Alfabet output: 'm' (0), 'f' (1), ' ' (2)
//
// Alur enkripsi:
//   1. Build FREQ dari key (FNV-1a + Fisher-Yates) untuk 256 simbol byte
//   2. Bangun pohon Huffman terner dari FREQ
//   3. Prepend header (magic + ekstensi asli) ke plaintext
//   4. Encode byte stream -> digit terner (via Huffman)
//   5. XOR terner: (digit + keystream) mod 3   <- stream cipher
//
// Penggunaan: ./mfcipher [enc/dec] [input] [output] [key]

package main

import (
	"container/heap"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Frekuensi dasar untuk 256 simbol byte
var freqBase = [256]float64{
	/* 0x00-0x0F */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 5, 1, 1, 2, 1, 1,
	/* 0x10-0x1F */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	/* 0x20-0x2F */
	15, 2, 3, 1, 1, 1, 2, 2, 2, 2, 1, 1, 3, 2, 3, 1,
	/* 0x30-0x3F */
	4, 3, 3, 3, 3, 3, 3, 3, 3, 3, 2, 2, 1, 1, 1, 1,
	/* 0x40-0x4F */
	1, 6, 3, 4, 4, 7, 3, 3, 4, 6, 2, 2, 4, 4, 6, 6,
	/* 0x50-0x5F */
	4, 1, 5, 6, 5, 4, 3, 3, 2, 3, 1, 1, 1, 1, 1, 1,
	/* 0x60-0x6F */
	1, 9, 2, 5, 6, 12, 3, 3, 5, 9, 1, 1, 6, 4, 8, 8,
	/* 0x70-0x7F */
	4, 1, 7, 8, 7, 5, 3, 3, 2, 3, 1, 1, 1, 1, 1, 1,
	/* 0x80-0xFF: byte biner, distribusi flat */
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
}

// Header magic untuk identifikasi format
var headerMagic = [4]byte{'M', 'F', 'C', 'I'}

const headerVersion = 1


// ========== PRNG ==========

func fnv1aHash(key string) uint64 {
	h := uint64(14695981039346656037)
	for i := 0; i < len(key); i++ {
		h ^= uint64(key[i])
		h *= 1099511628211
	}
	return h
}

type xorshift64 struct{ state uint64 }

func newXS(seed uint64) *xorshift64 {
	if seed == 0 {
		seed = 1
	}
	return &xorshift64{state: seed}
}

func (x *xorshift64) next() uint64 {
	x.state ^= x.state << 13
	x.state ^= x.state >> 7
	x.state ^= x.state << 17
	return x.state
}

func buildFreq(key string) [256]float64 {
	freq := freqBase
	rng := newXS(fnv1aHash(key))
	for i := 255; i > 0; i-- {
		j := int(rng.next() % uint64(i+1))
		freq[i], freq[j] = freq[j], freq[i]
	}
	return freq
}

func ksInit(key string) *xorshift64 {
	seed := fnv1aHash(key) ^ 0xdeadbeefcafe
	if seed == 0 {
		seed = 0xdeadbeefcafe
	}
	return &xorshift64{state: seed}
}


// ========== Pohon Huffman ==========

type hnode struct {
	symbol int
	freq   float64
	order  int64
	child  [3]*hnode
}

type nodeHeap []*hnode

func (h nodeHeap) Len() int { return len(h) }
func (h nodeHeap) Less(i, j int) bool {
	if h[i].freq != h[j].freq {
		return h[i].freq < h[j].freq
	}
	return h[i].order < h[j].order
}
func (h nodeHeap) Swap(i, j int)       { h[i], h[j] = h[j], h[i] }
func (h *nodeHeap) Push(x interface{}) { *h = append(*h, x.(*hnode)) }
func (h *nodeHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[:n-1]
	return x
}

func buildTree(freq [256]float64) *hnode {
	h := &nodeHeap{}
	heap.Init(h)
	var counter int64
	for i := 0; i < 256; i++ {
		heap.Push(h, &hnode{symbol: i, freq: freq[i], order: counter})
		counter++
	}
	for (h.Len()-1)%2 != 0 {
		heap.Push(h, &hnode{symbol: -2, freq: 0, order: counter})
		counter++
	}
	for h.Len() > 1 {
		p := &hnode{symbol: -1, order: counter}
		counter++
		for d := 0; d < 3; d++ {
			c := heap.Pop(h).(*hnode)
			p.child[d] = c
			p.freq += c.freq
		}
		heap.Push(h, p)
	}
	return heap.Pop(h).(*hnode)
}

var codes [256][]int8

func extractCodes(n *hnode, path []int8) {
	if n == nil {
		return
	}
	if n.symbol >= 0 && n.symbol < 256 {
		cp := make([]int8, len(path))
		copy(cp, path)
		codes[n.symbol] = cp
		return
	}
	for d := 0; d < 3; d++ {
		extractCodes(n.child[d], append(path, int8(d)))
	}
}


// ========== Header ==========

// buildHeader membuat header yang menyimpan ekstensi asli.
// Format: MAGIC(4) | VERSION(1) | EXT_LEN(1) | EXT(n)
func buildHeader(ext string) []byte {
	ext = strings.TrimPrefix(ext, ".")
	ext = strings.ToLower(ext)
	if len(ext) > 31 {
		ext = ext[:31]
	}
	hdr := make([]byte, 6+len(ext))
	copy(hdr[0:4], headerMagic[:])
	hdr[4] = headerVersion
	hdr[5] = byte(len(ext))
	copy(hdr[6:], []byte(ext))
	return hdr
}

// parseHeader mengekstrak ekstensi dan payload dari hasil dekripsi.
// Kembalikan ("", data) jika header tidak valid.
func parseHeader(data []byte) (ext string, payload []byte) {
	if len(data) < 6 {
		return "", data
	}
	if [4]byte(data[0:4]) != headerMagic {
		return "", data
	}
	if data[4] != headerVersion {
		return "", data
	}
	extLen := int(data[5])
	if len(data) < 6+extLen {
		return "", data
	}
	return string(data[6 : 6+extLen]), data[6+extLen:]
}


// ========== Encoder & Decoder ==========

func encode(src []byte, key string) []byte {
	ks := ksInit(key)
	out := make([]byte, 0, len(src)*5)
	for _, b := range src {
		for _, d := range codes[int(b)] {
			kd := int(ks.next() % 3)
			cd := (int(d) + kd) % 3
			switch cd {
			case 0:
				out = append(out, 'm')
			case 1:
				out = append(out, 'f')
			default:
				out = append(out, ' ')
			}
		}
	}
	return out
}

func decode(src []byte, root *hnode, key string) []byte {
	ks := ksInit(key)
	out := make([]byte, 0, len(src)/4)
	cur := root
	for i, b := range src {
		var raw int
		switch b {
		case 'm':
			raw = 0
		case 'f':
			raw = 1
		case ' ':
			raw = 2
		default:
			continue
		}
		kd := int(ks.next() % 3)
		d := (raw - kd + 3) % 3
		cur = cur.child[d]
		if cur == nil {
			fmt.Fprintf(os.Stderr, "[-] Data korup pada posisi %d.\n", i)
			return out
		}
		if cur.symbol >= 0 && cur.symbol < 256 {
			out = append(out, byte(cur.symbol))
			cur = root
		}
	}
	return out
}


// ========== Entry Point ==========

func main() {
	if len(os.Args) != 5 {
		fmt.Fprintf(os.Stderr,
			"MFCIPHER - Ternary Huffman Cipher\nPenggunaan: %s [enc/dec] [input] [output] [key]\n",
			os.Args[0])
		os.Exit(1)
	}
	mode, inPath, outPath, key := os.Args[1], os.Args[2], os.Args[3], os.Args[4]
	if mode != "enc" && mode != "dec" {
		fmt.Fprintln(os.Stderr, "[-] Mode tidak valid. Gunakan 'enc' atau 'dec'.")
		os.Exit(1)
	}

	data, err := os.ReadFile(inPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "[-] Gagal membaca input:", err)
		os.Exit(1)
	}

	freq := buildFreq(key)
	root := buildTree(freq)
	extractCodes(root, nil)

	var result []byte

	if mode == "enc" {
		ext     := filepath.Ext(inPath)
		payload := append(buildHeader(ext), data...)
		result   = encode(payload, key)
		fmt.Fprintf(os.Stderr, "[+] Enkripsi selesai -> %s\n", outPath)

	} else {
		raw        := decode(data, root, key)
		ext, payload := parseHeader(raw)
		result       = payload

		if ext != "" {
			/* Terapkan ekstensi asli jika output belum punya ekstensi */
			if filepath.Ext(outPath) == "" {
				outPath = outPath + "." + ext
			}
			fmt.Fprintf(os.Stderr, "[+] Ekstensi asli dipulihkan: .%s\n", ext)
		}
		fmt.Fprintf(os.Stderr, "[+] Dekripsi selesai -> %s\n", outPath)
	}

	if err := os.WriteFile(outPath, result, 0644); err != nil {
		fmt.Fprintln(os.Stderr, "[-] Gagal menulis output:", err)
		os.Exit(1)
	}
}