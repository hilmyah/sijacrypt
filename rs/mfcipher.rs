// MFCIPHER - Ternary Huffman Cipher dengan Secret Key
// Alfabet output: 'm' (0), 'f' (1), ' ' (2)
//
// Alur enkripsi:
//   1. Build FREQ dari key (FNV-1a + Fisher-Yates)
//   2. Bangun pohon Huffman terner dari FREQ
//   3. Encode plaintext -> digit terner (via Huffman)
//   4. XOR terner: (digit + keystream) mod 3   <- stream cipher
//
// Penggunaan: ./mfcipher [enc/dec] [input] [output] [key]

use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::env;
use std::fs;
use std::process;

const FREQ_BASE: [f64; 128] = [
    1.0,1.0,1.0,1.0,1.0,1.0,1.0,1.0,1.0,2.0,5.0,1.0,1.0,2.0,1.0,1.0,
    1.0,1.0,1.0,1.0,1.0,1.0,1.0,1.0,1.0,1.0,1.0,1.0,1.0,1.0,1.0,1.0,
    15.0,2.0,3.0,1.0,1.0,1.0,2.0,2.0,2.0,2.0,1.0,1.0,3.0,2.0,3.0,1.0,
    4.0,3.0,3.0,3.0,3.0,3.0,3.0,3.0,3.0,3.0,2.0,2.0,1.0,1.0,1.0,1.0,
    1.0,6.0,3.0,4.0,4.0,7.0,3.0,3.0,4.0,6.0,2.0,2.0,4.0,4.0,6.0,6.0,
    4.0,1.0,5.0,6.0,5.0,4.0,3.0,3.0,2.0,3.0,1.0,1.0,1.0,1.0,1.0,1.0,
    1.0,9.0,2.0,5.0,6.0,12.0,3.0,3.0,5.0,9.0,1.0,1.0,6.0,4.0,8.0,8.0,
    4.0,1.0,7.0,8.0,7.0,5.0,3.0,3.0,2.0,3.0,1.0,1.0,1.0,1.0,1.0,1.0,
];

// ========== PRNG ==========

fn fnv1a_hash(key: &str) -> u64 {
    let mut h: u64 = 14695981039346656037;
    for b in key.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(1099511628211);
    }
    h
}

struct Xorshift64 {
    state: u64,
}

impl Xorshift64 {
    fn new(seed: u64) -> Self {
        Self { state: if seed == 0 { 1 } else { seed } }
    }
    fn next(&mut self) -> u64 {
        self.state ^= self.state << 13;
        self.state ^= self.state >> 7;
        self.state ^= self.state << 17;
        self.state
    }
}

fn build_freq(key: &str) -> [f64; 128] {
    let mut freq = FREQ_BASE;
    let mut rng = Xorshift64::new(fnv1a_hash(key));
    for i in (1..=127usize).rev() {
        let j = (rng.next() % (i as u64 + 1)) as usize;
        freq.swap(i, j);
    }
    freq
}

fn ks_init(key: &str) -> Xorshift64 {
    let seed = fnv1a_hash(key) ^ 0xdeadbeefcafe_u64;
    Xorshift64::new(if seed == 0 { 0xdeadbeefcafe } else { seed })
}

// ========== Pohon Huffman ==========

#[derive(Debug)]
enum NodeKind {
    Leaf(u8),
    Internal([Box<HNode>; 3]),
    Dummy,
}

#[derive(Debug)]
struct HNode {
    freq:  f64,
    order: i64,
    kind:  NodeKind,
}

struct Item(Box<HNode>);

impl PartialEq for Item {
    fn eq(&self, o: &Self) -> bool {
        self.0.freq == o.0.freq && self.0.order == o.0.order
    }
}
impl Eq for Item {}
impl PartialOrd for Item {
    fn partial_cmp(&self, o: &Self) -> Option<Ordering> { Some(self.cmp(o)) }
}
impl Ord for Item {
    fn cmp(&self, o: &Self) -> Ordering {
        let fc = o.0.freq.partial_cmp(&self.0.freq).unwrap_or(Ordering::Equal);
        if fc != Ordering::Equal { return fc; }
        o.0.order.cmp(&self.0.order)
    }
}

fn build_tree(freq: &[f64; 128]) -> Box<HNode> {
    let mut heap = BinaryHeap::<Item>::new();
    let mut counter: i64 = 0;
    for i in 0u8..128 {
        heap.push(Item(Box::new(HNode {
            freq: freq[i as usize],
            order: counter,
            kind: NodeKind::Leaf(i),
        })));
        counter += 1;
    }
    while (heap.len() - 1) % 2 != 0 {
        heap.push(Item(Box::new(HNode { freq: 0.0, order: counter, kind: NodeKind::Dummy })));
        counter += 1;
    }
    while heap.len() > 1 {
        let c0 = heap.pop().unwrap().0;
        let c1 = heap.pop().unwrap().0;
        let c2 = heap.pop().unwrap().0;
        let total = c0.freq + c1.freq + c2.freq;
        heap.push(Item(Box::new(HNode {
            freq: total,
            order: counter,
            kind: NodeKind::Internal([c0, c1, c2]),
        })));
        counter += 1;
    }
    heap.pop().unwrap().0
}

fn extract_codes(node: &HNode, path: &mut Vec<u8>, codes: &mut [Vec<u8>; 128]) {
    match &node.kind {
        NodeKind::Leaf(sym) => { codes[*sym as usize] = path.clone(); }
        NodeKind::Internal(children) => {
            for (d, child) in children.iter().enumerate() {
                path.push(d as u8);
                extract_codes(child, path, codes);
                path.pop();
            }
        }
        NodeKind::Dummy => {}
    }
}

// ========== Encoder & Decoder ==========

fn encode(src: &[u8], codes: &[Vec<u8>; 128], key: &str) -> Vec<u8> {
    let mut ks = ks_init(key);
    let mut out = Vec::with_capacity(src.len() * 5);
    for &b in src {
        let sym = if b < 128 { b as usize } else { b'?' as usize };
        for &d in &codes[sym] {
            let kd = (ks.next() % 3) as u8;
            let cd = (d + kd) % 3;
            out.push(match cd { 0 => b'm', 1 => b'f', _ => b' ' });
        }
    }
    out
}

fn decode(src: &[u8], root: &HNode, key: &str) -> Vec<u8> {
    let mut ks  = ks_init(key);
    let mut out = Vec::with_capacity(src.len() / 5);
    let mut cur = root;
    for (i, &b) in src.iter().enumerate() {
        let raw: u64 = match b { b'm' => 0, b'f' => 1, b' ' => 2, _ => continue };
        let kd  = ks.next() % 3;
        let d   = ((raw + 3 - kd) % 3) as usize;
        match &cur.kind {
            NodeKind::Internal(children) => { cur = &children[d]; }
            _ => {
                eprintln!("[-] Data korup pada posisi {}.", i);
                return out;
            }
        }
        if let NodeKind::Leaf(sym) = cur.kind {
            out.push(sym);
            cur = root;
        }
    }
    out
}

// ========== Entry Point ==========

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 5 {
        eprintln!(
            "MFCIPHER - Ternary Huffman Cipher\nPenggunaan: {} [enc/dec] [input] [output] [key]",
            args[0]
        );
        process::exit(1);
    }
    let (mode, in_path, out_path, key) = (&args[1], &args[2], &args[3], &args[4]);
    if mode != "enc" && mode != "dec" {
        eprintln!("[-] Mode tidak valid. Gunakan 'enc' atau 'dec'.");
        process::exit(1);
    }

    let data = fs::read(in_path).expect("[-] Gagal membaca file input.");
    let freq  = build_freq(key);
    let root  = build_tree(&freq);
    let mut codes: [Vec<u8>; 128] = std::array::from_fn(|_| Vec::new());
    extract_codes(&root, &mut Vec::new(), &mut codes);

    let result = if mode == "enc" {
        let r = encode(&data, &codes, key);
        eprintln!("[+] Enkripsi selesai -> {}", out_path);
        r
    } else {
        let r = decode(&data, &root, key);
        eprintln!("[+] Dekripsi selesai -> {}", out_path);
        r
    };

    fs::write(out_path, &result).expect("[-] Gagal menulis file output.");
}