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

use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::env;
use std::fs;
use std::path::Path;
use std::process;

// Frekuensi dasar untuk 256 simbol byte
const FREQ_BASE: [f64; 256] = [
    /* 0x00-0x0F */
    1.0,1.0,1.0,1.0,1.0,1.0,1.0,1.0,1.0,2.0,5.0,1.0,1.0,2.0,1.0,1.0,
    /* 0x10-0x1F */
    1.0,1.0,1.0,1.0,1.0,1.0,1.0,1.0,1.0,1.0,1.0,1.0,1.0,1.0,1.0,1.0,
    /* 0x20-0x2F */
    15.0,2.0,3.0,1.0,1.0,1.0,2.0,2.0,2.0,2.0,1.0,1.0,3.0,2.0,3.0,1.0,
    /* 0x30-0x3F */
    4.0,3.0,3.0,3.0,3.0,3.0,3.0,3.0,3.0,3.0,2.0,2.0,1.0,1.0,1.0,1.0,
    /* 0x40-0x4F */
    1.0,6.0,3.0,4.0,4.0,7.0,3.0,3.0,4.0,6.0,2.0,2.0,4.0,4.0,6.0,6.0,
    /* 0x50-0x5F */
    4.0,1.0,5.0,6.0,5.0,4.0,3.0,3.0,2.0,3.0,1.0,1.0,1.0,1.0,1.0,1.0,
    /* 0x60-0x6F */
    1.0,9.0,2.0,5.0,6.0,12.0,3.0,3.0,5.0,9.0,1.0,1.0,6.0,4.0,8.0,8.0,
    /* 0x70-0x7F */
    4.0,1.0,7.0,8.0,7.0,5.0,3.0,3.0,2.0,3.0,1.0,1.0,1.0,1.0,1.0,1.0,
    /* 0x80-0xFF: byte biner, distribusi flat */
    2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,
    2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,
    2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,
    2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,
    2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,
    2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,
    2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,
    2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,2.0,
];

const HEADER_MAGIC: &[u8; 4] = b"MFCI";
const HEADER_VERSION: u8 = 1;


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

fn build_freq(key: &str) -> [f64; 256] {
    let mut freq = FREQ_BASE;
    let mut rng = Xorshift64::new(fnv1a_hash(key));
    for i in (1..=255usize).rev() {
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
    Leaf(usize),
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

fn build_tree(freq: &[f64; 256]) -> Box<HNode> {
    let mut heap = BinaryHeap::<Item>::new();
    let mut counter: i64 = 0;
    for i in 0usize..256 {
        heap.push(Item(Box::new(HNode {
            freq: freq[i],
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

fn extract_codes(node: &HNode, path: &mut Vec<u8>, codes: &mut [Vec<u8>; 256]) {
    match &node.kind {
        NodeKind::Leaf(sym) => { codes[*sym] = path.clone(); }
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


// ========== Header ==========

fn build_header(ext: &str) -> Vec<u8> {
    let ext = ext.trim_start_matches('.').to_lowercase();
    let ext_bytes = ext.as_bytes();
    let ext_len = ext_bytes.len().min(31);
    let mut hdr = Vec::with_capacity(6 + ext_len);
    hdr.extend_from_slice(HEADER_MAGIC);
    hdr.push(HEADER_VERSION);
    hdr.push(ext_len as u8);
    hdr.extend_from_slice(&ext_bytes[..ext_len]);
    hdr
}

fn parse_header(data: &[u8]) -> (String, &[u8]) {
    if data.len() < 6 || &data[0..4] != HEADER_MAGIC || data[4] != HEADER_VERSION {
        return (String::new(), data);
    }
    let ext_len = data[5] as usize;
    if data.len() < 6 + ext_len {
        return (String::new(), data);
    }
    let ext     = String::from_utf8_lossy(&data[6..6 + ext_len]).into_owned();
    let payload = &data[6 + ext_len..];
    (ext, payload)
}


// ========== Encoder & Decoder ==========

fn encode(src: &[u8], codes: &[Vec<u8>; 256], key: &str) -> Vec<u8> {
    let mut ks = ks_init(key);
    let mut out = Vec::with_capacity(src.len() * 5);
    for &b in src {
        for &d in &codes[b as usize] {
            let kd = (ks.next() % 3) as u8;
            let cd = (d + kd) % 3;
            out.push(match cd { 0 => b'm', 1 => b'f', _ => b' ' });
        }
    }
    out
}

fn decode(src: &[u8], root: &HNode, key: &str) -> Vec<u8> {
    let mut ks  = ks_init(key);
    let mut out = Vec::with_capacity(src.len() / 4);
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
            out.push(sym as u8);
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
    let mut codes: [Vec<u8>; 256] = std::array::from_fn(|_| Vec::new());
    extract_codes(&root, &mut Vec::new(), &mut codes);

    let (result, final_out_path) = if mode == "enc" {
        let ext     = Path::new(in_path).extension()
                          .and_then(|e| e.to_str()).unwrap_or("");
        let mut payload = build_header(ext);
        payload.extend_from_slice(&data);
        let r = encode(&payload, &codes, key);
        eprintln!("[+] Enkripsi selesai -> {}", out_path);
        (r, out_path.clone())
    } else {
        let raw          = decode(&data, &root, key);
        let (ext, payload) = parse_header(&raw);
        let final_path   = if !ext.is_empty() && Path::new(out_path).extension().is_none() {
            eprintln!("[+] Ekstensi asli dipulihkan: .{}", ext);
            format!("{}.{}", out_path, ext)
        } else {
            out_path.clone()
        };
        eprintln!("[+] Dekripsi selesai -> {}", final_path);
        (payload.to_vec(), final_path)
    };

    fs::write(&final_out_path, &result).expect("[-] Gagal menulis file output.");
}