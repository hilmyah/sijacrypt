# MFCIPHER

Sistem penyandian teks berbasis **Ternary Huffman Coding** dengan alfabet output yang dibatasi pada tiga karakter: `m`, `f`, dan spasi (` `). Sistem dilengkapi lapisan **ternary stream cipher** yang diaplikasikan setelah Huffman encoding, menghilangkan kebocoran statistik dari ciphertext.

---

## Konsep Algoritma

### Ternary Huffman Coding

Huffman Coding adalah algoritma kompresi lossless yang membangun pohon berdasarkan frekuensi kemunculan simbol. Pada MFCIPHER, basis pohon diubah menjadi **terner (3 cabang)**, di mana setiap cabang merepresentasikan satu karakter dari alfabet output:

| Digit Terner | Karakter Output |
|:---:|:---:|
| 0 | `m` |
| 1 | `f` |
| 2 | spasi |

### Alur Enkripsi

```
Plaintext
    |
    v
[1] Build FREQ dari key
    FNV-1a(key) --> seed --> xorshift64 --> Fisher-Yates shuffle pada FREQ[0..127]
    |
    v
[2] Bangun pohon Huffman terner dari FREQ yang telah diacak
    |
    v
[3] Huffman Encode: setiap byte plaintext --> urutan digit terner {0,1,2}
    |
    v
[4] Ternary Stream Cipher: setiap digit d_i --> (d_i + k_i) mod 3
    di mana k_i adalah digit keystream dari xorshift64 dengan seed terpisah
    |
    v
Ciphertext: string karakter {m, f, ' '}
```

Alur dekripsi adalah kebalikan langkah [4] kemudian [3], dengan pohon yang dibangun ulang secara deterministik dari key yang sama.

### Mekanisme Secret Key

Secret key mengontrol dua komponen yang saling independen:

**Komponen 1 — Shuffle FREQ (mengacak struktur pohon)**

```
key --> FNV-1a --> seed_shuffle --> xorshift64 --> Fisher-Yates pada FREQ[0..127]
```

Mengubah pemetaan simbol ke kode Huffman. Tanpa key yang benar, pohon yang dibangun berbeda sehingga dekripsi menghasilkan output yang salah.

**Komponen 2 — Ternary Stream Cipher (menghancurkan pola statistik)**

```
key --> FNV-1a --> seed_shuffle XOR 0xDEADBEEFCAFE --> xorshift64 --> keystream
```

Seed keystream sengaja dibuat berbeda dari seed shuffle menggunakan operasi XOR dengan konstanta tetap. Setiap digit terner hasil Huffman dimodifikasi sebagai:

```
enkripsi : cipherdigit = (huffman_digit + keystream_digit) mod 3
dekripsi : huffman_digit = (cipherdigit - keystream_digit + 3) mod 3
```

### Komponen yang Digunakan

| Komponen | Pilihan | Alasan |
|---|---|---|
| Hash fungsi | FNV-1a 64-bit | Deterministik, sederhana, mudah diimplementasi identik di semua bahasa |
| PRNG | xorshift64 (shift: 13, 7, 17) | Periode panjang, bebas dependensi, hasil identik lintas platform |
| Shuffle | Fisher-Yates (127 turun ke 1) | Menghasilkan permutasi seragam, deterministik dengan seed yang sama |
| Stream cipher | Ternary XOR modulo 3 | Mempertahankan alfabet output, menghancurkan pola statistik |

### Determinisme Lintas Bahasa

Seluruh implementasi menggunakan komponen yang menghasilkan hasil bit-identical:

1. FNV-1a dengan konstanta 64-bit eksplisit dan aritmetika modulo 2^64.
2. xorshift64 dengan shift parameter identik (13, 7, 17).
3. Fisher-Yates dengan urutan iterasi identik (127 turun ke 1).
4. Ternary XOR dengan seed keystream identik (`seed_shuffle XOR 0xDEADBEEFCAFE`).
5. Tie-breaking heap berdasarkan insertion order.

## Struktur Direktori

```
mfcipher/
├── mfcipher.c     Implementasi C
├── mfcipher.go    Implementasi Go
├── mfcipher.rs    Implementasi Rust
├── mfcipher.py    Implementasi Python (CLI)
├── gui.py         Implementasi Python (GUI, CustomTkinter)
└── README.md
```

---

## Instruksi Kompilasi

### C

```bash
gcc mfcipher.c -o mfcipher_c.exe -O2
```

### Go

```bash
go build -o mfcipher_go.exe mfcipher.go
```

### Rust

```bash
rustc mfcipher.rs -o mfcipher_rs.exe -C opt-level=2
```

### Python

Tidak memerlukan kompilasi. Untuk mengemas GUI menjadi executable mandiri:

```bash
pip install customtkinter pyinstaller
python -m PyInstaller --noconsole --onefile --name "MFCIPHER_UI" gui.py
```

---

## Instruksi Penggunaan

### Pola Argumen CLI

```
[program] [enc/dec] [input] [output] [key]
```

### Enkripsi

```bash
./mfcipher_c.exe  enc dokumen.txt dokumen.mfc "kunci-rahasia"
./mfcipher_go.exe enc dokumen.txt dokumen.mfc "kunci-rahasia"
./mfcipher_rs.exe enc dokumen.txt dokumen.mfc "kunci-rahasia"
python mfcipher.py enc dokumen.txt dokumen.mfc "kunci-rahasia"
```

### Dekripsi

```bash
./mfcipher_c.exe  dec dokumen.mfc dokumen_recovered.txt "kunci-rahasia"
./mfcipher_go.exe dec dokumen.mfc dokumen_recovered.txt "kunci-rahasia"
./mfcipher_rs.exe dec dokumen.mfc dokumen_recovered.txt "kunci-rahasia"
python mfcipher.py dec dokumen.mfc dokumen_recovered.txt "kunci-rahasia"
```

### GUI (Python)

Jalankan `python gui.py` atau file `MFCIPHER_UI.exe` hasil kompilasi PyInstaller. Pilih file target, masukkan secret key pada kolom yang tersedia, lalu klik **ENKRIPSI** atau **DEKRIPSI**. File output disimpan di direktori yang sama dengan ekstensi `.mfc` (enkripsi) atau sufiks `_recovered.txt` (dekripsi).

---

## Kompatibilitas Lintas Bahasa

File yang dienkripsi oleh implementasi manapun dapat didekripsi oleh implementasi bahasa lain, selama key yang digunakan sama. Hal ini dijamin karena seluruh komponen (FNV-1a, xorshift64, Fisher-Yates, ternary XOR) bersifat deterministik dan menghasilkan hasil bit-identical di semua bahasa.

---

## Catatan

- Format input yang didukung adalah file teks dengan encoding ASCII (karakter 0-127). Byte di luar rentang ini disubstitusi dengan karakter `?`.
- File output berukuran lebih besar dari input karena setiap byte dikodekan menjadi beberapa karakter teks. Ini adalah konsekuensi yang disengaja dari pembatasan alfabet output menjadi tiga karakter.
- Tidak ada header, metadata, atau padding pada file output; seluruh konten adalah ciphertext murni.
- Seed keystream stream cipher dibuat berbeda dari seed shuffle secara eksplisit untuk menghindari korelasi antara kedua komponen.