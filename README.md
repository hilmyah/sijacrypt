# MFCIPHER

Sistem penyandian file berbasis **Ternary Huffman Coding** dengan alfabet output yang dibatasi pada tiga karakter: `m`, `f`, dan spasi (` `). Mendukung semua jenis file — teks, dokumen, gambar, audio, video, dan format biner lainnya. Sistem dilengkapi lapisan **ternary stream cipher** yang diaplikasikan setelah Huffman encoding, menghilangkan kebocoran statistik dari ciphertext.

---

## Konsep Algoritma

### Ternary Huffman Coding

Huffman Coding adalah algoritma kompresi lossless yang membangun pohon berdasarkan frekuensi kemunculan simbol. Pada MFCIPHER, basis pohon diubah menjadi **terner (3 cabang)**, di mana setiap cabang merepresentasikan satu karakter dari alfabet output:

| Digit Terner | Karakter Output |
|:---:|:---:|
| 0 | `m` |
| 1 | `f` |
| 2 | spasi |

Pohon dibangun untuk seluruh ruang byte (0–255), sehingga semua format file didukung secara native.

### Alur Enkripsi

```
File Input (format apa saja)
    |
    v
[1] Build FREQ dari key
    FNV-1a(key) --> seed --> xorshift64 --> Fisher-Yates shuffle pada FREQ[0..255]
    |
    v
[2] Bangun pohon Huffman terner dari FREQ yang telah diacak
    |
    v
[3] Prepend header ke plaintext
    MAGIC(4) | VERSION(1) | EXT_LEN(1) | EXT(n)   <- menyimpan ekstensi asli
    |
    v
[4] Huffman Encode: setiap byte (header + file) --> urutan digit terner {0,1,2}
    |
    v
[5] Ternary Stream Cipher: setiap digit d_i --> (d_i + k_i) mod 3
    di mana k_i adalah digit keystream dari xorshift64 dengan seed terpisah
    |
    v
Ciphertext: string karakter {m, f, ' '} -> disimpan sebagai file .mfc
```

Alur dekripsi adalah kebalikan langkah [5] kemudian [4], diikuti ekstraksi header untuk mendapatkan ekstensi asli, dengan pohon yang dibangun ulang secara deterministik dari key yang sama.

### Format Header

Header disisipkan di awal plaintext sebelum enkripsi, sehingga ikut terenkripsi bersama data:

```
Offset  Panjang  Isi
0       4        Magic: "MFCI"
4       1        Versi: 0x01
5       1        Panjang ekstensi (0-31 byte)
6       n        Ekstensi asli dalam ASCII lowercase (tanpa titik)
```

Pada saat dekripsi, header diekstrak dari hasil dekripsi dan ekstensi asli diterapkan kembali ke nama file output. Jika header tidak ditemukan (kompatibilitas ke belakang), output tetap ditulis tanpa ekstensi tambahan.

### Mekanisme Secret Key

Secret key mengontrol dua komponen yang saling independen:

**Komponen 1 — Shuffle FREQ (mengacak struktur pohon)**

```
key --> FNV-1a --> seed_shuffle --> xorshift64 --> Fisher-Yates pada FREQ[0..255]
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
| Shuffle | Fisher-Yates (255 turun ke 1) | Menghasilkan permutasi seragam, deterministik dengan seed yang sama |
| Stream cipher | Ternary XOR modulo 3 | Mempertahankan alfabet output, menghancurkan pola statistik |
| Ruang simbol | 256 byte (0x00-0xFF) | Mendukung semua format file secara native |

### Determinisme Lintas Bahasa

Seluruh implementasi menggunakan komponen yang menghasilkan hasil bit-identical:

1. FNV-1a dengan konstanta 64-bit eksplisit dan aritmetika modulo 2^64.
2. xorshift64 dengan shift parameter identik (13, 7, 17).
3. Fisher-Yates dengan urutan iterasi identik (255 turun ke 1).
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

Argumen `output` pada mode dekripsi adalah nama dasar file; ekstensi asli akan diterapkan secara otomatis dari header yang tersimpan di dalam ciphertext. Jika nama output sudah memiliki ekstensi, ekstensi tersebut dipertahankan.

### Enkripsi

```bash
./mfcipher_c  enc dokumen.pdf  dokumen.mfc "kunci-rahasia"
./mfcipher_go enc foto.jpg     foto.mfc    "kunci-rahasia"
./mfcipher_rs enc video.mp4   video.mfc   "kunci-rahasia"
python mfcipher.py enc arsip.docx arsip.mfc "kunci-rahasia"
```

### Dekripsi

```bash
./mfcipher_c  dec dokumen.mfc dokumen_recovered "kunci-rahasia"
# -> dokumen_recovered.pdf  (ekstensi dipulihkan dari header)

./mfcipher_go dec foto.mfc    foto_recovered    "kunci-rahasia"
# -> foto_recovered.jpg

./mfcipher_rs dec video.mfc   video_recovered   "kunci-rahasia"
# -> video_recovered.mp4

python mfcipher.py dec arsip.mfc arsip_recovered "kunci-rahasia"
# -> arsip_recovered.docx
```

### GUI (Python)

Jalankan `python gui.py` atau file `MFCIPHER_UI` hasil kompilasi PyInstaller. Pilih file target (format apa saja), masukkan secret key pada kolom yang tersedia, lalu klik **ENKRIPSI** atau **DEKRIPSI**.

- Enkripsi: output disimpan di direktori yang sama dengan ekstensi `.mfc`.
- Dekripsi: output disimpan di direktori yang sama dengan sufiks `_recovered` dan ekstensi asli yang dipulihkan secara otomatis.

---

## Format yang Didukung

MFCIPHER bekerja pada level byte mentah sehingga mendukung semua format file tanpa batasan:

| Kategori | Contoh Format |
|---|---|
| Dokumen | .pdf, .docx, .xlsx, .pptx, .odt, .txt |
| Gambar | .jpg, .png, .gif, .bmp, .webp, .tiff |
| Audio | .mp3, .flac, .wav, .aac, .ogg |
| Video | .mp4, .mkv, .avi, .mov, .webm |
| Arsip | .zip, .tar, .gz, .7z, .rar |
| Lainnya | Semua format biner atau teks |

---

## Kompatibilitas Lintas Bahasa

File yang dienkripsi oleh implementasi manapun dapat didekripsi oleh implementasi bahasa lain, selama key yang digunakan sama. Hal ini dijamin karena seluruh komponen (FNV-1a, xorshift64, Fisher-Yates, ternary XOR) bersifat deterministik dan menghasilkan hasil bit-identical di semua bahasa.

---

## Catatan

- File output berukuran lebih besar dari input karena setiap byte dikodekan menjadi beberapa karakter teks. Ini adalah konsekuensi yang disengaja dari pembatasan alfabet output menjadi tiga karakter.
- Tidak ada padding pada file output; seluruh konten adalah ciphertext murni ditambah header terenkripsi di awal.
- Seed keystream stream cipher dibuat berbeda dari seed shuffle secara eksplisit untuk menghindari korelasi antara kedua komponen.
- Header ikut terenkripsi sehingga tidak ada informasi ekstensi yang bocor pada ciphertext.