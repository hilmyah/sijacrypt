<div align="center">
  <h1>MFCIPHER</h1>
  <p>Sistem penyandian berkas berbasis Ternary Huffman Coding dengan alfabet keluaran terbatas pada tiga karakter dan lapisan Ternary Stream Cipher.</p>
</div>

<p align="center">
  <img src="https://img.shields.io/badge/Rust-%3E%3D1.65-CE422B?logo=rust&logoColor=white" alt="Rust">
  <img src="https://img.shields.io/badge/Python-%3E%3D3.8-3776AB?logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/Go-%3E%3D1.19-00ADD8?logo=go&logoColor=white" alt="Go">
  <img src="https://img.shields.io/badge/C-C99-A8B9CC?logo=c&logoColor=white" alt="C">
</p>

---

MFCIPHER adalah sistem penyandian berkas yang mengompresi dan mengenkripsi seluruh jenis berkas menggunakan Ternary Huffman Coding dengan alfabet keluaran yang dibatasi pada tiga karakter: `m`, `f`, dan spasi (` `). Sistem dilengkapi lapisan Ternary Stream Cipher yang diaplikasikan setelah proses Huffman encoding untuk menghilangkan kebocoran statistik dari ciphertext.

Algoritma dirancang dengan pendekatan deterministik murni sehingga berkas yang dienkripsi menggunakan implementasi satu bahasa dapat didekripsi oleh implementasi bahasa lain selama kunci yang digunakan sama. Tersedia empat implementasi bahasa (C, Go, Python, Rust) serta antarmuka grafis berbasis Python.

## Daftar Isi

- [Fitur](#fitur)
- [Konsep dan Arsitektur](#konsep-dan-arsitektur)
- [Struktur Repository](#struktur-repository)
- [Prasyarat](#prasyarat)
- [Instalasi](#instalasi)
- [Manajemen dan Operasional](#manajemen-dan-operasional)
- [Catatan](#catatan)
- [Lisensi](#lisensi)

---

## Fitur

| Fitur | Deskripsi |
| --- | --- |
| Ternary Huffman Coding | Mengompresi dan memetakan ruang byte data menjadi struktur pohon terner (3 cabang) menggunakan alfabet khusus. Pohon dibangun untuk seluruh ruang byte (0-255) sehingga semua format berkas didukung secara native. |
| Batasan Alfabet | Membatasi elemen ciphertext hanya pada tiga karakter statis: `m`, `f`, dan karakter spasi (` `). |
| Ternary Stream Cipher | Lapisan enkripsi tambahan setelah proses encoding untuk mengacak distribusi frekuensi karakter secara deterministik, menghilangkan pola statistik pada ciphertext. |
| Pemulihan Ekstensi | Menyimpan metadata ekstensi asli secara aman di dalam header terenkripsi untuk rekonstruksi berkas otomatis saat dekripsi. |
| Kompatibilitas Lintas Bahasa | Implementasi C, Go, Python, dan Rust menghasilkan output bit-identik; berkas yang dienkripsi oleh satu implementasi dapat didekripsi oleh implementasi bahasa lain selama kunci yang digunakan sama. |
| Antarmuka GUI | Antarmuka grafis berbasis CustomTkinter untuk operasi enkripsi dan dekripsi tanpa menggunakan terminal. |

### Format yang Didukung

Sistem beroperasi pada level byte mentah, sehingga mendukung seluruh format berkas tanpa batasan:

| Kategori | Contoh Format |
| --- | --- |
| Dokumen | `.pdf`, `.docx`, `.xlsx`, `.pptx`, `.odt`, `.txt` |
| Gambar | `.jpg`, `.png`, `.gif`, `.bmp`, `.webp`, `.tiff` |
| Audio | `.mp3`, `.flac`, `.wav`, `.aac`, `.ogg` |
| Video | `.mp4`, `.mkv`, `.avi`, `.mov`, `.webm` |
| Arsip | `.zip`, `.tar`, `.gz`, `.7z`, `.rar` |
| Lainnya | Semua format biner atau teks |

---

## Konsep dan Arsitektur

### Ternary Huffman Coding

Huffman Coding konvensional menggunakan basis biner (2 cabang). MFCIPHER memodifikasi arsitektur pohon menjadi berbasis terner (3 cabang) untuk mengakomodasi pembatasan alfabet keluaran. Setiap cabang merepresentasikan satu karakter fisik:

| Digit Terner | Karakter Output |
| :---: | :---: |
| 0 | `m` |
| 1 | `f` |
| 2 | spasi (` `) |

### Alur Enkripsi

```
Berkas Input (format apa saja)
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
[4] Huffman Encode: setiap byte (header + berkas) --> urutan digit terner {0, 1, 2}
    |
    v
[5] Ternary Stream Cipher: setiap digit d_i --> (d_i + k_i) mod 3
    k_i adalah digit keystream dari xorshift64 dengan seed terpisah
    |
    v
Ciphertext: string karakter {m, f, ' '} --> disimpan sebagai berkas .mfc
```

### Alur Dekripsi

Alur dekripsi adalah kebalikan matematis dari alur enkripsi:

1. Baca berkas `.mfc`, terjemahkan susunan karakter alfabet kembali menjadi deret digit terner (0, 1, 2).
2. Dekripsi lapisan stream cipher menggunakan operasi inversi modular: `huffman_digit = (cipherdigit - keystream_digit + 3) mod 3`.
3. Bangun ulang pohon Huffman terner yang identik menggunakan kunci yang sama.
4. Lakukan decoding deret terner kembali menuju byte data mentah.
5. Pisahkan blok header, baca metadata ekstensi asli, tulis berkas output dengan sufiks `_recovered`.

### Format Header

Header disisipkan di awal plaintext sebelum enkripsi sehingga ikut terenkripsi bersama data:

| Offset | Panjang | Isi |
| --- | --- | --- |
| 0 | 4 byte | Magic: `MFCI` |
| 4 | 1 byte | Versi: `0x01` |
| 5 | 1 byte | Panjang ekstensi (0-31 byte) |
| 6 | n byte | Ekstensi asli dalam ASCII lowercase tanpa titik |

Jika header tidak ditemukan saat dekripsi (kompatibilitas ke belakang), output tetap ditulis tanpa ekstensi tambahan.

### Mekanisme Secret Key

Secret key mengontrol dua komponen yang saling independen:

**Komponen 1 - Shuffle FREQ (mengacak struktur pohon)**

```
key --> FNV-1a --> seed_shuffle --> xorshift64 --> Fisher-Yates pada FREQ[0..255]
```

Mengubah pemetaan simbol ke kode Huffman. Tanpa kunci yang benar, pohon yang dibangun berbeda sehingga dekripsi menghasilkan output yang salah.

**Komponen 2 - Ternary Stream Cipher (menghancurkan pola statistik)**

```
key --> FNV-1a --> seed_shuffle XOR 0xDEADBEEFCAFE --> xorshift64 --> keystream
```

Seed keystream dibuat berbeda dari seed shuffle menggunakan operasi XOR dengan konstanta tetap. Setiap digit terner hasil Huffman dimodifikasi:

```
enkripsi : cipherdigit    = (huffman_digit + keystream_digit) mod 3
dekripsi : huffman_digit  = (cipherdigit  - keystream_digit + 3) mod 3
```

### Komponen Teknis

| Komponen | Pilihan | Alasan |
| --- | --- | --- |
| Hash fungsi | FNV-1a 64-bit | Deterministik, sederhana, mudah diimplementasikan identik di semua bahasa; aritmetika modulo 2^64 eksplisit. |
| PRNG | xorshift64 (shift: 13, 7, 17) | Periode panjang, bebas dependensi eksternal, hasil identik lintas platform. |
| Shuffle | Fisher-Yates (iterasi 255 turun ke 1) | Menghasilkan permutasi seragam dan deterministik dengan seed yang sama. |
| Stream cipher | Ternary XOR modulo 3 | Mempertahankan alfabet output tiga karakter sekaligus menghancurkan pola statistik. |
| Ruang simbol | 256 byte (0x00-0xFF) | Mendukung semua format berkas secara native tanpa dependensi eksternal. |

---

## Struktur Repository

```
mfcipher/
├── mfcipher.c        Implementasi C.
├── mfcipher.go       Implementasi Go.
├── mfcipher.rs       Implementasi Rust.
├── mfcipher.py       Implementasi Python (CLI).
├── gui.py            Implementasi Python (GUI, CustomTkinter).
└── README.md
```

---

## Prasyarat

Setiap implementasi bahasa bersifat independen; hanya instal komponen yang sesuai dengan implementasi yang akan digunakan.

| Komponen | Versi Minimal | Keterangan |
| --- | --- | --- |
| Python | >= 3.8 | Diperlukan untuk CLI Python dan antarmuka GUI. |
| Rust | >= 1.65 (Edition 2021) | Diperlukan untuk kompilasi implementasi Rust. |
| Go | >= 1.19 | Diperlukan untuk kompilasi implementasi Go. |
| C Compiler | GCC / Clang (C99) | Diperlukan untuk kompilasi implementasi C. |

---

## Instalasi

```bash
git clone https://github.com/hilmyah/sijacrypt.git
cd sijacrypt
```

---

## Manajemen dan Operasional

### Kompilasi

**C**

```bash
gcc mfcipher.c -o mfcipher_c -O2
```

**Go**

```bash
go build -o mfcipher_go mfcipher.go
```

**Rust**

```bash
rustc mfcipher.rs -o mfcipher_rs -C opt-level=2
```

**Python**

Tidak memerlukan kompilasi. Untuk mengemas GUI menjadi executable mandiri:

```bash
pip install customtkinter pyinstaller
python -m PyInstaller --noconsole --onefile --name "MFCIPHER_UI" gui.py
```

### Penggunaan CLI

Pola argumen:

```
[program] [enc/dec] [input] [output] [key]
```

Argumen `output` pada mode dekripsi adalah nama dasar berkas; ekstensi asli diterapkan secara otomatis dari header yang tersimpan di dalam ciphertext. Jika nama output sudah memiliki ekstensi, ekstensi tersebut dipertahankan.

**Enkripsi**

```bash
./mfcipher_c  enc dokumen.pdf  dokumen.mfc  "kunci-rahasia"
./mfcipher_go enc foto.jpg     foto.mfc     "kunci-rahasia"
./mfcipher_rs enc video.mp4    video.mfc    "kunci-rahasia"
python mfcipher.py enc arsip.docx arsip.mfc "kunci-rahasia"
```

**Dekripsi**

```bash
./mfcipher_c  dec dokumen.mfc dokumen_recovered  "kunci-rahasia"
# -> dokumen_recovered.pdf

./mfcipher_go dec foto.mfc    foto_recovered     "kunci-rahasia"
# -> foto_recovered.jpg

./mfcipher_rs dec video.mfc   video_recovered    "kunci-rahasia"
# -> video_recovered.mp4

python mfcipher.py dec arsip.mfc arsip_recovered "kunci-rahasia"
# -> arsip_recovered.docx
```

### Penggunaan GUI

Jalankan `python gui.py` atau file `MFCIPHER_UI` hasil kompilasi PyInstaller. Pilih berkas target, masukkan secret key pada kolom yang tersedia, lalu klik **ENKRIPSI** atau **DEKRIPSI**.

- Enkripsi: output disimpan di direktori yang sama dengan ekstensi `.mfc`.
- Dekripsi: output disimpan di direktori yang sama dengan sufiks `_recovered` dan ekstensi asli yang dipulihkan secara otomatis.

---

## Catatan

- **Ukuran berkas output**: Berkas `.mfc` akan memiliki ukuran lebih besar dibandingkan berkas asal karena satu byte plaintext direpresentasikan sebagai beberapa karakter teks untuk memenuhi batasan tiga karakter alfabet. Ini adalah konsekuensi yang disengaja dari desain sistem.
- **Tanpa padding**: Berkas output tidak memiliki byte kosong tambahan. Seluruh konten adalah ciphertext murni ditambah blok header terenkripsi di bagian awal.
- **Separasi seed**: Seed untuk pengacakan pohon (shuffle) dan seed untuk keystream stream cipher sengaja dibuat berbeda menggunakan operasi XOR dengan konstanta tetap untuk meminimalkan korelasi pola statistik antara kedua komponen.
- **Proteksi metadata**: Blok header ikut diproses menggunakan lapisan stream cipher yang sama sehingga informasi ekstensi asli tidak dapat dibaca dari ciphertext tanpa kunci yang benar.

---

## Lisensi

Repository ini tidak memiliki berkas `LICENSE`. Status lisensi belum dideklarasikan secara resmi.

---

<div align="center">
  <sub>MFCIPHER (Sijacrypt) - Sistem Penyandian Berkas Ternary</sub>
</div>
