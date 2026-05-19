# MFCIPHER

Sistem penyandian teks berbasis **Ternary Huffman Coding** dengan alfabet output yang dibatasi secara ketat pada tiga karakter: `m`, `f`, dan spasi. Proyek ini mengimplementasikan logika yang sepenuhnya identik di empat bahasa pemrograman (C, Go, Rust, Python) beserta antarmuka grafis berbasis Python.

---

## Konsep Algoritma

### Ternary Huffman Coding

Huffman Coding adalah algoritma kompresi lossless yang membangun pohon berdasarkan frekuensi kemunculan simbol. Pada MFCIPHER, basis pohon diubah menjadi **terner (3 cabang)**, di mana setiap cabang merepresentasikan satu karakter dari alfabet output:

| Digit Terner | Karakter Output |
|:---:|:---:|
| 0 | `m` |
| 1 | `f` |
| 2 | spasi |

Setiap simbol ASCII (0-127) dipetakan ke kode terner dengan panjang bervariasi. Simbol yang sering muncul (spasi, huruf vokal, huruf kecil umum) mendapat kode pendek (2-3 digit), sedangkan simbol yang jarang muncul mendapat kode lebih panjang (5-7 digit). Rata-rata panjang kode untuk teks bahasa alami adalah sekitar 3-4 digit per karakter.

Tabel frekuensi yang digunakan bersifat **statis dan deterministik**, identik di seluruh implementasi. Hal ini memungkinkan file yang dienkripsi di satu bahasa dapat didekripsi menggunakan implementasi bahasa lain tanpa konfigurasi tambahan.

### Determinisme Lintas Bahasa

Saat terdapat banyak simbol dengan frekuensi identik, urutan penyisipan ke dalam heap akan menentukan struktur pohon yang terbentuk. Untuk menjamin hasil enkripsi identik di semua implementasi, seluruh node menggunakan **tie-breaking berdasarkan insertion order**: node yang lebih awal dimasukkan ke heap mendapat prioritas lebih tinggi saat frekuensi sama.

### Pertimbangan Pemilihan Metode

Sebelum memilih Ternary Huffman, beberapa metode kompresi dengan alfabet 3 simbol dievaluasi:

| Metode | Panjang Rata-rata | Determinisme | Kompleksitas |
|---|:---:|:---:|:---:|
| Base-3 Fixed-Length | 5 digit/karakter | Ya | Rendah |
| Ternary Huffman | ~3-4 digit/karakter | Ya | Sedang |
| Arithmetic Coding (basis 3) | ~2.9 digit/karakter | Tidak* | Tinggi |

*Arithmetic Coding bergantung pada presisi aritmetika titik-mengambang yang tidak konsisten lintas platform dan bahasa, sehingga tidak cocok untuk use case kompatibilitas lintas bahasa.

---

## Struktur Direktori

```
mfcipher/
├── mfcipher.c     Implementasi C (performa tinggi, zero external dependencies)
├── mfcipher.go    Implementasi Go (kompilasi statis, container/heap)
├── mfcipher.rs    Implementasi Rust (keamanan memori, zero unsafe code)
├── mfcipher.py    Implementasi Python CLI
├── gui.py         Antarmuka grafis Python (CustomTkinter)
└── README.md
```

---

## Instruksi Kompilasi

### C

```bash
gcc mfcipher.c -o mfcipher_c -O2
```

### Go

```bash
go build -o mfcipher_go mfcipher.go
```

### Rust

```bash
rustc mfcipher.rs -o mfcipher_rs -C opt-level=2
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
[program] [enc/dec] [input] [output]
```

### Enkripsi

```bash
./mfcipher_c  enc dokumen.txt dokumen.mfc
./mfcipher_go enc dokumen.txt dokumen.mfc
./mfcipher_rs enc dokumen.txt dokumen.mfc
python mfcipher.py enc dokumen.txt dokumen.mfc
```

### Dekripsi

```bash
./mfcipher_c  dec dokumen.mfc dokumen_recovered.txt
./mfcipher_go dec dokumen.mfc dokumen_recovered.txt
./mfcipher_rs dec dokumen.mfc dokumen_recovered.txt
python mfcipher.py dec dokumen.mfc dokumen_recovered.txt
```

### GUI (Python)

Eksekusi `python gui.py` atau file `MFCIPHER_UI.exe` hasil kompilasi PyInstaller. Pilih file target, lalu klik tombol **ENKRIPSI** atau **DEKRIPSI**. File output disimpan di direktori yang sama dengan ekstensi `.mfc` (enkripsi) atau sufiks `_recovered.txt` (dekripsi).

---

## Kompatibilitas Lintas Bahasa

File yang dienkripsi oleh implementasi manapun dapat didekripsi oleh implementasi bahasa lain secara tepat, karena ketiga kondisi berikut terpenuhi:

1. Tabel frekuensi statis identik di seluruh implementasi.
2. Algoritma pembangunan pohon deterministik melalui tie-breaking insertion order.
3. Tidak ada state eksternal yang mempengaruhi struktur pohon.

---

## Catatan

- Format input yang didukung adalah file teks dengan encoding ASCII (karakter 0-127). Byte di luar rentang ini akan disubstitusi dengan karakter `?`.
- File output berukuran lebih besar dari input karena setiap byte dikodekan menjadi beberapa karakter teks. Ini adalah konsekuensi yang disengaja dari pembatasan alfabet output menjadi tiga karakter.
- Tidak ada header, metadata, atau padding pada file output; seluruh konten adalah ciphertext murni.
