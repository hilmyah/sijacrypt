<div align="center">
  <h1>MFCIPHER (Sijacrypt)</h1>
  <p>Sistem penyandian berkas berbasis Ternary Huffman Coding dengan alfabet keluaran terbatas dan lapisan Ternary Stream Cipher.</p>
</div>

![Rust](https://img.shields.io/badge/Rust-1.x-orange?logo=rust&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.x-blue?logo=python&logoColor=white)
![Go](https://img.shields.io/badge/Go-1.x-00ADD8?logo=go&logoColor=white)
![C](https://img.shields.io/badge/C-C99-A8B9CC?logo=c&logoColor=white)

## Fitur

| Fitur | Deskripsi |
| --- | --- |
| Ternary Huffman Coding | Mengompresi dan memetakan ruang byte data menjadi struktur pohon terner (3 cabang) menggunakan alfabet khusus. |
| Batasan Alfabet | Membatasi elemen cipher teks hanya pada tiga karakter statis yaitu `m`, `f`, dan karakter spasi. |
| Ternary Stream Cipher | Lapisan enkripsi tambahan setelah proses encoding untuk mengacak distribusi frekuensi karakter secara deterministik. |
| Pemulihan Ekstensi | Menyimpan metadata ekstensi asli secara aman di dalam header terenkripsi untuk proses rekonstruksi berkas otomatis. |
| Kompatibilitas Lintas Bahasa | Implementasi algoritma menghasilkan bit biner yang identik di seluruh varian bahasa pemrograman (C, Go, Python, Rust). |

## Konsep dan Arsitektur

### Ternary Huffman Coding

Huffman Coding konvensional menggunakan basis biner (2 cabang). Proyek ini memodifikasi arsitektur pohon menjadi berbasis terner (3 cabang) untuk mengakomodasi pembatasan alfabet keluaran. Setiap cabang merepresentasikan satu karakter fisik:

| Digit Terner | Karakter Alfabet Output |
| :---: | --- |
| 0 | `m` |
| 1 | `f` |
| 2 | Karakter Spasi (` `) |

Struktur pohon dibangun secara dinamis mencakup seluruh ruang byte (indeks 0 hingga 255), menjamin seluruh jenis tipe berkas biner dapat dipetakan tanpa kegagalan transfer data.

### Alur Enkripsi

Proses enkripsi mengubah berkas mentah menjadi format sandi terner melalui tahapan berikut:

```text
Berkas Input (Format Bebas)
    |
    v
[1] Inisialisasi Kunci (Key)
    FNV-1a(key) --> Seed Utama --> xorshift64 --> Fisher-Yates Shuffle pada tabel FREQ[0..255]
    |
    v
[2] Konstruksi Pohon
    Membangun struktur pohon Huffman terner berdasarkan nilai FREQ yang telah diacak
    |
    v
[3] Penyusunan Header
    Menyusun blok data: MAGIC(4 byte) | VERSION(1 byte) | EXT_LEN(1 byte) | EXT(n byte)
    |
    v
[4] Proses Encoding
    Melakukan encode Huffman Terner pada gabungan struktur Header dan Plaintext berkas
    |
    v
[5] Lapisan Stream Cipher Terner
    Menghasilkan keystream terner (0, 1, 2) menggunakan generator xorshift64 (Seed Kedua)
    Eksekusi operasi matematika terner: c = (p + k) mod 3
    |
    v
[6] Pemetaan Alfabet
    Mengonversi digit hasil cipher terner menjadi karakter fisik ('m', 'f', ' ')
    |
    v
Berkas Output (.mfc)

```

### Alur Dekripsi

Proses dekripsi merupakan kebalikan matematis dari alur enkripsi untuk memulihkan data asal:

1. Membaca berkas biner `.mfc` lalu menerjemahkan kembali susunan alfabet teks menjadi deret digit terner (0, 1, 2).
2. Mengeksekusi dekripsi lapisan stream cipher terner untuk memulihkan bitstream asli menggunakan operasi inversi modular: `p = (c - k + 3) mod 3`.
3. Membangun ulang struktur pohon Huffman terner yang identik menggunakan penurunan nilai *seed* dari parameter kunci (*key*) yang sama.
4. Melakukan operasi *decoding* dari deret terner kembali menuju bentuk byte data mentah.
5. Memisahkan struktur blok header, membaca metadata ukuran dan nama ekstensi asli, kemudian menuliskan kembali berkas utuh ke media penyimpanan dengan sufiks `_recovered`.

## Format yang Didukung

Sistem beroperasi pada level pemrosesan byte mentah (raw bytes), sehingga mampu memproses seluruh format berkas tanpa dependensi eksternal:

| Kategori | Contoh Format Ekstensi Berkas |
| --- | --- |
| Dokumen | .pdf, .docx, .xlsx, .pptx, .odt, .txt |
| Gambar | .jpg, .png, .gif, .bmp, .webp, .tiff |
| Audio | .mp3, .flac, .wav, .aac, .ogg |
| Video | .mp4, .mkv, .avi, .mov, .webm |
| Arsip | .zip, .tar, .gz, .7z, .rar |

## Kompatibilitas Lintas Bahasa

Algoritma dirancang dengan pendekatan deterministik murni. Komponen FNV-1a, xorshift64, Fisher-Yates shuffle, dan aritmatika modular terner diimplementasikan secara matematis serupa di setiap bahasa pemrograman. Berkas yang dikunci menggunakan skrip Python dapat dibuka kembali secara valid menggunakan program berbasis Rust, C, maupun Go selama parameter kunci (*key*) yang dimasukkan tepat sama.

## Prasyarat

| Komponen Bahasa | Versi Minimal | Keterangan |
| --- | --- | --- |
| Python | >= 3.8 | Diperlukan untuk modul CLI dan visualisasi GUI Tkinter |
| Rust | >= 1.65 (Edition 2021) | Kebutuhan kompilasi kode native performa tinggi |
| Go | >= 1.19 | Kebutuhan kompilasi paket dependensi Go |
| C Compiler | GCC / Clang (C99) | Kompilasi dependensi tingkat rendah |

## Instalasi

Kloning repositori kerja ke dalam komputer lokal:

```bash
git clone [https://github.com/hilmyah/sijacrypt.git](https://github.com/hilmyah/sijacrypt.git)
cd sijacrypt

```

## Struktur Direktori

| Direktori atau File | Fungsi |
| --- | --- |
| `c/` | Implementasi inti algoritma menggunakan bahasa C. |
| `go/` | Implementasi modul enkripsi dan dekripsi menggunakan bahasa Go. |
| `py/` | Implementasi skrip pemrosesan berbasis bahasa Python. |
| `rs/` | Source code performa tinggi menggunakan bahasa Rust. |
| `gui.py` | Aplikasi antarmuka grafis desktop (GUI) berbasis Tkinter untuk mempermudah operasional pengguna. |

## Manajemen dan Operasional

### 1. Operasional Menggunakan Python (CLI & GUI)

Menjalankan aplikasi berbasis grafis desktop:

```bash
python gui.py

```

Menjalankan pemrosesan via terminal menggunakan skrip Python internal:

```bash
cd py
# Proses Enkripsi
python mfcipher.py encrypt dokumen.txt "kuncirahasia"
# Proses Dekripsi
python mfcipher.py decrypt dokumen.txt.mfc "kuncirahasia"

```

### 2. Operasional Menggunakan Rust

Masuk ke dalam folder spesifik, lakukan kompilasi rilis, lalu eksekusi berkas biner:

```bash
cd rs
rustc -O mfcipher.rs

# Proses Enkripsi
./mfcipher encrypt dokumen.txt "kuncirahasia"
# Proses Dekripsi
./mfcipher decrypt dokumen.txt.mfc "kuncirahasia"

```

### 3. Operasional Menggunakan Go

Eksekusi langsung menggunakan perkakas runtime Go:

```bash
cd go
# Proses Enkripsi
go run mfcipher.go encrypt dokumen.txt "kuncirahasia"
# Proses Dekripsi
go run mfcipher.go decrypt dokumen.txt.mfc "kuncirahasia"

```

### 4. Operasional Menggunakan Bahasa C

Lakukan kompilasi menggunakan kompiler GCC dengan standar C99:

```bash
cd c
gcc -O3 mfcipher.c -o mfcipher

# Proses Enkripsi
./mfcipher encrypt dokumen.txt "kuncirahasia"
# Proses Dekripsi
./mfcipher decrypt dokumen.txt.mfc "kuncirahasia"

```

## Catatan Penting

* **Volume Ukuran File**: Berkas luaran (.mfc) akan memiliki ukuran fisik lebih besar dibandingkan berkas asal. Hal ini terjadi karena representasi satu byte Plaintext dipecah menjadi deretan karakter teks alfabet terpisah guna memenuhi batasan arsitektur tiga karakter luaran.
* **Ketiadaan Data Padding**: Berkas sandi luaran bersifat presisi tanpa penambahan byte kosong (zero-padding). Seluruh data merupakan representasi Ciphertext murni beserta informasi blok header yang melekat di bagian awal.
* **Separasi Nilai Seed**: Nilai awal generator (*seed*) untuk kebutuhan pengacakan pohon (*shuffle*) diatur berbeda secara eksplisit dengan nilai generator untuk kebutuhan *keystream* guna meminimalkan korelasi pola distribusi statistik data sandi.
* **Proteksi Metadata**: Blok informasi header ikut diproses menggunakan lapisan enkripsi *stream cipher* yang sama, mengamankan ekstensi asli dari analisis struktur berkas pihak luar.
