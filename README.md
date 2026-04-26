# SIJACRYPT

Sistem keamanan data hibrida tingkat sistem berbasis Command Line Interface (CLI) dan Graphical User Interface (GUI). Proyek ini mendemonstrasikan konsistensi logika kriptografi lintas platform menggunakan arsitektur enkripsi kustom.

## Fitur Utama
1. Metadata Masking: Menyembunyikan format ekstensi asli file di dalam ciphertext dan memulihkannya secara otomatis saat proses dekripsi. File terenkripsi dipaksa menggunakan ekstensi .sija.
2. 3-Layer Hybrid Engine: Menggabungkan SHA-256 Key Expansion, Dynamic Position Shifting, dan Repeating-Key XOR pada level byte.
3. Cross-Language Compatibility: File yang dienkripsi menggunakan satu bahasa dapat didekripsi oleh implementasi bahasa lain secara presisi.

## Struktur Direktori
- /cpp   : Implementasi C++ (Performa maksimal, manajemen memori manual)
- /go    : Implementasi Golang (Kompilasi cepat, file biner statis)
- /py    : Implementasi Python 3 (CLI, eksekusi berbasis interpreter)
- /rs    : Implementasi Rust (Keamanan memori absolut)
- gui.py : Implementasi Antarmuka Grafis (Desktop) menggunakan Python (CustomTkinter)

## Instruksi Kompilasi (Build)
Untuk bahasa yang membutuhkan kompilasi menjadi file biner (.exe):
- Go: go build -o test_go.exe test.go
- Rust: rustc test.rs -o test_rs.exe
- C++: g++ test.cpp -o test_cpp.exe -O3
- GUI (Python): python -m PyInstaller --noconsole --onefile --name "SIJACRYPT_UI" gui.py

## Instruksi Penggunaan (CLI)
Pola argumen terminal: [program] [mode] [input_file] [output_file] [password]
Catatan: Parameter [output_file] pada implementasi terbaru diabaikan oleh sistem. Output akan otomatis menyesuaikan menjadi .sija (enkripsi) atau format asli (dekripsi).

### Mode Enkripsi
Contoh (Rust): ./test_rs.exe enc dokumen.txt dummy password123
Hasil: dokumen.sija (Format .txt dienkripsi ke dalam metadata header)

### Mode Dekripsi
Contoh (Rust): ./test_rs.exe dec dokumen.sija dummy password123
Hasil: dokumen_recovered.txt (Format .txt dipulihkan secara otomatis)

## Instruksi Penggunaan (GUI)
1. Eksekusi file SIJACRYPT_UI.exe yang berada di folder /dist (hasil kompilasi PyInstaller).
2. Pilih file target melalui antarmuka.
3. Masukkan kata sandi.
4. Klik tombol "ENKRIPSI" atau "DEKRIPSI". Program akan otomatis menangani ekstensi file dan menyimpannya di direktori yang sama.