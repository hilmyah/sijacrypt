# SIJACRYPT

Platform kriptografi hibrida yang mengimplementasikan algoritma kustom 3 lapis pada bahasa pemrograman Python, Go, Rust, dan C++. Proyek ini bertujuan untuk mendemonstrasikan konsistensi logika kriptografi lintas bahasa pemrograman tingkat sistem.

## Arsitektur Algoritma
Algoritma menggunakan metode Hybrid Cipher dengan tahapan sebagai berikut:
1. Key Expansion: Menggunakan SHA-256 atau Key Stretching untuk menghasilkan Super Key 32-byte.
2. Dynamic Position Shifting: Penambahan nilai indeks byte untuk menghancurkan pola frekuensi.
3. Repeating-Key XOR: Operasi biner akhir menggunakan Super Key.

## Struktur Direktori
- /cpp : Implementasi menggunakan C++ (Standard 11 atau lebih baru).
- /go  : Implementasi menggunakan Golang.
- /py  : Implementasi menggunakan Python 3.
- /rs  : Implementasi menggunakan Rust.

## Instruksi Eksekusi

### Python
Ekspresi: python test.py [mode] [input] [output] [password]
Contoh: python test.py enc test.txt hasil.sija password123

### Go
Kompilasi: go build -o test_go.exe test.go
Eksekusi: ./test_go.exe enc test.txt hasil.sija password123

### Rust
Kompilasi: rustc test.rs -o test_rs.exe
Eksekusi: ./test_rs.exe enc test.txt hasil.sija password123

### C++
Kompilasi: g++ test.cpp -o test_cpp.exe -O3
Eksekusi: ./test_cpp.exe enc test.txt hasil.sija password123