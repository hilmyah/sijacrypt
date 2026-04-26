import sys
import os
import hashlib

def generate_super_key(password):
    # Mengubah password biasa menjadi array of bytes acak sepanjang 32-byte
    return hashlib.sha256(password.encode('utf-8')).digest()

def encrypt_core(data, key_hash):
    encrypted_data = bytearray()
    key_len = len(key_hash)
    
    for i in range(len(data)):
        # Lapis 2: Position Shifting (Ditambah index posisinya, dibatasi max 255)
        shifted_byte = (data[i] + i) % 256
        
        # Lapis 3: XOR dengan Super Key
        final_byte = shifted_byte ^ key_hash[i % key_len]
        encrypted_data.append(final_byte)
        
    return encrypted_data

def decrypt_core(data, key_hash):
    decrypted_data = bytearray()
    key_len = len(key_hash)
    
    for i in range(len(data)):
        # Kebalikan Lapis 3: Buka XOR-nya
        unshifted_byte = data[i] ^ key_hash[i % key_len]
        
        # Kebalikan Lapis 2: Kurangi dengan index posisinya
        original_byte = (unshifted_byte - i) % 256
        decrypted_data.append(original_byte)
        
    return decrypted_data

def process_file(input_file, output_file, password, mode):
    try:
        # Membaca isi file secara murni (Binary)
        with open(input_file, 'rb') as f:
            data = f.read()
            
        # Lapis 1: Buat kunci super dari password user
        key_hash = generate_super_key(password)
        
        # Penentuan Arah Algoritma
        if mode == 'enc':
            processed_data = encrypt_core(data, key_hash)
            print("[+] Proses ENKRIPSI Lapis 3 Berhasil!")
        else:
            processed_data = decrypt_core(data, key_hash)
            print("[+] Proses DEKRIPSI Berhasil, data dikembalikan!")
            
        # Tulis hasilnya ke file baru (.sija atau .dll)
        with open(output_file, 'wb') as f:
            f.write(processed_data)
            
        print(f"[+] Output tersimpan di: {output_file}")
        
    except FileNotFoundError:
        print(f"[-] Error: File '{input_file}' tidak ditemukan di folder ini.")
    except Exception as e:
        print(f"[-] Terjadi kesalahan sistem: {e}")

def main():
    # Menangkap perintah dari CLI Terminal
    args = sys.argv
    
    if len(args) != 5:
        print("SIJACRYPT")
        print("Penggunaan:")
        print("  python sijacrypt.py [enc/dec] [input] [output] [password]")
        print("\nContoh:")
        print("  python sijacrypt.py enc rahasia.txt data.sija admin123")
        sys.exit(1)
        
    mode = args[1].lower()
    input_file = args[2]
    output_file = args[3]
    password = args[4]
    
    if mode not in ['enc', 'dec']:
        print("[-] Mode salah! Gunakan 'enc' untuk Enkripsi, 'dec' untuk Dekripsi.")
        sys.exit(1)
        
    process_file(input_file, output_file, password, mode)

if __name__ == "__main__":
    main()