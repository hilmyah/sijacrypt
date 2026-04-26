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
        with open(input_file, 'rb') as f:
            data = f.read()
            
        key_hash = generate_super_key(password)
        
        if mode == 'enc':
            ext = os.path.splitext(input_file)[1].encode('utf-8')
            combined_data = bytes([len(ext)]) + ext + data
            processed_data = encrypt_core(combined_data, key_hash)
            
            final_output = os.path.splitext(input_file)[0] + ".sija"
            print("[+] Proses ENKRIPSI Lapis 3 Berhasil!")
            
        else:
            decrypted_combined = decrypt_core(data, key_hash)
            
            ext_len = decrypted_combined[0]
            original_ext = decrypted_combined[1:1+ext_len].decode('utf-8')
            processed_data = decrypted_combined[1+ext_len:]
            
            final_output = input_file.replace(".sija", f"_recovered{original_ext}")
            print("[+] Proses DEKRIPSI Berhasil, data dikembalikan!")
            
        with open(final_output, 'wb') as f:
            f.write(processed_data)
            
        print(f"[+] Output tersimpan di: {final_output}")
        
    except Exception as e:
        print(f"[-] Terjadi kesalahan: {e}")

def main():
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