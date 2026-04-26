import customtkinter as ctk
from tkinter import filedialog, messagebox
import hashlib
import os

# --- CORE LOGIC ---
def generate_super_key(password):
    return hashlib.sha256(password.encode('utf-8')).digest()

def encrypt_core(data, key_hash):
    encrypted_data = bytearray()
    for i in range(len(data)):
        shifted_byte = (data[i] + i) % 256
        encrypted_data.append(shifted_byte ^ key_hash[i % 32])
    return encrypted_data

def decrypt_core(data, key_hash):
    decrypted_data = bytearray()
    for i in range(len(data)):
        unshifted_byte = data[i] ^ key_hash[i % 32]
        decrypted_data.append((unshifted_byte - i) % 256)
    return decrypted_data

# --- UI CLASS ---
class SijaCryptApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("SIJACRYPT Desktop V2")
        self.geometry("500x400")
        ctk.set_appearance_mode("dark")

        # UI Elements
        self.label = ctk.CTkLabel(self, text="SIJACRYPT - Hybrid Engine", font=("Arial", 20, "bold"))
        self.label.pack(pady=20)

        self.btn_select = ctk.CTkButton(self, text="Pilih File", command=self.select_file)
        self.btn_select.pack(pady=10)

        self.file_label = ctk.CTkLabel(self, text="File: Belum dipilih", font=("Arial", 12))
        self.file_label.pack(pady=5)

        self.entry_pass = ctk.CTkEntry(self, placeholder_text="Masukkan Password", show="*", width=300)
        self.entry_pass.pack(pady=10)

        self.frame_btn = ctk.CTkFrame(self, fg_color="transparent")
        self.frame_btn.pack(pady=20)

        self.btn_enc = ctk.CTkButton(self.frame_btn, text="ENKRIPSI", fg_color="darkred", command=lambda: self.run_process("enc"))
        self.btn_enc.grid(row=0, column=0, padx=10)

        self.btn_dec = ctk.CTkButton(self.frame_btn, text="DEKRIPSI", fg_color="darkgreen", command=lambda: self.run_process("dec"))
        self.btn_dec.grid(row=0, column=1, padx=10)

        self.selected_path = ""

    def select_file(self):
        self.selected_path = filedialog.askopenfilename()
        if self.selected_path:
            self.file_label.configure(text=f"File: {os.path.basename(self.selected_path)}")

    def run_process(self, mode):
        password = self.entry_pass.get()
        if not self.selected_path or not password:
            messagebox.showwarning("Error", "File dan Password wajib diisi!")
            return

        try:
            with open(self.selected_path, 'rb') as f:
                data = f.read()
            
            key_hash = generate_super_key(password)
            
            if mode == "enc":
                ext = os.path.splitext(self.selected_path)[1].encode('utf-8')
                combined_data = bytes([len(ext)]) + ext + data
                
                processed = encrypt_core(combined_data, key_hash)
                output_path = os.path.splitext(self.selected_path)[0] + ".sija"
            else:
                decrypted_combined = decrypt_core(data, key_hash)
                
                # Baca 1 byte pertama untuk panjang ekstensi
                ext_len = decrypted_combined[0]
                # Ambil string ekstensi asli
                original_ext = decrypted_combined[1:1+ext_len].decode('utf-8')
                # Ambil data file sebenarnya
                processed = decrypted_combined[1+ext_len:]
                
                base_name = self.selected_path.replace(".sija", "")
                output_path = f"{base_name}_recovered{original_ext}"

            with open(output_path, 'wb') as f:
                f.write(processed)
            
            messagebox.showinfo("Sukses", f"Proses {mode} selesai!\nSaved: {output_path}")
        except Exception as e:
            messagebox.showerror("System Error", str(e))

if __name__ == "__main__":
    app = SijaCryptApp()
    app.mainloop()