use std::env;
use std::fs;
use std::process;
use std::path::Path;

// Custom Key Stretching untuk dependensi nol (Zero Dependencies)
fn generate_super_key(password: &str) -> Vec<u8> {
    let mut key = vec![0u8; 32];
    let pass_bytes = password.as_bytes();
    for i in 0..32 {
        if !pass_bytes.is_empty() {
            key[i] = pass_bytes[i % pass_bytes.len()] ^ (i as u8).wrapping_mul(7);
        }
    }
    key
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 5 {
        println!("Penggunaan: ./sijacrypt [enc/dec] [input] [output] [password]");
        process::exit(1);
    }

    let mode = &args[1];
    let input_file = &args[2];
    // Variabel output_file (args[3]) sengaja diabaikan karena nama file dinamis
    let password = &args[4];

    let data = fs::read(input_file).expect("[-] Gagal membaca file input");
    let key_hash = generate_super_key(password);
    
    let mut payload = Vec::new();
    if mode == "enc" {
        let path = Path::new(input_file);
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        let ext_with_dot = if ext.is_empty() { String::new() } else { format!(".{}", ext) };
        let ext_bytes = ext_with_dot.as_bytes();
        
        payload.push(ext_bytes.len() as u8);
        payload.extend_from_slice(ext_bytes);
        payload.extend_from_slice(&data);
    } else {
        payload = data;
    }

    let mut processed_data = Vec::with_capacity(payload.len());
    for i in 0..payload.len() {
        let i_u8 = (i % 256) as u8;
        if mode == "enc" {
            let shifted_byte = payload[i].wrapping_add(i_u8);
            processed_data.push(shifted_byte ^ key_hash[i % 32]);
        } else if mode == "dec" {
            let unshifted_byte = payload[i] ^ key_hash[i % 32];
            processed_data.push(unshifted_byte.wrapping_sub(i_u8));
        }
    }

    let final_output;
    let output_data: &[u8];

    if mode == "enc" {
        let path = Path::new(input_file);
        let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("output");
        final_output = format!("{}.sija", stem);
        output_data = &processed_data;
        println!("[+] Proses ENKRIPSI Lapis 3 Berhasil!");
    } else {
        let ext_len = processed_data[0] as usize;
        let original_ext = String::from_utf8_lossy(&processed_data[1..1+ext_len]);
        output_data = &processed_data[1+ext_len..];
        
        let base_name = input_file.strip_suffix(".sija").unwrap_or(input_file);
        final_output = format!("{}_recovered{}", base_name, original_ext);
        println!("[+] Proses DEKRIPSI Berhasil, data dikembalikan!");
    }

    fs::write(&final_output, output_data).expect("[-] Gagal menulis file output");
    println!("[+] File berhasil diproses dan disimpan di: {}", final_output);
}