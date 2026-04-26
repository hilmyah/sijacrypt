use std::env;
use std::fs;
use std::process;

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
    let output_file = &args[3];
    let password = &args[4];

    let data = fs::read(input_file).expect("[-] Gagal membaca file input");
    let key_hash = generate_super_key(password);
    let mut processed_data = Vec::with_capacity(data.len());

    for i in 0..data.len() {
        let i_u8 = (i % 256) as u8;
        
        if mode == "enc" {
            let shifted_byte = data[i].wrapping_add(i_u8);
            processed_data.push(shifted_byte ^ key_hash[i % 32]);
        } else if mode == "dec" {
            let unshifted_byte = data[i] ^ key_hash[i % 32];
            processed_data.push(unshifted_byte.wrapping_sub(i_u8));
        }
    }

    fs::write(output_file, processed_data).expect("[-] Gagal menulis file output");
    println!("[+] File berhasil diproses dan disimpan di: {}", output_file);
}