package main

import (
	"crypto/sha256"
	"fmt"
	"os"
)

func processFile(inputFile, outputFile, password, mode string) {
	// Membaca file sebagai binary
	data, err := os.ReadFile(inputFile)
	if err != nil {
		fmt.Println("[-] Error membaca file:", err)
		return
	}

	// Lapis 1: Key Expansion menggunakan SHA-256 bawaan Go
	keyHash := sha256.Sum256([]byte(password))
	processedData := make([]byte, len(data))

	for i := 0; i < len(data); i++ {
		if mode == "enc" {
			// Lapis 2 & 3: Shift (ditambah index) lalu XOR
			shiftedByte := byte((int(data[i]) + i) % 256)
			processedData[i] = shiftedByte ^ keyHash[i%32]
		} else if mode == "dec" {
			// Kebalikan Lapis 3 & 2: Buka XOR lalu Un-Shift
			unshiftedByte := data[i] ^ keyHash[i%32]
			processedData[i] = unshiftedByte - byte(i%256)
		}
	}

	// Menyimpan file output
	err = os.WriteFile(outputFile, processedData, 0644)
	if err != nil {
		fmt.Println("[-] Error menyimpan file:", err)
		return
	}
	fmt.Printf("[+] Berhasil! Output tersimpan di: %s\n", outputFile)
}

func main() {
	args := os.Args
	if len(args) != 5 {
		fmt.Println("Penggunaan: ./sijacrypt [enc/dec] [input] [output] [password]")
		os.Exit(1)
	}
	mode, input, output, password := args[1], args[2], args[3], args[4]
	processFile(input, output, password, mode)
}