package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func processFile(inputFile, outputFile, password, mode string) {
	data, err := os.ReadFile(inputFile)
	if err != nil {
		fmt.Println("[-] Error membaca file:", err)
		return
	}

	keyHash := sha256.Sum256([]byte(password))
	var payload []byte

	if mode == "enc" {
		ext := filepath.Ext(inputFile)
		extBytes := []byte(ext)
		payload = append([]byte{byte(len(extBytes))}, extBytes...)
		payload = append(payload, data...)
	} else {
		payload = data
	}

	processedData := make([]byte, len(payload))
	for i := 0; i < len(payload); i++ {
		if mode == "enc" {
			shiftedByte := byte((int(payload[i]) + i) % 256)
			processedData[i] = shiftedByte ^ keyHash[i%32]
		} else if mode == "dec" {
			unshiftedByte := payload[i] ^ keyHash[i%32]
			processedData[i] = unshiftedByte - byte(i%256)
		}
	}

	var finalOutput string
	var outputData []byte

	if mode == "enc" {
		finalOutput = strings.TrimSuffix(inputFile, filepath.Ext(inputFile)) + ".sija"
		outputData = processedData
		fmt.Println("[+] Proses ENKRIPSI Lapis 3 Berhasil!")
	} else {
		extLen := processedData[0]
		originalExt := string(processedData[1 : 1+extLen])
		outputData = processedData[1+extLen:]
		finalOutput = strings.TrimSuffix(inputFile, ".sija") + "_recovered" + originalExt
		fmt.Println("[+] Proses DEKRIPSI Berhasil, data dikembalikan!")
	}

	err = os.WriteFile(finalOutput, outputData, 0644)
	if err != nil {
		fmt.Println("[-] Error menyimpan file:", err)
		return
	}
	fmt.Printf("[+] Output tersimpan di: %s\n", finalOutput)
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