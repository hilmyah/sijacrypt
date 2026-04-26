#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstdint>

using namespace std;

vector<uint8_t> generateSuperKey(const string& password) {
    vector<uint8_t> key(32, 0);
    for (size_t i = 0; i < 32; ++i) {
        key[i] = password[i % password.length()] ^ (uint8_t)(i * 7);
    }
    return key;
}

int main(int argc, char* argv[]) {
    if (argc != 5) {
        cout << "Penggunaan: ./sijacrypt [enc/dec] [input] [output] [password]\n";
        return 1;
    }

    string mode = argv[1];
    string inputFile = argv[2];
    string outputFile = argv[3];
    string password = argv[4];

    ifstream inFile(inputFile, ios::binary);
    if (!inFile) {
        cout << "[-] Error membaca file!\n";
        return 1;
    }
    vector<uint8_t> data((istreambuf_iterator<char>(inFile)), istreambuf_iterator<char>());
    inFile.close();

    vector<uint8_t> keyHash = generateSuperKey(password);
    vector<uint8_t> processedData(data.size());

    for (size_t i = 0; i < data.size(); ++i) {
        if (mode == "enc") {
            uint8_t shiftedByte = data[i] + (uint8_t)(i % 256);
            processedData[i] = shiftedByte ^ keyHash[i % 32];
        } else if (mode == "dec") {
            uint8_t unshiftedByte = data[i] ^ keyHash[i % 32];
            processedData[i] = unshiftedByte - (uint8_t)(i % 256);
        }
    }

    ofstream outFile(outputFile, ios::binary);
    outFile.write(reinterpret_cast<const char*>(processedData.data()), processedData.size());
    outFile.close();

    cout << "[+] Berhasil diproses!\n";
    return 0;
}