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

    vector<uint8_t> payload;
    if (mode == "enc") {
        size_t dotPos = inputFile.find_last_of('.');
        string ext = (dotPos != string::npos) ? inputFile.substr(dotPos) : "";
        payload.push_back(static_cast<uint8_t>(ext.length()));
        payload.insert(payload.end(), ext.begin(), ext.end());
        payload.insert(payload.end(), data.begin(), data.end());
    } else {
        payload = data;
    }

    vector<uint8_t> keyHash = generateSuperKey(password);
    vector<uint8_t> processedData(payload.size());

    for (size_t i = 0; i < payload.size(); ++i) {
        if (mode == "enc") {
            uint8_t shiftedByte = payload[i] + (uint8_t)(i % 256);
            processedData[i] = shiftedByte ^ keyHash[i % 32];
        } else if (mode == "dec") {
            uint8_t unshiftedByte = payload[i] ^ keyHash[i % 32];
            processedData[i] = unshiftedByte - (uint8_t)(i % 256);
        }
    }

    string finalOutput;
    const uint8_t* outPtr = nullptr;
    size_t outSize = 0;

    if (mode == "enc") {
        size_t dotPos = inputFile.find_last_of('.');
        string stem = (dotPos != string::npos) ? inputFile.substr(0, dotPos) : inputFile;
        finalOutput = stem + ".sija";
        outPtr = processedData.data();
        outSize = processedData.size();
        cout << "[+] Proses ENKRIPSI Lapis 3 Berhasil!\n";
    } else {
        uint8_t extLen = processedData[0];
        string originalExt(processedData.begin() + 1, processedData.begin() + 1 + extLen);
        
        size_t sijaPos = inputFile.rfind(".sija");
        string baseName = (sijaPos != string::npos) ? inputFile.substr(0, sijaPos) : inputFile;
        finalOutput = baseName + "_recovered" + originalExt;
        
        outPtr = processedData.data() + 1 + extLen;
        outSize = processedData.size() - (1 + extLen);
        cout << "[+] Proses DEKRIPSI Berhasil, data dikembalikan!\n";
    }

    ofstream outFile(finalOutput, ios::binary);
    outFile.write(reinterpret_cast<const char*>(outPtr), outSize);
    outFile.close();

    cout << "[+] Output tersimpan di: " << finalOutput << "\n";
}