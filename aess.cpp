#include <iostream>
#include <string>
#include <fstream>
#include <cryptopp/osrng.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/sha.h>

using namespace CryptoPP;

void DeriveKey(const std::string& password, SecByteBlock& key) {
    PKCS5_PBKDF2_HMAC<SHA256> pbkdf2;
    byte salt[] = "fixed_salt";
    pbkdf2.DeriveKey(key, key.size(), 0, (byte*)password.data(), password.size(), salt, 10, 10000);
}
void processFile(bool encrypt, std::string inputPath, std::string outputPath, std::string password) {
    SecByteBlock key(AES::MAX_KEYLENGTH);
    DeriveKey(password, key);

    const int GCM_IV_SIZE = 12;
    byte iv[GCM_IV_SIZE] = {0}; 

    std::ifstream in(inputPath, std::ios::binary | std::ios::ate);
    std::streamsize fileSize = in.tellg();
    in.seekg(0, std::ios::beg);
    std::ofstream out(outputPath, std::ios::binary);

    try {
        if (encrypt) {
            GCM<AES>::Encryption e;
            e.SetKeyWithIV(key, key.size(), iv, GCM_IV_SIZE);

            FileSource fs(in, true,
                new AuthenticatedEncryptionFilter(e,
                    new FileSink(out)
                )
            );
        } else {
            GCM<AES>::Decryption d;
            d.SetKeyWithIV(key, key.size(), iv, GCM_IV_SIZE);

            FileSource fs(in, true,
                new AuthenticatedDecryptionFilter(d,
                    new FileSink(out)
                )
            );
        }
        std::cout << "Great success! High five!" << std::endl;
    } catch (const CryptoPP::Exception& e) {
        std::cerr << "Crypto++ Error: " << e.what() << std::endl;
    }
}
int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cout << "Usage: ./main <enc/dec> <input> <output>\n";
        return 1;
    }

    std::string modeArg = argv[1];
    bool isEncrypt = (modeArg == "enc" || modeArg == "encrypt");
    bool isDecrypt = (modeArg == "dec" || modeArg == "decrypt");

    if (!isEncrypt && !isDecrypt) {
        std::cerr << "Unknown mode! Use 'enc' or 'dec'.\n";
        return 1;
    }

    std::string pass;
    std::cout << "Enter Password: ";
    std::cin >> pass;

    try {
        processFile(isEncrypt, argv[2], argv[3], pass);
        std::cout << "Great success! High five!" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "CRITICAL ERROR: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
