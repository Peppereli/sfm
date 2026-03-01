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
    const size_t SALT_SIZE = 16;
    const size_t IV_SIZE = 12;
    const size_t KEY_SIZE = 32; // AES-256

    AutoSeededRandomPool prng;

    try {
        if (encrypt) {
            // ----- Generate salt -----
            byte salt[SALT_SIZE];
            prng.GenerateBlock(salt, SALT_SIZE);

            // ----- Derive key -----
            SecByteBlock key(KEY_SIZE);
            PKCS5_PBKDF2_HMAC<SHA256> pbkdf2;
            pbkdf2.DeriveKey(
                key, key.size(),
                0,
                (byte*)password.data(), password.size(),
                salt, SALT_SIZE,
                100000
            );

            // ----- Generate IV -----
            byte iv[IV_SIZE];
            prng.GenerateBlock(iv, IV_SIZE);

            // ----- Setup encryption -----
            GCM<AES>::Encryption e;
            e.SetKeyWithIV(key, key.size(), iv, IV_SIZE);

            std::string ciphertext;

            FileSource fs(inputPath.c_str(), true,
                new AuthenticatedEncryptionFilter(
                    e,
                    new StringSink(ciphertext)
                )
            );

            // ----- Write output file -----
            std::ofstream out(outputPath, std::ios::binary);
            out.write((char*)salt, SALT_SIZE);
            out.write((char*)iv, IV_SIZE);
            out.write(ciphertext.data(), ciphertext.size());
            out.close();

        } else {
            // ----- Open input file -----
            std::ifstream in(inputPath, std::ios::binary);
            if (!in)
                throw std::runtime_error("Cannot open input file");

            // ----- Read salt -----
            byte salt[SALT_SIZE];
            in.read((char*)salt, SALT_SIZE);

            // ----- Derive key -----
            SecByteBlock key(KEY_SIZE);
            PKCS5_PBKDF2_HMAC<SHA256> pbkdf2;
            pbkdf2.DeriveKey(
                key, key.size(),
                0,
                (byte*)password.data(), password.size(),
                salt, SALT_SIZE,
                100000
            );

            // ----- Read IV -----
            byte iv[IV_SIZE];
            in.read((char*)iv, IV_SIZE);

            // ----- Read remaining ciphertext -----
            std::string ciphertext(
                (std::istreambuf_iterator<char>(in)),
                std::istreambuf_iterator<char>()
            );

            in.close();

            // ----- Setup decryption -----
            GCM<AES>::Decryption d;
            d.SetKeyWithIV(key, key.size(), iv, IV_SIZE);

            std::string decrypted;

            AuthenticatedDecryptionFilter df(
                d,
                new StringSink(decrypted),
                AuthenticatedDecryptionFilter::THROW_EXCEPTION
            );

            StringSource ss(ciphertext, true,
                new Redirector(df)
            );

            // If we reach here → authentication succeeded
            std::ofstream out(outputPath, std::ios::binary);
            out.write(decrypted.data(), decrypted.size());
            out.close();
        }

        std::cout << "Success!" << std::endl;

    } catch (const CryptoPP::Exception& e) {
        std::cerr << "Decryption failed (wrong password or corrupted file)." << std::endl;
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
