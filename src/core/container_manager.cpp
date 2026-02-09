#include "container_manager.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>

// Crypto++ Includes
#include <cryptopp/osrng.h>
#include <cryptopp/scrypt.h> // Using Scrypt (Option 1)
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>

using namespace CryptoPP;

ContainerManager::ContainerManager() { }

bool ContainerManager::createContainer(const std::string& filePath, const std::string& password, long sizeInBytes) {
    std::cout << "[Core] Initializing Secure Container..." << std::endl;

    SFMHeader header = createDefaultHeader();

    // Generate Random Salt & Nonce
    AutoSeededRandomPool prng;
    prng.GenerateBlock(header.kdfSalt, SALT_SIZE);
    prng.GenerateBlock(header.encryptionNonce, NONCE_SIZE);

    // Derive Key using Scrypt
    SecByteBlock masterKey(32);
    Scrypt kdf;
    kdf.DeriveKey(
        masterKey, masterKey.size(),
        (const byte*)password.data(), password.size(),
        header.kdfSalt, SALT_SIZE,
        header.kdfMemoryCost,
        header.kdfIterations
    );

    try {
        GCM<AES>::Encryption encryptor;
        encryptor.SetKeyWithIV(masterKey, masterKey.size(), header.encryptionNonce, NONCE_SIZE);

        std::ofstream file(filePath, std::ios::binary);
        if (!file.is_open()) return false;

        // Write Header
        file.write(reinterpret_cast<const char*>(&header), sizeof(SFMHeader));

        // --- THE FIX IS HERE ---
        // We switched from StreamTransformationFilter to AuthenticatedEncryptionFilter
        // This is required for AES-GCM mode.
        AuthenticatedEncryptionFilter filter(encryptor, new FileSink(file));

        // Write Encrypted "Zeros" to create volume
        const int CHUNK_SIZE = 4096;
        std::vector<byte> emptyBlock(CHUNK_SIZE, 0);

        long bytesWritten = 0;
        while (bytesWritten < sizeInBytes) {
            long remaining = sizeInBytes - bytesWritten;
            long currentChunk = (remaining < CHUNK_SIZE) ? remaining : CHUNK_SIZE;
            filter.Put(emptyBlock.data(), currentChunk);
            bytesWritten += currentChunk;
        }
        filter.MessageEnd(); // This writes the integrity tag
        file.close();

        return true;

    } catch (const Exception& e) {
        std::cerr << "[Crypto Error] " << e.what() << std::endl;
        return false;
    }
}

// ... (Keep your existing stubs below unchanged) ...
SFMHeader ContainerManager::createDefaultHeader() {
    SFMHeader header;
    std::memset(&header, 0, sizeof(SFMHeader));
    header.magic[0] = 'S'; header.magic[1] = 'F'; header.magic[2] = 'M'; header.magic[3] = '\0';
    header.version = 1;
    header.algoType = 1; 
    header.kdfIterations = 16384;   // Standard Scrypt iteration count
    header.kdfMemoryCost = 8;       // Standard Scrypt block size factor
    return header;
}

void ContainerManager::generateRandomSalt(uint8_t* buffer, int length) {
    AutoSeededRandomPool prng;
    prng.GenerateBlock(buffer, length);
}

bool ContainerManager::openContainer(const std::string& filePath, const std::string& password) {
    std::cout << "[Core] Attempting to open container..." << std::endl;

    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "[Error] File not found!" << std::endl;
        return false;
    }

    // 1. Read the Header
    SFMHeader header;
    file.read(reinterpret_cast<char*>(&header), sizeof(SFMHeader));

    // 2. Validate Magic Bytes ("SFM\0")
    if (header.magic[0] != 'S' || header.magic[1] != 'F' || 
        header.magic[2] != 'M' || header.magic[3] != '\0') {
        std::cerr << "[Error] Invalid file format! Not an SFM container." << std::endl;
        return false;
    }

    // 3. Derive the Key (Same logic as Create)
    SecByteBlock masterKey(32);
    Scrypt kdf;
    kdf.DeriveKey(
        masterKey, masterKey.size(),
        (const byte*)password.data(), password.size(),
        header.kdfSalt, SALT_SIZE,
        header.kdfMemoryCost,
        header.kdfIterations
    );

    // 4. Verify Password by decrypting the first block
    try {
        // Read the first 16 bytes of the encrypted body
        byte encryptedBlock[16];
        file.read(reinterpret_cast<char*>(encryptedBlock), 16);

        if (file.gcount() < 16) {
            std::cerr << "[Error] File is too short/corrupted." << std::endl;
            return false;
        }

        // Setup Decryption
        GCM<AES>::Decryption decryptor;
        decryptor.SetKeyWithIV(masterKey, masterKey.size(), header.encryptionNonce, NONCE_SIZE);

        // Raw Decryption (ProcessData ignores the auth tag for now)
        byte decryptedBlock[16];
        decryptor.ProcessData(decryptedBlock, encryptedBlock, 16);

        // 5. Check if it is Zeros
        bool isZeros = true;
        for (int i = 0; i < 16; i++) {
            if (decryptedBlock[i] != 0) {
                isZeros = false;
                break;
            }
        }

        if (isZeros) {
            std::cout << "[Success] Password Correct! Container is valid." << std::endl;
            return true;
        } else {
            std::cerr << "[Access Denied] Incorrect Password." << std::endl;
            return false;
        }

    } catch (const Exception& e) {
        std::cerr << "[Crypto Error] " << e.what() << std::endl;
        return false;
    }
}