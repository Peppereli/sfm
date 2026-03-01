#include "functions.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>

#include <cryptopp/osrng.h>
#include <cryptopp/scrypt.h>
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>
#include <cryptopp/hex.h>
#include <cryptopp/sha.h>

#include <cstdio>

using namespace CryptoPP;

ContainerManager::ContainerManager() { }

bool ContainerManager::createContainer(const std::string& filePath, const std::string& password, long sizeInBytes) {
    std::cout << "[Core] Initializing Secure Container..." << std::endl;

    SFMHeader header = createDefaultHeader();

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

        // 1. Write the Header in PLAINTEXT
        file.write(reinterpret_cast<const char*>(&header), sizeof(SFMHeader));
        
        AuthenticatedEncryptionFilter filter(encryptor, new FileSink(file));

        // 2. Create an Empty Table of Contents and ENCRYPT IT
        VaultIndex index;
        std::memset(&index, 0, sizeof(VaultIndex)); // Fill it with zeros (0 files)
        
        // Push the index through the AES-GCM filter
        filter.Put(reinterpret_cast<const byte*>(&index), sizeof(VaultIndex));

        // 3. Fill the REST of the vault with encrypted zeros
        const int CHUNK_SIZE = 4096;
        std::vector<byte> emptyBlock(CHUNK_SIZE, 0);

        // We subtract the index size so the total file size stays exactly what the user asked for
        long remainingBytes = sizeInBytes - sizeof(VaultIndex);
        long bytesWritten = 0;
        
        while (bytesWritten < remainingBytes) {
            long remainingChunk = remainingBytes - bytesWritten;
            long currentChunk = (remainingChunk < CHUNK_SIZE) ? remainingChunk : CHUNK_SIZE;
            filter.Put(emptyBlock.data(), currentChunk);
            bytesWritten += currentChunk;
        }
        
        filter.MessageEnd();
        file.close();

        return true;

    } catch (const Exception& e) {
        std::cerr << "[Crypto Error] " << e.what() << std::endl;
        return false;
    }
}

SFMHeader ContainerManager::createDefaultHeader() {
    SFMHeader header;
    std::memset(&header, 0, sizeof(SFMHeader));
    header.magic[0] = 'S'; header.magic[1] = 'F'; header.magic[2] = 'M'; header.magic[3] = '\0';
    header.version = 1;
    header.algoType = 1; 
    header.kdfIterations = 16384;
    header.kdfMemoryCost = 8;
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

    SFMHeader header;
    file.read(reinterpret_cast<char*>(&header), sizeof(SFMHeader));
    if (header.magic[0] != 'S' || header.magic[1] != 'F' || 
        header.magic[2] != 'M' || header.magic[3] != '\0') {
        std::cerr << "[Error] Invalid file format! Not an SFM container." << std::endl;
        return false;
    }
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
        const int indexSize = sizeof(VaultIndex);
        std::vector<byte> encryptedIndex(indexSize);
        file.read(reinterpret_cast<char*>(encryptedIndex.data()), indexSize);

        if (file.gcount() < indexSize) {
            std::cerr << "[Error] File is too short/corrupted." << std::endl;
            return false;
        }

        // Setup Decryptor
        GCM<AES>::Decryption decryptor;
        decryptor.SetKeyWithIV(masterKey, masterKey.size(), header.encryptionNonce, NONCE_SIZE);

        // 4. Decrypt the Index directly into our struct
        VaultIndex index;
        decryptor.ProcessData(reinterpret_cast<byte*>(&index), encryptedIndex.data(), indexSize);

        // 5. The "Sanity Check" (Verifying the Password)
        // If the password is wrong, index.fileCount will be a massive random number.
        if (index.fileCount > MAX_FILES_PER_VAULT) {
            std::cerr << "[Access Denied] Incorrect Password or Corrupted Vault." << std::endl;
            return false;
        }

        // If we pass the check, the password is correct!
        std::cout << "[Success] Password Correct! Vault Unlocked." << std::endl;
        std::cout << "[Vault Info] Found " << index.fileCount << " files inside." << std::endl;

        return true;

    } catch (const Exception& e) {
        std::cerr << "[Crypto Error] " << e.what() << std::endl;
        return false;
    }
}
bool ContainerManager::encryptFile(const std::string& inputPath, const std::string& outputPath, const std::string& password) {
    std::cout << "[Core] Encrypting file: " << inputPath << " -> " << outputPath << std::endl;

    try {
        std::ifstream inFile(inputPath, std::ios::binary);
        if (!inFile.is_open()) {
            std::cerr << "[Error] Input file not found." << std::endl;
            return false;
        }
        std::ofstream outFile(outputPath, std::ios::binary);
        if (!outFile.is_open()) return false;
        SFMHeader header = createDefaultHeader();
        
        AutoSeededRandomPool prng;
        prng.GenerateBlock(header.kdfSalt, SALT_SIZE);
        prng.GenerateBlock(header.encryptionNonce, NONCE_SIZE);
        SecByteBlock masterKey(32);
        Scrypt kdf;
        kdf.DeriveKey(
            masterKey, masterKey.size(),
            (const byte*)password.data(), password.size(),
            header.kdfSalt, SALT_SIZE,
            header.kdfMemoryCost,
            header.kdfIterations
        );
        outFile.write(reinterpret_cast<const char*>(&header), sizeof(SFMHeader));
        GCM<AES>::Encryption encryptor;
        encryptor.SetKeyWithIV(masterKey, masterKey.size(), header.encryptionNonce, NONCE_SIZE);
        FileSource fs(inFile, true,
            new AuthenticatedEncryptionFilter(encryptor,
                new FileSink(outFile)
            )
        );

        std::cout << "[Success] File encrypted successfully." << std::endl;
        return true;

    } catch (const Exception& e) {
        std::cerr << "[Crypto Error] " << e.what() << std::endl;
        return false;
    }
}

bool ContainerManager::decryptFile(const std::string& inputPath, const std::string& outputPath, const std::string& password) {
    std::cout << "[Core] Decrypting file: " << inputPath << " -> " << outputPath << std::endl;

    try {
        std::ifstream inFile(inputPath, std::ios::binary);
        if (!inFile.is_open()) {
            std::cerr << "[Error] Input file not found." << std::endl;
            return false;
        }
        SFMHeader header;
        inFile.read(reinterpret_cast<char*>(&header), sizeof(SFMHeader));
        if (header.magic[0] != 'S' || header.magic[1] != 'F' || header.magic[2] != 'M') {
            std::cerr << "[Error] Invalid SFM file format." << std::endl;
            return false;
        }
        SecByteBlock masterKey(32);
        Scrypt kdf;
        kdf.DeriveKey(
            masterKey, masterKey.size(),
            (const byte*)password.data(), password.size(),
            header.kdfSalt, SALT_SIZE,
            header.kdfMemoryCost,
            header.kdfIterations
        );
        GCM<AES>::Decryption decryptor;
        decryptor.SetKeyWithIV(masterKey, masterKey.size(), header.encryptionNonce, NONCE_SIZE);
        std::ofstream outFile(outputPath, std::ios::binary);
        
        FileSource fs(inFile, true,
            new AuthenticatedDecryptionFilter(decryptor,
                new FileSink(outFile)
            )
        );

        std::cout << "[Success] File decrypted successfully." << std::endl;
        return true;

    } catch (const Exception& e) {
        std::cerr << "[Crypto Error] Decryption failed (Wrong password or corrupted file)." << std::endl;
        return false;
    }
}

bool ContainerManager::secureDeleteFile(const std::string& filePath) {
    std::cout << "[Core] Securely wiping file: " << filePath << std::endl;

    std::fstream file(filePath, std::ios::binary | std::ios::in | std::ios::out);
    if (!file.is_open()) {
        std::cerr << "[Error] File not found or currently in use." << std::endl;
        return false;
    }

    file.seekg(0, std::ios::end);
    long fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    if (fileSize == 0) {
        file.close();
        std::remove(filePath.c_str());
        std::cout << "[Success] Empty file deleted." << std::endl;
        return true;
    }

    const int BUFFER_SIZE = 4096;
    std::vector<char> buffer(BUFFER_SIZE);

    std::cout << "[Wipe] Pass 1/3: Overwriting with zeros..." << std::endl;
    std::fill(buffer.begin(), buffer.end(), 0x00);
    for (long i = 0; i < fileSize; i += BUFFER_SIZE) {
        long chunk = (fileSize - i < BUFFER_SIZE) ? (fileSize - i) : BUFFER_SIZE;
        file.write(buffer.data(), chunk);
    }
    file.flush();
    file.seekg(0, std::ios::beg);

    std::cout << "[Wipe] Pass 2/3: Overwriting with ones..." << std::endl;
    std::fill(buffer.begin(), buffer.end(), 0xFF);
    for (long i = 0; i < fileSize; i += BUFFER_SIZE) {
        long chunk = (fileSize - i < BUFFER_SIZE) ? (fileSize - i) : BUFFER_SIZE;
        file.write(buffer.data(), chunk);
    }
    file.flush();
    file.seekg(0, std::ios::beg);

    std::cout << "[Wipe] Pass 3/3: Overwriting with random data..." << std::endl;
    AutoSeededRandomPool prng;
    for (long i = 0; i < fileSize; i += BUFFER_SIZE) {
        long chunk = (fileSize - i < BUFFER_SIZE) ? (fileSize - i) : BUFFER_SIZE;
        prng.GenerateBlock(reinterpret_cast<byte*>(buffer.data()), chunk);
        file.write(buffer.data(), chunk);
    }
    file.flush();
    
    file.close();

    if (std::remove(filePath.c_str()) == 0) {
        std::cout << "[Success] File securely wiped and deleted." << std::endl;
        return true;
    } else {
        std::cerr << "[Error] Failed to delete file record (data is wiped though)." << std::endl;
        return false;
    }
}

// Password hash and storage
std::string ContainerManager::hashMasterPassword(const std::string& password) {
    SHA256 hash;
    std::string digest;

    StringSource ss(password, true,
        new HashFilter(hash,
            new HexEncoder(
                new StringSink(digest)
            )
        )
    );

    return digest;
}
bool ContainerManager::authenticateOrRegister(const std::string& hashFile, const std::string& password) {
    std::ifstream inFile(hashFile);
    std::string storedHash;
    
    std::string currentHash = hashMasterPassword(password);

    if (inFile >> storedHash) {
        if (currentHash == storedHash) {
            return true; 
        } else {
            std::cerr << "[Critical] Access Denied: Incorrect Password." << std::endl;
            return false;
        }
    } else {
        std::ofstream outFile(hashFile);
        if (!outFile) return false;

        outFile << currentHash;
        std::cout << "[Info] No password file found. New password registered." << std::endl;
        return true;
    }
}
