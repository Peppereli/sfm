#include "container_manager.h"
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

        file.write(reinterpret_cast<const char*>(&header), sizeof(SFMHeader));
        AuthenticatedEncryptionFilter filter(encryptor, new FileSink(file));
        const int CHUNK_SIZE = 4096;
        std::vector<byte> emptyBlock(CHUNK_SIZE, 0);

        long bytesWritten = 0;
        while (bytesWritten < sizeInBytes) {
            long remaining = sizeInBytes - bytesWritten;
            long currentChunk = (remaining < CHUNK_SIZE) ? remaining : CHUNK_SIZE;
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
        byte encryptedBlock[16];
        file.read(reinterpret_cast<char*>(encryptedBlock), 16);

        if (file.gcount() < 16) {
            std::cerr << "[Error] File is too short/corrupted." << std::endl;
            return false;
        }

        GCM<AES>::Decryption decryptor;
        decryptor.SetKeyWithIV(masterKey, masterKey.size(), header.encryptionNonce, NONCE_SIZE);
        byte decryptedBlock[16];
        decryptor.ProcessData(decryptedBlock, encryptedBlock, 16);
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

bool ContainerManager::authenticateOrRegister(const std::string& hashFile) {
    std::ifstream inFile(hashFile);
    std::string storedHash;
    
    if (inFile >> storedHash) {
        std::string attempt;
        std::cout << "[Auth] Enter login: ";
        std::getline(std::cin, attempt);

        if (hashMasterPassword(attempt) == storedHash) {
            std::cout << "[Auth] Success.\n";
            return true;
        } else {
            std::cerr << "[Auth] Failure.\n";
            return false;
        }
    } else {
        std::cout << "[Auth] Setup password: ";
        std::string newPass;
        std::getline(std::cin, newPass);

        std::ofstream outFile(hashFile);
        if (!outFile) {
            std::cerr << "[Error] Could not create auth file.\n";
            return false;
        }

        outFile << hashMasterPassword(newPass);
        std::cout << "[Auth] Master password initialized.\n";
        return true;
    }
}
