#include "functions.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <filesystem>
#include <cstdlib>

#include <cryptopp/osrng.h>
#include <cryptopp/scrypt.h>
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>
#include <cryptopp/hex.h>
#include <cryptopp/sha.h>

#include <cstdio>

#ifdef _WIN32
#include <windows.h>
#include <commdlg.h>
#endif


using namespace CryptoPP;

std::string getSFMDirectory() {
#ifdef _WIN32
    const char* home = std::getenv("USERPROFILE");
#else
    const char* home = std::getenv("HOME");
#endif

    std::string path;

    if (home) {
        path = std::string(home) + "/.sfm";
    } else {
        path = ".sfm"; // fallback
    }

    std::filesystem::create_directories(path);
    return path;
}

std::string resolvePath(const std::string& filename) {
    std::string sfmPath = getSFMDirectory() + "/" + filename;
    if (std::filesystem::exists(sfmPath)) return sfmPath;
    return filename;
}

ContainerManager::ContainerManager() { }


bool ContainerManager::isPasswordSet(const std::string& hashFile) {
    std::string fullPath = getSFMDirectory() + "/" + hashFile;
    return std::filesystem::exists(fullPath);
}

bool ContainerManager::authenticate(const std::string& hashFile, const std::string& password) {
    std::string fullPath = getSFMDirectory() + "/" + hashFile;
    std::ifstream inFile(fullPath);
    std::string storedHash;
    if (inFile >> storedHash) {
        return hashMasterPassword(password) == storedHash;
    }
    return false;
}

bool ContainerManager::setPassword(const std::string& hashFile, const std::string& newPassword) {
    std::string fullPath = getSFMDirectory() + "/" + hashFile;
    std::ofstream outFile(fullPath);
    if (!outFile) return false;
    outFile << hashMasterPassword(newPassword);
    return true;
}

bool ContainerManager::changePassword(const std::string& hashFile, const std::string& oldPassword, const std::string& newPassword) {
    if (authenticate(hashFile, oldPassword)) {
        return setPassword(hashFile, newPassword);
    }
    return false;
}

std::string ContainerManager::saveFileDialog() {
#ifdef _WIN32
    char filename[MAX_PATH] = {0};
    OPENFILENAMEA ofn;
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = NULL;
    ofn.lpstrFilter = "SFM Vaults (*.sfm)\0*.sfm\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = filename;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_EXPLORER | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT;
    ofn.lpstrDefExt = "sfm";

    if (GetSaveFileNameA(&ofn)) {
        return std::string(filename);
    }
    return "";
#else
    char filename[1024] = {0};
    FILE* f = popen("zenity --file-selection --save --confirm-overwrite --title=\"Create New Vault\"", "r");
    if (f) {
        if (fgets(filename, sizeof(filename), f) != nullptr) {
            std::string result(filename);
            size_t pos = result.find_last_not_of(" \n\r\t");
            if (pos != std::string::npos) result.erase(pos + 1);
            else result.clear();
            pclose(f);
            return result;
        }
        pclose(f);
    }
    return "";
#endif
}

std::string ContainerManager::openFileDialog() {
#ifdef _WIN32
    char filename[MAX_PATH] = {0};
    OPENFILENAMEA ofn;
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = NULL;
    ofn.lpstrFilter = "All Files (*.*)\0*.*\0";
    ofn.lpstrFile = filename;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;

    if (GetOpenFileNameA(&ofn)) {
        return std::string(filename);
    }
    return "";
#else
    char filename[1024] = {0};
    FILE* f = popen("zenity --file-selection --title=\"Select File to Open\"", "r");
    if (f) {
        if (fgets(filename, sizeof(filename), f) != nullptr) {
            std::string result(filename);
            size_t pos = result.find_last_not_of(" \n\r\t");
            if (pos != std::string::npos) result.erase(pos + 1);
            else result.clear();
            pclose(f);
            return result;
        }
        pclose(f);
    }
    return "";
#endif
}

void ContainerManager::openWithDefaultApp(const std::string& filePath) {
#ifdef _WIN32
    ShellExecuteA(NULL, "open", filePath.c_str(), NULL, NULL, SW_SHOWNORMAL);
#elif __APPLE__
    std::string cmd = "open \"" + filePath + "\"";
    std::system(cmd.c_str());
#else
    std::string cmd = "xdg-open \"" + filePath + "\" &";
    std::system(cmd.c_str());
#endif
}
 

bool ContainerManager::createContainer(const std::string& filePath, const std::string& password, long sizeInBytes) {
    std::cout << "[Core] Initializing Secure Container...\n";

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

    try {
        GCM<AES>::Encryption encryptor;
        encryptor.SetKeyWithIV(masterKey, masterKey.size(), header.encryptionNonce, NONCE_SIZE);

        std::ofstream file(filePath, std::ios::binary);
        if (!file.is_open()) return false;

        file.write(reinterpret_cast<const char*>(&header), sizeof(SFMHeader));
        
        AuthenticatedEncryptionFilter filter(encryptor, new FileSink(file));

        VaultIndex index;
        std::memset(&index, 0, sizeof(VaultIndex));

        filter.Put(reinterpret_cast<const byte*>(&index), sizeof(VaultIndex));

        const int CHUNK_SIZE = 4096;
        std::vector<byte> emptyBlock(CHUNK_SIZE, 0);

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

        masterKey.CleanNew(masterKey.size());
        return true;

    } catch (const Exception& e) {
        std::cerr << "[Crypto Error] " << e.what() << "\n";
        return false;
    }
}

SFMHeader ContainerManager::createDefaultHeader() {
    SFMHeader header;
    std::memset(&header, 0, sizeof(SFMHeader));
    header.magic[0] = 'S'; header.magic[1] = 'F'; header.magic[2] = 'M'; header.magic[3] = '\0';
    header.version = 1;
    header.algoType = 1;
    header.kdfIterations = 32768;
    header.kdfMemoryCost = 64;

    return header;
}

void ContainerManager::generateRandomSalt(uint8_t* buffer, int length) {
    AutoSeededRandomPool prng;
    prng.GenerateBlock(buffer, length);
}

bool ContainerManager::openContainer(const std::string& filePath, const std::string& password) {
    std::cout << "[Core] Attempting to open container...\n";

    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "[Error] File not found!\n";
        return false;
    }

    SFMHeader header;
    file.read(reinterpret_cast<char*>(&header), sizeof(SFMHeader));

    if (header.magic[0] != 'S' || header.magic[1] != 'F' || 
        header.magic[2] != 'M' || header.magic[3] != '\0') {
        std::cerr << "[Error] Invalid file format!\n";
        return false;
    }

    if (header.version != 1) {
        std::cerr << "[Error] Unsupported version.\n";
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

        GCM<AES>::Decryption decryptor;
        decryptor.SetKeyWithIV(masterKey, masterKey.size(), header.encryptionNonce, NONCE_SIZE);

        VaultIndex index;

        AuthenticatedDecryptionFilter df(
            decryptor,
            new ArraySink(reinterpret_cast<byte*>(&index), sizeof(VaultIndex)),
            AuthenticatedDecryptionFilter::THROW_EXCEPTION
        );

        df.Put(encryptedIndex.data(), encryptedIndex.size());
        df.MessageEnd();

        if (index.fileCount > MAX_FILES_PER_VAULT) {
            std::cerr << "[Access Denied]\n";
            return false;
        }

        std::cout << "[Success] Vault Unlocked.\n";

        masterKey.CleanNew(masterKey.size());
        return true;

    } catch (const Exception& e) {
        std::cerr << "[Crypto Error] " << e.what() << "\n";
        return false;
    }
}

bool ContainerManager::encryptFile(const std::string& inputPath, const std::string& outputPath, const std::string& password, const std::string& comment) { // comment
    std::cout << "[Core] Encrypting file: " << inputPath << "\n";

    try {
        std::ifstream inFile(inputPath, std::ios::binary);
        if (!inFile.is_open()) return false;

        std::string realOutput = getSFMDirectory() + "/" + outputPath;
        std::ofstream outFile(realOutput, std::ios::binary);

        SFMHeader header = createDefaultHeader();

        std::strncpy(header.comment, comment.c_str(), sizeof(header.comment) - 1); // copy the comment into the title

        AutoSeededRandomPool prng;
        prng.GenerateBlock(header.kdfSalt, SALT_SIZE);
        prng.GenerateBlock(header.encryptionNonce, NONCE_SIZE);

        SecByteBlock masterKey(32);
        Scrypt kdf;
        kdf.DeriveKey(masterKey, masterKey.size(),
            (const byte*)password.data(), password.size(),
            header.kdfSalt, SALT_SIZE,
            header.kdfMemoryCost,
            header.kdfIterations);

        outFile.write(reinterpret_cast<const char*>(&header), sizeof(SFMHeader));

        GCM<AES>::Encryption encryptor;
        encryptor.SetKeyWithIV(masterKey, masterKey.size(), header.encryptionNonce, NONCE_SIZE);

        FileSource fs(inFile, true,
            new AuthenticatedEncryptionFilter(encryptor,
                new FileSink(outFile)
            )
        );

        std::cout << "[Success] Stored in: " << realOutput << "\n";

        masterKey.CleanNew(masterKey.size());

        //the thing that ends the usage of file that we want to wipe
        inFile.close();
        outFile.close();

        //securely wipe the original unencrypted file
        std::cout << "[Cleanup] Wiping original file...\n";
        secureDeleteFile(inputPath);
        
        return true;

    } catch (...) {
        return false;
    }
}

bool ContainerManager::decryptFile(const std::string& inputPath, const std::string& outputPath, const std::string& password) {
    std::cout << "[Core] Decrypting file: " << inputPath << "\n";

    try {
        std::string realInput = resolvePath(inputPath);
        std::ifstream inFile(realInput, std::ios::binary);
        if (!inFile.is_open()) return false;

        SFMHeader header;
        inFile.read(reinterpret_cast<char*>(&header), sizeof(SFMHeader));

        SecByteBlock masterKey(32);
        Scrypt kdf;
        kdf.DeriveKey(masterKey, masterKey.size(),
            (const byte*)password.data(), password.size(),
            header.kdfSalt, SALT_SIZE,
            header.kdfMemoryCost,
            header.kdfIterations);

        GCM<AES>::Decryption decryptor;
        decryptor.SetKeyWithIV(masterKey, masterKey.size(), header.encryptionNonce, NONCE_SIZE);

        std::ofstream outFile(outputPath, std::ios::binary);

        FileSource fs(inFile, true,
            new AuthenticatedDecryptionFilter(decryptor,
                new FileSink(outFile)
            )
        );

        std::cout << "[Success] Decrypted successfully.\n";

        masterKey.CleanNew(masterKey.size());

        //the thing that ends the usage of file that we want to wipe
        inFile.close();
        outFile.close();

        //securely wipe the original encrypted file
        std::cout << "[Cleanup] Wiping encrypted file...\n";
        secureDeleteFile(realInput);
        
        return true;

    } catch (...) {
        std::cerr << "[Crypto Error] Decryption failed.\n";
        return false;
    }
}
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

std::string ContainerManager::getFileComment(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) return "";

    SFMHeader header;
    file.read(reinterpret_cast<char*>(&header), sizeof(SFMHeader));

    // cheking for exact encrypted file 
    if (header.magic[0] == 'S' && header.magic[1] == 'F' && header.magic[2] == 'M') {
        header.comment[sizeof(header.comment) - 1] = '\0';
        return std::string(header.comment);
    }
    
    return "";
}

bool ContainerManager::secureDeleteFile(const std::string& filePath) {
    std::cout << "[Core] Securely wiping file: " << filePath << "\n";

    std::fstream file(filePath, std::ios::binary | std::ios::in | std::ios::out);
    if (!file.is_open()) {
        std::cerr << "[Error] File not found or currently in use.\n";
        return false;
    }

    file.seekg(0, std::ios::end);
    long fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    if (fileSize == 0) {
        file.close();
        std::remove(filePath.c_str());
        std::cout << "[Success] Empty file deleted.\n";
        return true;
    }

    const int BUFFER_SIZE = 4096;
    std::vector<char> buffer(BUFFER_SIZE);

    std::cout << "[Wipe] Pass 1/3: Overwriting with zeros...\n";
    std::fill(buffer.begin(), buffer.end(), 0x00);
    for (long i = 0; i < fileSize; i += BUFFER_SIZE) {
        long chunk = (fileSize - i < BUFFER_SIZE) ? (fileSize - i) : BUFFER_SIZE;
        file.write(buffer.data(), chunk);
    }
    file.flush();
    file.seekg(0, std::ios::beg);

    std::cout << "[Wipe] Pass 2/3: Overwriting with ones...\n";
    std::fill(buffer.begin(), buffer.end(), 0xFF);
    for (long i = 0; i < fileSize; i += BUFFER_SIZE) {
        long chunk = (fileSize - i < BUFFER_SIZE) ? (fileSize - i) : BUFFER_SIZE;
        file.write(buffer.data(), chunk);
    }
    file.flush();
    file.seekg(0, std::ios::beg);

    std::cout << "[Wipe] Pass 3/3: Overwriting with random data...\n";
    AutoSeededRandomPool prng;
    for (long i = 0; i < fileSize; i += BUFFER_SIZE) {
        long chunk = (fileSize - i < BUFFER_SIZE) ? (fileSize - i) : BUFFER_SIZE;
        prng.GenerateBlock(reinterpret_cast<byte*>(buffer.data()), chunk);
        file.write(buffer.data(), chunk);
    }
    file.flush();
    
    file.close();

    if (std::remove(filePath.c_str()) == 0) {
        std::cout << "[Success] File securely wiped and deleted.\n";
        return true;
    } else {
        std::cerr << "[Error] Failed to delete file record (data is wiped though).\n";
        return false;
    }
}

