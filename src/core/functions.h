#ifndef FUNCTIONS_H
#define FUNCTIONS_H

#include <string>
#include <cstdint>

#define SALT_SIZE 16
#define NONCE_SIZE 12
#define MAX_FILES_PER_VAULT 1000

struct SFMHeader {
    char magic[4];
    uint32_t version;
    uint32_t algoType;
    uint32_t kdfIterations;
    uint32_t kdfMemoryCost;
    uint8_t kdfSalt[SALT_SIZE];
    uint8_t encryptionNonce[NONCE_SIZE];
};

struct VaultIndex {
    uint32_t fileCount;
};

class ContainerManager {
public:
    ContainerManager();

    bool createContainer(const std::string& filePath, const std::string& password, long sizeInBytes);
    bool openContainer(const std::string& filePath, const std::string& password);
    bool encryptFile(const std::string& inputPath, const std::string& outputPath, const std::string& password);
    bool decryptFile(const std::string& inputPath, const std::string& outputPath, const std::string& password);
    bool secureDeleteFile(const std::string& filePath);

    std::string hashMasterPassword(const std::string& password);
    bool authenticateOrRegister(const std::string& hashFile, const std::string& password);

private:
    SFMHeader createDefaultHeader();
    void generateRandomSalt(uint8_t* buffer, int length);
};

std::string getSFMDirectory();
std::string resolvePath(const std::string& filename);

#endif
