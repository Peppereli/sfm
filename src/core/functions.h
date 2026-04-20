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
    char comment[128]; //128 byte for a comment on encrypted file
};

struct VaultIndex {
    uint32_t fileCount;
};

class ContainerManager {
public:
    ContainerManager();

    bool createContainer(const std::string& filePath, const std::string& password, long sizeInBytes);
    bool openContainer(const std::string& filePath, const std::string& password);
    bool encryptFile(const std::string& inputPath, const std::string& outputPath, const std::string& password, const std::string& comment = "");
    bool decryptFile(const std::string& inputPath, const std::string& outputPath, const std::string& password);
    bool secureDeleteFile(const std::string& filePath);

    std::string getFileComment(const std::string& filePath); // method for reading comment

    std::string hashMasterPassword(const std::string& password);
    bool isPasswordSet(const std::string& hashFile);
    bool authenticate(const std::string& hashFile, const std::string& password);
    bool setPassword(const std::string& hashFile, const std::string& newPassword);
    bool changePassword(const std::string& hashFile, const std::string& oldPassword, const std::string& newPassword);

    std::string saveFileDialog();
    std::string openFileDialog();
    void openWithDefaultApp(const std::string& filePath);

private:
    SFMHeader createDefaultHeader();
    void generateRandomSalt(uint8_t* buffer, int length);
};

std::string getSFMDirectory();
std::string resolvePath(const std::string& filename);

#endif
