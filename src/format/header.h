#include <cstdint>
#include <array>

const int SALT_SIZE = 32;
const int NONCE_SIZE = 12;
const int AUTH_TAG_SIZE = 16;

enum class EncryptionAlgo : uint8_t {
    AES_256_GCM = 1,
    CHACHA20_POLY1305 = 2
};

#pragma pack(push, 1)

struct SFMHeader {
    uint8_t magic[4];

    uint16_t version;

    uint8_t algoType;

    uint8_t kdfSalt[SALT_SIZE];

    uint32_t kdfIterations;
    uint32_t kdfMemoryCost;

    uint8_t encryptionNonce[NONCE_SIZE];

    uint8_t headerChecksum[32]; 
};

#pragma pack(pop)


#pragma pack(push, 1)

// represents a single file stored INSIDE the encrypted vault
struct FileEntry {
    char filename[128];
    uint64_t size;
    uint64_t offset;
    bool isDeleted;
};

const int MAX_FILES_PER_VAULT = 100;

struct VaultIndex {
    uint32_t fileCount;
    FileEntry entries[MAX_FILES_PER_VAULT];
};

#pragma pack(pop)
