#include <cstdint>
#include <array>

// Define constants for strict size management
const int SALT_SIZE = 32;       // Standard for Argon2
const int NONCE_SIZE = 12;      // Standard for AES-GCM / ChaCha20-Poly1305
const int AUTH_TAG_SIZE = 16;   // Integrity check tag size

// Enum to switch between algorithms 
enum class EncryptionAlgo : uint8_t {
    AES_256_GCM = 1,
    CHACHA20_POLY1305 = 2
};

#pragma pack(push, 1)

// The Master Header Structure
struct SFMHeader {
    // 1. Magic Bytes (4 bytes)
    // Identifies this file as yours. e.g., 'S', 'F', 'M', '\0'
    // If the file doesn't start with this, your app rejects it immediately.
    uint8_t magic[4];

    // 2. Version (2 bytes)
    // Allows you to upgrade the format later without breaking old files.
    uint16_t version;

    // 3. Algorithm Identifier (1 byte)
    // Tells the decryptor: "Use AES" or "Use ChaCha20" 
    uint8_t algoType;

    // 4. Key Derivation Salt (32 bytes)
    // Crucial for security. Random data mixed with the password 
    // to prevent Rainbow Table attacks. 
    uint8_t kdfSalt[SALT_SIZE];

    // 5. KDF Iterations (4 bytes)
    // How hard should the CPU work? e.g., 4 memory passes, 2 iterations.
    // Storing this allows you to increase difficulty in the future.
    uint32_t kdfIterations;
    uint32_t kdfMemoryCost;

    // 6. Nonce / IV (12 bytes)
    // "Number used once". Required for the encryption math.
    uint8_t encryptionNonce[NONCE_SIZE];

    // 7. Integrity Check / Header Checksum (32 bytes)
    // A hash of this header itself to prove nobody tampered with 
    // the "shipping label". 
    uint8_t headerChecksum[32]; 
};

#pragma pack(pop)