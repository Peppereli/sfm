#include <iostream>
#include "../src/format/sfm_header.h"

int main() {
    SFMHeader header;
    
    // Calculate expected size manually:
    // Magic(4) + Ver(2) + Algo(1) + Salt(32) + Iter(4) + Mem(4) + Nonce(12) + Checksum(32)
    // = 91 bytes
    
    std::cout << "Expected Size: 91 bytes" << std::endl;
    std::cout << "Actual Size:   " << sizeof(header) << " bytes" << std::endl;

    if (sizeof(header) == 91) {
        std::cout << "SUCCESS: Struct is packed correctly!" << std::endl;
    } else {
        std::cout << "WARNING: Compiler added invisible padding!" << std::endl;
    }

    return 0;
}