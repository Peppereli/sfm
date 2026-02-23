#ifndef CONTAINER_MANAGER_H
#define CONTAINER_MANAGER_H

#include <string>
#include <vector>
#include "../format/sfm_header.h"

class ContainerManager {
public:
    ContainerManager();

    bool createContainer(const std::string& filePath, const std::string& password, long sizeInBytes);

    bool openContainer(const std::string& filePath, const std::string& password);    

    bool encryptFile(const std::string& inputPath, const std::string& outputPath, const std::string& password);

    bool decryptFile(const std::string& inputPath, const std::string& outputPath, const std::string& password);

private:
    void generateRandomSalt(uint8_t* buffer, int length);
    SFMHeader createDefaultHeader();
};

#endif
