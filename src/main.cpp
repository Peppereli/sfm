#include <iostream>
#include <string>
#include "core/container_manager.h"

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cout << "Usage: sfm_tool <command> <args...>\n";
        std::cout << "Commands:\n";
        std::cout << "  create <vault_name> [size_mb]   Create a new empty vault\n";
        std::cout << "  open   <vault_name>             Check vault password\n";
        std::cout << "  enc    <input_file> <out_file>  Encrypt a single file\n";
        std::cout << "  dec    <sfm_file>   <out_file>  Decrypt a single file\n";
        std::cout << "  del    <file_path>              Securely wipe & delete a file\n";
        return 1;
    }

    std::string command = argv[1];
    
    std::string password;
    std::cout << "Enter Password: ";
    std::cin >> password;

    ContainerManager manager;

    if (command == "create") {
        std::string filePath = argv[2];
        long sizeMb = (argc >= 4) ? std::stol(argv[3]) : 10;
        long sizeBytes = sizeMb * 1024 * 1024;
        
        if (manager.createContainer(filePath, password, sizeBytes)) {
            std::cout << "Container created!" << std::endl;
        }
    } 
    else if (command == "open") {
        std::string filePath = argv[2];
        manager.openContainer(filePath, password);
    }

    else if (command == "enc") {
        if (argc < 4) {
            std::cout << "Usage: sfm_tool enc <input> <output>" << std::endl;
            return 1;
        }
        std::string input = argv[2];
        std::string output = argv[3];
        manager.encryptFile(input, output, password);
    }
    else if (command == "dec") {
        if (argc < 4) {
            std::cout << "Usage: sfm_tool dec <input> <output>" << std::endl;
            return 1;
        }
        std::string input = argv[2];
        std::string output = argv[3];
        manager.decryptFile(input, output, password);
    }
    else if (command == "del") {
        std::string filePath = argv[2];
        std::cout << "WARNING: This will permanently destroy data in: " << filePath << std::endl;
        std::cout << "Are you sure? (y/n): ";
        char confirm;
        std::cin >> confirm;
        if (confirm == 'y' || confirm == 'Y') {
            manager.secureDeleteFile(filePath);
        } else {
            std::cout << "Operation cancelled." << std::endl;
        }
    }
    else {
        std::cout << "Unknown command." << std::endl;
    }

    return 0;
}
