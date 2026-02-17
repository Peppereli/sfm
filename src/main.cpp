/*
#include <iostream>
#include <string>
#include "core/container_manager.h"

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cout << "Usage: sfm_tool <command> <file> [size_mb]\n";
        std::cout << "Examples:\n";
        std::cout << "  ./sfm_tool create my_vault.sfm 20\n";
        std::cout << "  ./sfm_tool open my_vault.sfm\n";
        return 1;
    }

    std::string command = argv[1];
    std::string filePath = argv[2];

    std::string password;
    std::cout << "Enter Password: ";
    std::cin >> password;

    ContainerManager manager;

    if (command == "create") {
        long sizeMb = (argc >= 4) ? std::stol(argv[3]) : 10;
        long sizeBytes = sizeMb * 1024 * 1024;
        
        if (manager.createContainer(filePath, password, sizeBytes)) {
            std::cout << "Great success! High five!" << std::endl;
        } else {
            std::cout << "Error creating container." << std::endl;
        }
    } 
    else if (command == "open") {  // <--- THIS WAS MISSING
        if (manager.openContainer(filePath, password)) {
            // Success message is handled inside openContainer, 
            // but we can add one here too if we want.
        } else {
            std::cout << "Failed to open container." << std::endl;
        }
    }
    else {
        std::cout << "Unknown command." << std::endl;
    }

    return 0;
}
*/


//--------------------------------------------------------------------------------------------------------------------------17.02.2026

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
    else {
        std::cout << "Unknown command." << std::endl;
    }

    return 0;
}
