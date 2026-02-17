/*
#ifndef CONTAINER_MANAGER_H
#define CONTAINER_MANAGER_H

#include <string>
#include <vector>
#include "../format/sfm_header.h"

// Этот класс управляет жизненным циклом контейнера.
// Он соединяет UI (Member C) и Криптографию (Member A).
class ContainerManager {
public:
    // Конструктор
    ContainerManager();

    // Главная задача Level 1: Создать новый зашифрованный файл
    // Возвращает true, если успешно
    bool createContainer(const std::string& filePath, const std::string& password, long sizeInBytes);

    // Открыть существующий файл (проверить пароль)
    bool openContainer(const std::string& filePath, const std::string& password);

private:
    // Вспомогательная функция для генерации случайной соли (для Member A)
    void generateRandomSalt(uint8_t* buffer, int length);
    
    // Вспомогательная функция для заполнения заголовка по умолчанию
    SFMHeader createDefaultHeader();
};

#endif
*/



//--------------------------------------------------------------------------------------------------------------------------17.02.2026
#ifndef CONTAINER_MANAGER_H
#define CONTAINER_MANAGER_H

#include <string>
#include <vector>
#include "../format/sfm_header.h" // Убедитесь, что путь верный относительно папки core

class ContainerManager {
public:
    ContainerManager();

    // Создание пустого контейнера (существующий метод)
    bool createContainer(const std::string& filePath, const std::string& password, long sizeInBytes);

    // Проверка пароля (существующий метод)
    bool openContainer(const std::string& filePath, const std::string& password);

    // --- НОВЫЕ МЕТОДЫ (Интеграция prototype_aess.cpp) ---
    
    // Шифрует обычный файл inputPath в формат SFM по пути outputPath
    bool encryptFile(const std::string& inputPath, const std::string& outputPath, const std::string& password);

    // Расшифровывает SFM-файл inputPath в обычный файл outputPath
    bool decryptFile(const std::string& inputPath, const std::string& outputPath, const std::string& password);

private:
    void generateRandomSalt(uint8_t* buffer, int length);
    SFMHeader createDefaultHeader();
};

#endif
