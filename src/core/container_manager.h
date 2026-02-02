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