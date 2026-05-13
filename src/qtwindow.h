#pragma once

#include <QMainWindow>
#include <QPushButton>
#include <QVBoxLayout>
#include <QMessageBox>
#include <QInputDialog>
#include <QFileDialog>
#include <QTableWidget>
#include <QHeaderView>
#include <QClipboard>
#include <QGuiApplication>

#include <filesystem>
#include <vector>

#include "core/functions.h"

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);

private:
    ContainerManager manager;

    bool authenticate(std::string& pass);

    void encryptFile();
    void decryptFile();
    void secureWipe();
    void passwordManager();
    void changePassword();
};
