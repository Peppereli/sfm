#pragma once

#include <QMainWindow>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QMessageBox>
#include <QInputDialog>
#include <QFileDialog>
#include <QDialog>
#include <QTableWidget>
#include <QHeaderView>
#include <QClipboard>
#include <QGuiApplication>
#include <QApplication>

#include <filesystem>

#include "core/functions.h"

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);

private:
    ContainerManager manager;

    bool authenticate(std::string& pass);

    void encryptFile();
    void decryptFile();
    void secureWipe();
    void passwordManager();
    void changePassword();
};
