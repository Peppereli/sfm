#include "qtwindow.h"

namespace fs = std::filesystem;

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
{
    setWindowTitle("SFM");
    resize(500, 400);

    QWidget* central = new QWidget(this);

    setCentralWidget(central);

    QVBoxLayout* layout = new QVBoxLayout(central);

    QStringList buttons = {
        "Encrypt File",
        "Decrypt File",
        "Secure Wipe",
        "Password Manager",
        "Change Password",
        "Exit"
    };

    for (const QString& text : buttons)
    {
        QPushButton* btn = new QPushButton(text);

        btn->setMinimumHeight(45);

        layout->addWidget(btn);

        connect(btn, &QPushButton::clicked, this, [=]()
        {
            if (text == "Encrypt File")
                encryptFile();

            else if (text == "Decrypt File")
                decryptFile();

            else if (text == "Secure Wipe")
                secureWipe();

            else if (text == "Password Manager")
                passwordManager();

            else if (text == "Change Password")
                changePassword();

            else if (text == "Exit")
                close();
        });
    }
}

bool MainWindow::authenticate(std::string& pass)
{
    bool ok;

    if (!manager.isPasswordSet("pass"))
    {
        QString p1 = QInputDialog::getText(
            this,
            "Setup",
            "Create Master Password:",
            QLineEdit::Password,
            "",
            &ok
        );

        if (!ok || p1.isEmpty())
            return false;

        QString p2 = QInputDialog::getText(
            this,
            "Setup",
            "Confirm Password:",
            QLineEdit::Password,
            "",
            &ok
        );

        if (p1 != p2)
        {
            QMessageBox::critical(
                this,
                "Error",
                "Passwords do not match."
            );

            return false;
        }

        manager.setPassword("pass", p1.toStdString());

        std::vector<std::string> answers(3);

        answers[0] = QInputDialog::getText(
            this,
            "Security Question",
            "Pet name:"
        ).toStdString();

        answers[1] = QInputDialog::getText(
            this,
            "Security Question",
            "Birth city:"
        ).toStdString();

        answers[2] = QInputDialog::getText(
            this,
            "Security Question",
            "Favorite book:"
        ).toStdString();

        manager.setupSecurityQuestions(answers);

        pass = p1.toStdString();

        return true;
    }

    QString pwd = QInputDialog::getText(
        this,
        "Authentication",
        "Password:",
        QLineEdit::Password,
        "",
        &ok
    );

    if (!ok || pwd.isEmpty())
        return false;

    if (!manager.authenticate("pass", pwd.toStdString()))
    {
        QMessageBox::critical(
            this,
            "Denied",
            "Invalid password."
        );

        return false;
    }

    pass = pwd.toStdString();

    return true;
}

void MainWindow::encryptFile()
{
    std::string pass;

    if (!authenticate(pass))
        return;

    QString file = QFileDialog::getOpenFileName(
        this,
        "Select File"
    );

    if (file.isEmpty())
        return;

    QString comment = QInputDialog::getText(
        this,
        "Comment",
        "Optional Comment:"
    );

    std::string out =
        fs::path(file.toStdString()).filename().string();

    bool ok = manager.encryptFile(
        file.toStdString(),
        out,
        pass,
        comment.toStdString()
    );

    QMessageBox::information(
        this,
        "Encryption",
        ok ? "Encrypted successfully."
           : "Encryption failed."
    );
}

void MainWindow::decryptFile()
{
    std::string pass;

    if (!authenticate(pass))
        return;

    QString file = QFileDialog::getOpenFileName(
        this,
        "Decrypt File",
        QString::fromStdString(getSFMDirectory())
    );

    if (file.isEmpty())
        return;

    std::string filename =
        fs::path(file.toStdString()).filename().string();

    std::string out =
        fs::current_path().string() + "/" + filename;

    bool ok = manager.decryptFile(
        file.toStdString(),
        out,
        pass
    );

    QMessageBox::information(
        this,
        "Decrypt",
        ok ? "Decrypted successfully."
           : "Decryption failed."
    );
}

void MainWindow::secureWipe()
{
    QString file = QFileDialog::getOpenFileName(
        this,
        "Select File"
    );

    if (file.isEmpty())
        return;

    auto confirm = QMessageBox::warning(
        this,
        "WARNING",
        "Permanently delete this file?",
        QMessageBox::Yes | QMessageBox::No
    );

    if (confirm != QMessageBox::Yes)
        return;

    bool ok = manager.secureDeleteFile(
        file.toStdString()
    );

    QMessageBox::information(
        this,
        "Wipe",
        ok ? "File securely deleted."
           : "Delete failed."
    );
}

void MainWindow::passwordManager()
{
    std::string pass;

    if (!authenticate(pass))
        return;

    std::vector<PasswordEntry> passwords =
        manager.loadPasswords(pass);

    QDialog dialog(this);

    dialog.setWindowTitle("Password Manager");

    dialog.resize(700, 400);

    QVBoxLayout* layout = new QVBoxLayout(&dialog);

    QTableWidget* table = new QTableWidget();

    table->setColumnCount(2);

    table->setHorizontalHeaderLabels({
        "Account",
        "Login"
    });

    table->horizontalHeader()->setStretchLastSection(true);

    table->setRowCount(passwords.size());

    for (int i = 0; i < passwords.size(); i++)
    {
        table->setItem(
            i,
            0,
            new QTableWidgetItem(
                QString::fromStdString(passwords[i].name)
            )
        );

        table->setItem(
            i,
            1,
            new QTableWidgetItem(
                QString::fromStdString(passwords[i].login)
            )
        );
    }

    layout->addWidget(table);

    QPushButton* copyPass =
        new QPushButton("Copy Password");

    layout->addWidget(copyPass);

    QObject::connect(copyPass, &QPushButton::clicked,
    [&]()
    {
        int row = table->currentRow();

        if (row < 0)
            return;

        QGuiApplication::clipboard()->setText(
            QString::fromStdString(
                passwords[row].password
            )
        );
    });

    dialog.exec();
}

void MainWindow::changePassword()
{
    std::string pass;

    if (!authenticate(pass))
        return;

    bool ok;

    QString p1 = QInputDialog::getText(
        this,
        "Change Password",
        "New Password:",
        QLineEdit::Password,
        "",
        &ok
    );

    if (!ok || p1.isEmpty())
        return;

    QString p2 = QInputDialog::getText(
        this,
        "Change Password",
        "Confirm Password:",
        QLineEdit::Password,
        "",
        &ok
    );

    if (p1 != p2)
    {
        QMessageBox::critical(
            this,
            "Error",
            "Passwords do not match."
        );

        return;
    }

    bool changed = manager.changePassword(
        "pass",
        pass,
        p1.toStdString()
    );

    QMessageBox::information(
        this,
        "Password",
        changed
            ? "Password changed."
            : "Failed to change password."
    );
}
