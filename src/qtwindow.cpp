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

    layout->setAlignment(Qt::AlignCenter);
    layout->setSpacing(15);

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

        btn->setFixedSize(220, 45);

        layout->addWidget(btn, 0, Qt::AlignCenter);

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
        "Password (? for recovery):",
        QLineEdit::Password,
        "",
        &ok
    );

    if (!ok || pwd.isEmpty())
        return false;

    if (pwd == "?")
    {
        std::vector<std::string> answers(3);

        answers[0] = QInputDialog::getText(
            this,
            "Recovery",
            "Pet name:"
        ).toStdString();

        answers[1] = QInputDialog::getText(
            this,
            "Recovery",
            "Birth city:"
        ).toStdString();

        answers[2] = QInputDialog::getText(
            this,
            "Recovery",
            "Favorite book:"
        ).toStdString();

        if (!manager.verifySecurityQuestions(answers))
        {
            QMessageBox::critical(
                this,
                "Denied",
                "Wrong answers."
            );

            return false;
        }

        QString np1 = QInputDialog::getText(
            this,
            "Reset Password",
            "New Password:",
            QLineEdit::Password
        );

        QString np2 = QInputDialog::getText(
            this,
            "Reset Password",
            "Confirm Password:",
            QLineEdit::Password
        );

        if (np1 != np2 || np1.isEmpty())
            return false;

        manager.setPassword(
            "pass",
            np1.toStdString()
        );

        pass = np1.toStdString();

        QMessageBox::information(
            this,
            "Recovered",
            "Password reset successful."
        );

        return true;
    }

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

    if (filename == "pass" ||
        filename == "passwords.sfm" ||
        filename == ".temp_pwd")
    {
        QMessageBox::critical(
            this,
            "Denied",
            "Cannot decrypt system files."
        );

        return;
    }

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
    std::string pass;

    // REQUIRE PASSWORD FIRST
    if (!authenticate(pass))
        return;

    QMessageBox msg(this);

    msg.setWindowTitle("Secure Wipe");

    msg.setText("Choose location to wipe from:");

    QPushButton* currentBtn =
        msg.addButton(
            "Current Directory",
            QMessageBox::ActionRole
        );

    QPushButton* vaultBtn =
        msg.addButton(
            "Vault Directory",
            QMessageBox::ActionRole
        );

    QPushButton* cancelBtn =
        msg.addButton(QMessageBox::Cancel);

    msg.exec();

    QString startDir;

    if (msg.clickedButton() == currentBtn)
    {
        startDir =
            QString::fromStdString(
                fs::current_path().string()
            );
    }
    else if (msg.clickedButton() == vaultBtn)
    {
        startDir =
            QString::fromStdString(
                getSFMDirectory()
            );
    }
    else
    {
        return;
    }

    QString file = QFileDialog::getOpenFileName(
        this,
        "Select File",
        startDir
    );

    if (file.isEmpty())
        return;

    std::string filename =
        fs::path(file.toStdString()).filename().string();

    // BLOCK SYSTEM FILES
    if (
        filename == "pass" ||
        filename == "passwords.sfm" ||
        filename == ".temp_pwd"
    )
    {
        QMessageBox::critical(
            this,
            "Access Denied",
            "Cannot wipe system files."
        );

        return;
    }

    auto confirm = QMessageBox::warning(
        this,
        "WARNING",
        "This will permanently destroy:\n\n" +
        file +
        "\n\nContinue?",
        QMessageBox::Yes | QMessageBox::No
    );

    if (confirm != QMessageBox::Yes)
        return;

    bool ok =
        manager.secureDeleteFile(
            file.toStdString()
        );

    QMessageBox::information(
        this,
        "Secure Wipe",
        ok
            ? "File securely wiped."
            : "Wipe failed."
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

    dialog.resize(800, 450);

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

    QHBoxLayout* btnLayout = new QHBoxLayout();

    QPushButton* addBtn =
        new QPushButton("Add");

    QPushButton* genBtn =
        new QPushButton("Generate");

    QPushButton* editBtn =
        new QPushButton("Edit");

    QPushButton* delBtn =
        new QPushButton("Delete");

    QPushButton* copyPass =
        new QPushButton("Copy Password");

    QPushButton* copyLogin =
        new QPushButton("Copy Login");

    btnLayout->addWidget(addBtn);
    btnLayout->addWidget(genBtn);
    btnLayout->addWidget(editBtn);
    btnLayout->addWidget(delBtn);
    btnLayout->addWidget(copyPass);
    btnLayout->addWidget(copyLogin);

    layout->addLayout(btnLayout);

    connect(addBtn, &QPushButton::clicked, [&]()
    {
        QString name = QInputDialog::getText(
            &dialog,
            "Add Entry",
            "Account:"
        );

        QString login = QInputDialog::getText(
            &dialog,
            "Add Entry",
            "Login:"
        );

        QString pwd = QInputDialog::getText(
            &dialog,
            "Add Entry",
            "Password:",
            QLineEdit::Password
        );

        if (name.isEmpty() ||
            login.isEmpty() ||
            pwd.isEmpty())
            return;

        passwords.push_back({
            name.toStdString(),
            login.toStdString(),
            pwd.toStdString()
        });

        manager.savePasswords(passwords, pass);

        table->insertRow(table->rowCount());

        int row = table->rowCount() - 1;

        table->setItem(
            row,
            0,
            new QTableWidgetItem(name)
        );

        table->setItem(
            row,
            1,
            new QTableWidgetItem(login)
        );
    });

    connect(genBtn, &QPushButton::clicked, [&]()
    {
        bool ok;

        int len = QInputDialog::getInt(
            &dialog,
            "Generate Password",
            "Length:",
            16,
            8,
            128,
            1,
            &ok
        );

        if (!ok)
            return;

        std::string generated =
            manager.generateStrongPassword(len);

        QApplication::clipboard()->setText(
            QString::fromStdString(generated)
        );

        QMessageBox::information(
            &dialog,
            "Generated",
            "Password copied to clipboard."
        );
    });

    connect(editBtn, &QPushButton::clicked, [&]()
    {
        int row = table->currentRow();

        if (row < 0)
            return;

        QString name = QInputDialog::getText(
            &dialog,
            "Edit",
            "Account:",
            QLineEdit::Normal,
            QString::fromStdString(
                passwords[row].name
            )
        );

        QString login = QInputDialog::getText(
            &dialog,
            "Edit",
            "Login:",
            QLineEdit::Normal,
            QString::fromStdString(
                passwords[row].login
            )
        );

        QString pwd = QInputDialog::getText(
            &dialog,
            "Edit",
            "Password:",
            QLineEdit::Password,
            QString::fromStdString(
                passwords[row].password
            )
        );

        passwords[row] = {
            name.toStdString(),
            login.toStdString(),
            pwd.toStdString()
        };

        manager.savePasswords(passwords, pass);

        table->item(row, 0)->setText(name);
        table->item(row, 1)->setText(login);
    });

    connect(delBtn, &QPushButton::clicked, [&]()
    {
        int row = table->currentRow();

        if (row < 0)
            return;

        passwords.erase(
            passwords.begin() + row
        );

        manager.savePasswords(passwords, pass);

        table->removeRow(row);
    });

    connect(copyPass, &QPushButton::clicked,
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

    connect(copyLogin, &QPushButton::clicked,
    [&]()
    {
        int row = table->currentRow();

        if (row < 0)
            return;

        QGuiApplication::clipboard()->setText(
            QString::fromStdString(
                passwords[row].login
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
