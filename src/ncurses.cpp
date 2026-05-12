#include <ncurses.h>
#include <string>
#include <vector>
#include <filesystem>
#include <algorithm>
#include "core/functions.h"

namespace fs = std::filesystem;

std::string get_input_str(int y, int x, const std::string& prompt, bool mask = false) {
    mvprintw(y, x, "%s", prompt.c_str());
    clrtoeol();
    echo();
    if (mask) noecho();
    
    char buf[256];
    getnstr(buf, 255);
    
    noecho();
    return std::string(buf);
}

void update_status(const std::string& msg, bool is_error = false) {
    move(LINES - 1, 0);
    clrtoeol();
    if (is_error) attron(COLOR_PAIR(2) | A_BOLD);
    else attron(A_REVERSE);
    
    mvprintw(LINES - 1, 0, " Status: %s", msg.c_str());
    
    attroff(COLOR_PAIR(2) | A_BOLD);
    attroff(A_REVERSE);
    wnoutrefresh(stdscr);
    doupdate();
}

std::string file_browser(const std::string& start_dir, ContainerManager* manager = nullptr) {
    std::string current_dir = start_dir;
    int highlight = 0;
    int offset = 0;

    while (true) {
        erase();
        box(stdscr, 0, 0);
        attron(A_BOLD);
        mvprintw(1, 2, " [ Dir: %s ] ", current_dir.c_str());
        attroff(A_BOLD);

        std::vector<fs::directory_entry> entries;
        try {
            for (const auto& entry : fs::directory_iterator(current_dir)) {
                std::string fname = entry.path().filename().string();
                
                if (fname == "pass" || fname == "passwords.sfm" || fname == ".temp_pwd") {
                    continue; 
                }
                entries.push_back(entry);
            }
        } catch (...) {}

        std::sort(entries.begin(), entries.end(), [](const fs::directory_entry& a, const fs::directory_entry& b) {
            if (a.is_directory() && !b.is_directory()) return true;
            if (!a.is_directory() && b.is_directory()) return false;
            return a.path().filename().string() < b.path().filename().string();
        });

        std::vector<std::string> display_list;
        for (const auto& e : entries) {
            std::string name = e.path().filename().string();
            if (e.is_directory()) {
                name = "[ ] " + name;
            } 
            else if (manager != nullptr) {
                std::string cmt = manager->getFileComment(e.path().string());
                if (!cmt.empty()) {
                    name += "  // " + cmt;
                }
            }
            display_list.push_back(name);
        }

        int max_lines = LINES - 4;
        if (highlight < offset) {
            offset = highlight;
        } 
         else if (highlight >= offset + max_lines) {
            offset = highlight - max_lines + 1;
        }

        for (int i = 0; i < max_lines && (i + offset) < display_list.size(); i++) {
             int idx = i + offset;
             bool is_dir = entries[idx].is_directory();
             if (idx == highlight) attron(A_REVERSE);
             if (is_dir) attron(COLOR_PAIR(3));
             mvprintw(i + 3, 4, " %s ", display_list[idx].c_str());
             if (is_dir) attroff(COLOR_PAIR(3));
             if (idx == highlight) attroff(A_REVERSE);
        }
        mvprintw(LINES - 2, 2, " Use j/k to navigate, ENTER to select, 'q' to cancel.");
        wnoutrefresh(stdscr);
        doupdate();
        int c = getch();

        if (c == 'k' || c == KEY_UP) {
           if (highlight > 0) highlight--;
        }else if (c == 'j' || c == KEY_DOWN) {
           if (highlight < display_list.size() - 1) highlight++;
        }else if (c == 'h' || c == KEY_LEFT) {
           auto parent = fs::path(current_dir).parent_path();
           if (parent != current_dir)
              current_dir = parent.string();
              highlight = 0;
        }else if (c == 'l' || c == KEY_RIGHT || c == 10) {
              auto selected = entries[highlight];
              if (selected.is_directory()) {
              current_dir = selected.path().string();
              highlight = 0;
        }else {
              return selected.path().string();
        }
     highlight = 0;
    }else if (c == 'q') {
    return "";
    }
}
}

int main() {
    initscr();
    start_color();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    curs_set(0);

    init_pair(1, COLOR_CYAN, COLOR_BLACK);
    init_pair(2, COLOR_RED, COLOR_BLACK);
    init_pair(3, COLOR_BLUE, COLOR_BLACK);

    ContainerManager manager;
    
    std::vector<std::string> menu = {
        "Encrypt File",
        "Decrypt File",
        "Secure Wipe",
        "Password Manager",
        "Change Password",
        "Exit"
    };

    int highlight = 1;
    while(true) {
        erase();
        box(stdscr, 0, 0);
        attron(A_BOLD | COLOR_PAIR(3));
        mvprintw(1, 2, " SFM ");
        attroff(A_BOLD | COLOR_PAIR(3));

        for(int i = 0; i < menu.size(); i++) {
            if(highlight == i + 1) {
                attron(A_REVERSE);
                mvprintw(i + 3, 4, " %s ", menu[i].c_str());
                attroff(A_REVERSE);
            } else {
                mvprintw(i + 3, 4, " %s ", menu[i].c_str());
            }
        }
        wnoutrefresh(stdscr);
        doupdate();

        int c = getch();
        if (c == 'k' || c == KEY_UP) {
            highlight = (highlight == 1) ? menu.size() : highlight - 1;
        } else if (c == 'j' || c == KEY_DOWN) {
            highlight = (highlight == menu.size()) ? 1 : highlight + 1;
        } else if (c == 'q') {
            break;
        } else if (c == 10 || c == 'l') {
            if (highlight == 6) break;

            erase();
            box(stdscr, 0, 0);
            curs_set(1);

            std::string pass;
            
            if (!manager.isPasswordSet("pass")) {
                mvprintw(1, 2, "First time setup. Please create a master password.");
                pass = get_input_str(3, 2, "Enter Password: ", true);
                std::string pass2 = get_input_str(4, 2, "Confirm Password: ", true);
                
                if (pass != pass2 || pass.empty()) {
                    update_status("Passwords do not match or empty!", true);
                    curs_set(0); getch(); continue;
                }
                manager.setPassword("pass", pass);
                
                erase(); box(stdscr, 0, 0);
                mvprintw(1, 2, "--- Security Questions Setup ---");
                mvprintw(2, 2, "These will be used if you forget your password.");
                
                std::vector<std::string> answers(3);
                answers[0] = get_input_str(4, 2, "1. What is your pet's name? ");
                answers[1] = get_input_str(5, 2, "2. What city were you born in? ");
                answers[2] = get_input_str(6, 2, "3. What is your favorite book? ");
                
                manager.setupSecurityQuestions(answers);
                update_status("Password and security questions registered.");
            } else {
                pass = get_input_str(2, 2, "Password (type '?' to recover): ", true);
                
                if (pass == "?") {
                    erase(); box(stdscr, 0, 0);
                    mvprintw(1, 2, "--- Password Recovery ---");
                    
                    std::vector<std::string> answers(3);
                    answers[0] = get_input_str(3, 2, "1. What is your pet's name? ");
                    answers[1] = get_input_str(4, 2, "2. What city were you born in? ");
                    answers[2] = get_input_str(5, 2, "3. What is your favorite book? ");
                    
                    if (manager.verifySecurityQuestions(answers)) {
                        std::string new_pass = get_input_str(7, 2, "Enter New Password: ", true);
                        std::string new_pass2 = get_input_str(8, 2, "Confirm New Password: ", true);
                        
                        if (new_pass == new_pass2 && !new_pass.empty()) {
                            manager.setPassword("pass", new_pass);
                            pass = new_pass;
                            update_status("Password reset successfully. Authenticated.");
                        } else {
                            update_status("Passwords do not match!", true);
                            curs_set(0); getch(); continue;
                        }
                    } else {
                        update_status("Incorrect answers! Access Denied.", true);
                        curs_set(0); getch(); continue;
                    }
                } 
                else if (pass.empty()) {
                    update_status("Password cannot be empty!", true);
                    curs_set(0); getch(); continue;
                }
                else if (!manager.authenticate("pass", pass)) {
                    update_status("Invalid Password! Access Denied.", true);
                    curs_set(0); getch(); continue;
                } else {
                    update_status("Authenticated.");
                }
            }



            refresh();
            clear();
            box(stdscr, 0, 0);

            
            if (highlight == 1) { // Encrypt File
                erase();
                std::string in = file_browser(fs::current_path().string());
                if (!in.empty()) {
                    erase(); box(stdscr, 0, 0);
                    std::string out = fs::path(in).filename().string();
                    mvprintw(2, 2, "Encrypting: %s", out.c_str());
                    std::string comment = get_input_str(4, 2, "Comment (optional, Enter to skip): ");
                    mvprintw(6, 2, "Processing...");
                    refresh();
                    
                    if (manager.encryptFile(in, out, pass, comment))
                        update_status("Encrypted successfully.");
                    else
                        update_status("Encryption failed.", true);
                }
            }
            else if (highlight == 2) { // Decrypt File
                erase();
                std::string in = file_browser(getSFMDirectory(), &manager);
                if (!in.empty()) {
                    std::string filename = fs::path(in).filename().string();
                    
                    // ЖЕСТКАЯ БЛОКИРОВКА: запрещаем трогать системные файлы
                    if (filename == "pass" || filename == "passwords.sfm" || filename == ".temp_pwd") {
                        update_status("Access Denied: Cannot decrypt system files!", true);
                        continue;
                    }

                    erase(); box(stdscr, 0, 0);
                    std::string out = fs::current_path().string() + "/" + filename;
                    mvprintw(2, 2, "Decrypting to: %s", out.c_str());
                    refresh();

                    if (manager.decryptFile(in, out, pass))
                        update_status("Decrypted successfully.");
                    else
                        update_status("Decryption failed.", true);
                }
            }

            else if (highlight == 3) { // Secure Wipe
                erase(); box(stdscr, 0, 0);
                mvprintw(1, 2, " --- Secure Wipe --- ");
                mvprintw(3, 4, "[1] Browse Current Directory");
                mvprintw(4, 4, "[2] Browse .sfm Vault Directory");
                mvprintw(6, 2, "Select location (1/2) or 'q' to cancel: ");
                refresh();

                int choice = getch();
                std::string start_dir;

                if (choice == '1') {
                    start_dir = fs::current_path().string();
                } else if (choice == '2') {
                    start_dir = getSFMDirectory();
                } else {
                    update_status("Operation cancelled.");
                    continue;
                }

                std::string path_to_wipe = file_browser(start_dir, &manager);

                if (!path_to_wipe.empty()) {
                    erase(); box(stdscr, 0, 0);
                    attron(COLOR_PAIR(2) | A_BOLD);
                    mvprintw(2, 2, "WARNING: This will permanently destroy:");
                    attroff(COLOR_PAIR(2) | A_BOLD);
                    mvprintw(3, 2, "%s", path_to_wipe.c_str());
                    mvprintw(5, 2, "Are you sure? (y/n): ");
                    refresh();

                if (getch() == 'y') {
                    mvprintw(7, 2, "Wiping... Please wait.");
                    refresh();
                if (manager.secureDeleteFile(path_to_wipe)) {
                    update_status("File securely wiped and deleted.");
                } else {
                    update_status("Wipe failed (file might be in use).", true);
                }
                } else {
                update_status("Wipe cancelled.");
                }
                } else {
                    update_status("No file selected.");
                }
            }


            else if (highlight == 4) { // Password Manager
                erase(); box(stdscr, 0, 0);
                mvprintw(1, 2, " Loading Password Database... ");
                refresh();

                std::vector<PasswordEntry> passwords = manager.loadPasswords(pass);
                int pwd_highlight = 0;
                bool pwd_running = true;

                while (pwd_running) {
                    erase(); box(stdscr, 0, 0);
                    attron(A_BOLD | COLOR_PAIR(3));
                    mvprintw(1, 2, " --- Password Manager --- ");
                    attroff(A_BOLD | COLOR_PAIR(3));

                    if (passwords.empty()) {
                        mvprintw(3, 4, "No passwords saved yet.");
                    } else {
                        for (int i = 0; i < passwords.size(); i++) {
                            if (i == pwd_highlight) attron(A_REVERSE);
                            mvprintw(i + 3, 4, " %-20s | %-25s ", passwords[i].name.c_str(), passwords[i].login.c_str());
                            if (i == pwd_highlight) attroff(A_REVERSE);
                        }
                    }

                    mvprintw(LINES - 3, 2, " [a] Add  [g] Gen  [e] Edit  [d] Del  [c] Copy Pass  [u] Copy Login  [q] Back ");
                    wnoutrefresh(stdscr); doupdate();

                    int ch = getch();
                    if (ch == 'q') {
                        manager.savePasswords(passwords, pass);
                        pwd_running = false;
                    } 
                    else if (ch == 'k' || ch == KEY_UP) {
                        if (pwd_highlight > 0) pwd_highlight--;
                    } 
                    else if (ch == 'j' || ch == KEY_DOWN) {
                        if (pwd_highlight < passwords.size() - 1) pwd_highlight++;
                    }
                    else if (ch == 'a' || ch == 'g') {
                        erase(); box(stdscr, 0, 0);
                        
                        std::string name = get_input_str(2, 2, "Account Name (e.g. Telegram): ");
                        std::string login = get_input_str(3, 2, "Login/Email: ");
                        std::string new_pass;
                        
                        if (ch == 'g') {
                            std::string len_str = get_input_str(4, 2, "Password length (default 16): ");
                            int pwd_len = 16; 
                            
                            if (!len_str.empty()) {
                                try {
                                    pwd_len = std::stoi(len_str);
                                    if (pwd_len < 8) pwd_len = 8;
                                    if (pwd_len > 128) pwd_len = 128; 
                                } catch (...) {
                                    pwd_len = 16;
                                }
                            }
                            
                            new_pass = manager.generateStrongPassword(pwd_len);
                            move(5, 0); clrtoeol();
                            mvprintw(5, 2, "Generated Password: %s", new_pass.c_str());
                            mvprintw(6, 2, "Press any key to continue...");
                            getch();
                        } else {
                            new_pass = get_input_str(4, 2, "Password: ", true);
                        }

                        if (!name.empty() && !login.empty() && !new_pass.empty()) {
                            passwords.push_back(PasswordEntry{name, login, new_pass});
                            manager.savePasswords(passwords, pass);
                            update_status("Password saved successfully.");
                        }
                    }

                    else if (ch == 'e' && !passwords.empty()) {
                        erase(); box(stdscr, 0, 0);
                        mvprintw(1, 2, " --- Edit Entry --- ");
                        mvprintw(2, 2, " (Leave blank and press Enter to keep current value) ");
                        
                        std::string new_name = get_input_str(4, 2, "New Name [" + passwords[pwd_highlight].name + "]: ");
                        std::string new_login = get_input_str(5, 2, "New Login [" + passwords[pwd_highlight].login + "]: ");
                        std::string new_pass = get_input_str(6, 2, "New Password (hidden): ", true);

                        if (!new_name.empty()) passwords[pwd_highlight].name = new_name;
                        if (!new_login.empty()) passwords[pwd_highlight].login = new_login;
                        if (!new_pass.empty()) passwords[pwd_highlight].password = new_pass;

                        manager.savePasswords(passwords, pass);
                        update_status("Entry updated successfully.");
                    }
                    else if (ch == 'd' && !passwords.empty()) {
                        mvprintw(LINES - 2, 2, " Delete '%s'? (y/n): ", passwords[pwd_highlight].name.c_str());
                        int confirm = getch();
                        if (confirm == 'y' || confirm == 'Y') {
                            passwords.erase(passwords.begin() + pwd_highlight);
                            
                            if (pwd_highlight >= passwords.size() && pwd_highlight > 0) {
                                pwd_highlight--;
                            }
                            
                            manager.savePasswords(passwords, pass);
                            update_status("Entry deleted.");
                        } else {
                            update_status("Deletion cancelled.");
                        }
                    }
                    else if (ch == 'c' && !passwords.empty()) {
                        manager.copyToClipboard(passwords[pwd_highlight].password);
                        update_status("Password copied to clipboard!");
                    }
                    else if (ch == 'u' && !passwords.empty()) {
                        manager.copyToClipboard(passwords[pwd_highlight].login);
                        update_status("Login copied to clipboard!");
                    }
                }
            }


            else if (highlight == 5) {
                erase(); box(stdscr, 0, 0);
                mvprintw(1, 2, "--- Change Password ---");
                
                std::string newPass = get_input_str(3, 2, "Enter New Password: ", true);
                std::string newPass2 = get_input_str(4, 2, "Confirm New Password: ", true);
                
                if (newPass == newPass2 && !newPass.empty()) {
                    if (manager.changePassword("pass", pass, newPass)) {
                        update_status("Password changed successfully.");
                    } else {
                        update_status("Failed to change password.", true);
                    }
                } else {
                    update_status("New passwords do not match or empty!", true);
                }
            }
/*
            else if (highlight == 8) { // Self-Destruct
                erase(); box(stdscr, 0, 0);
                attron(COLOR_PAIR(2) | A_BOLD);
                mvprintw(2, 2, "!!! WARNING: TOTAL ANNIHILATION !!!");
                attroff(COLOR_PAIR(2) | A_BOLD);
                mvprintw(4, 2, "This will PERMANENTLY DELETE all your encrypted vaults,");
                mvprintw(5, 2, "passwords, and the application itself.");
                mvprintw(7, 2, "Type 'DESTROY' to confirm: ");
    
                echo();
                char confirmBuf[256];
                getnstr(confirmBuf, 255);
                noecho();
    
                if (std::string(confirmBuf) == "DESTROY") {
                    update_status("Wiping all data and self-destructing...");
                    std::string exePath = fs::canonical("/proc/self/exe").string();
        
                    manager.selfDestructApp(exePath);
        
                    endwin();
                    exit(0);
                } else {
                update_status("Self-destruct aborted.");
                }
            }
*/
            curs_set(0);
            mvprintw(LINES - 2, 2, "Done. Press any key...");
            getch();
            clear();
            refresh();
        }
    }

    endwin();
    return 0;
}

