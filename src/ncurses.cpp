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
        "Create New Vault",
        "Open/Check Vault",
        "Encrypt File",
        "Decrypt File",
        "Secure Wipe",
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
            if (highlight == 7) break;

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
                update_status("Password registered successfully.");
            } else {
                pass = get_input_str(2, 2, "Password: ", true);
                if (!manager.authenticate("pass", pass)) {
                    update_status("Invalid Password! Access Denied.", true);
                    curs_set(0); getch(); continue;
                }
                update_status("Authenticated.");
            }

            refresh();
            clear();
            box(stdscr, 0, 0);

            if (highlight == 1) {
                update_status("Opening system dialog to create vault...");
                endwin();
                std::string path = manager.saveFileDialog();
                refresh();
                
                if (!path.empty()) {
                    if (manager.createContainer(path, pass, 10 * 1024 * 1024))
                        update_status("Vault Created at: " + path);
                    else
                        update_status("Failed to create vault.", true);
                } else {
                    update_status("Creation cancelled.");
                }
            }
            else if (highlight == 2) { // Open/Check Vault
                update_status("Opening system dialog to select vault...");
                endwin();
                std::string path = manager.openFileDialog();
                refresh();
                
                if (!path.empty()) {
                    if (manager.openContainer(path, pass)) {
                        update_status("Vault unlocked. Opening with default OS tool...");
                        manager.openWithDefaultApp(path);
                    } else {
                        update_status("Failed to open vault.", true);
                    }
                } else {
                    update_status("Operation cancelled.");
                }
            }
            else if (highlight == 3) { // Encrypt File
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
            else if (highlight == 4) { // Decrypt File
                erase();
                std::string in = file_browser(getSFMDirectory(), &manager);
                if (!in.empty()) {
                    erase(); box(stdscr, 0, 0);
                    std::string out = fs::current_path().string() + "/" + fs::path(in).filename().string();
                    mvprintw(2, 2, "Decrypting to: %s", out.c_str());
                    refresh();

                    if (manager.decryptFile(in, out, pass))
                        update_status("Decrypted successfully.");
                    else
                        update_status("Decryption failed.", true);
                }
            }
            else if (highlight == 5) { // Secure Wipe
                std::string path = get_input_str(4, 2, "File to Wipe: ");
                mvprintw(6, 2, "Confirm Wipe? (y/n): ");
                if (getch() == 'y') {
                    if (manager.secureDeleteFile(path))
                        update_status("Wiped successfully.");
                    else
                        update_status("Wipe failed.", true);
                }
            }
            else if (highlight == 6) {
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

