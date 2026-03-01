#include <ncurses.h>
#include <string>
#include <vector>
#include "core/functions.h"

// Helper for string input
std::string get_input_str(int y, int x, const std::string& prompt, bool mask = false) {
    mvprintw(y, x, "%s", prompt.c_str());
    clrtoeol(); // Clear any old text on this line
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
    
    mvprintw(LINES - 1, 0, " STATUS: %s", msg.c_str());
    
    attroff(COLOR_PAIR(2) | A_BOLD);
    attroff(A_REVERSE);
    refresh();
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

    ContainerManager manager;
    std::vector<std::string> menu = {
        "Create New Vault",
        "Open/Check Vault",
        "Encrypt File",
        "Decrypt File",
        "Secure Wipe",
        "Exit"
    };

    int highlight = 1;
    while(true) {
        // Draw Menu
        clear();
        box(stdscr, 0, 0);
        attron(A_BOLD | COLOR_PAIR(1));
        mvprintw(1, 2, " SFM CRYPTO (Vim Keys Enabled) ");
        attroff(A_BOLD | COLOR_PAIR(1));

        for(int i = 0; i < menu.size(); i++) {
            if(highlight == i + 1) {
                attron(A_REVERSE);
                mvprintw(i + 3, 4, " %s ", menu[i].c_str());
                attroff(A_REVERSE);
            } else {
                mvprintw(i + 3, 4, " %s ", menu[i].c_str());
            }
        }
        refresh();

        int c = getch();
        // --- VIM KEY LOGIC ---
        if (c == 'k' || c == KEY_UP) {
            highlight = (highlight == 1) ? menu.size() : highlight - 1;
        } else if (c == 'j' || c == KEY_DOWN) {
            highlight = (highlight == menu.size()) ? 1 : highlight + 1;
        } else if (c == 'q') {
            break;
        } else if (c == 10 || c == 'l') { // Enter or 'l' to select
            if (highlight == 6) break;

            clear();
            box(stdscr, 0, 0);
            curs_set(1);

            // --- PASSWORD GUARD ---
            std::string pass = get_input_str(2, 2, "Password: ", true);
            
            // Check authentication BEFORE showing next prompts
            if (!manager.authenticateOrRegister("pass", pass)) {
                update_status("INVALID PASSWORD! Access Denied.", true);
                curs_set(0);
                getch(); 
                continue; // Skip the rest of the loop and return to menu
            }

            // If we reach here, password is correct
            update_status("Authenticated.");

            if (highlight == 1) {
                std::string path = get_input_str(4, 2, "Vault Name: ");
                if (manager.createContainer(path, pass, 10 * 1024 * 1024))
                    update_status("Created.");
            }
            else if (highlight == 2) {
                std::string path = get_input_str(4, 2, "Open Vault: ");
                manager.openContainer(path, pass);
            }
            else if (highlight == 3) {
                std::string in = get_input_str(4, 2, "File to Encrypt: ");
                std::string out = get_input_str(5, 2, "Output Name: ");
                manager.encryptFile(in, out, pass);
            }
            else if (highlight == 4) {
                std::string in = get_input_str(4, 2, "File to Decrypt: ");
                std::string out = get_input_str(5, 2, "Output Name: ");
                manager.decryptFile(in, out, pass);
            }
            else if (highlight == 5) {
                std::string path = get_input_str(4, 2, "File to Wipe: ");
                mvprintw(6, 2, "Confirm Wipe? (y/n): ");
                if (getch() == 'y') manager.secureDeleteFile(path);
            }

            curs_set(0);
            mvprintw(LINES - 2, 2, "Done. Press any key...");
            getch();
        }
    }

    endwin();
    return 0;
}
