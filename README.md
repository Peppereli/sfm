### Windows (MSYS2 / MinGW)
1.  Open your MSYS2 terminal (UCRT64).
2.  Install the toolchain and library:
    ```bash
    pacman -S mingw-w64-ucrt-x86_64-gcc
    pacman -S mingw-w64-ucrt-x86_64-cryptopp
    ```

---

## 📦 Compilation Instructions

### 1. Build the Main Tool
This is the primary CLI application for managing vaults.
```bash
g++ src/main.cpp src/core/container_manager.cpp -o sfm_tool -lcryptopp

```

### 2. Build the Prototype (Optional)

This allows you to run the legacy AES test script.

```bash
g++ src/tools/prototype_aes.cpp -o aes_test -lcryptopp

```

---

## ⚠️ Runtime Setup (Windows Only)

If you run the `.exe` and it closes immediately (silent crash), you are missing the runtime DLLs.
Run these commands in your project folder to copy them:

```bash
cp /c/msys64/ucrt64/bin/libcryptopp-*.dll .
cp /c/msys64/ucrt64/bin/libstdc++-6.dll .
cp /c/msys64/ucrt64/bin/libgcc_s_seh-1.dll .
cp /c/msys64/ucrt64/bin/libwinpthread-1.dll .

```

---

## 💻 Usage

### Create a Vault

Creates a new encrypted container filled with random-looking data (zeros encrypted).

```bash
# Syntax: create <filename> <size_in_mb>
./sfm_tool create my_vault.sfm 50

```

* **Password:** You will be prompted to enter a password securely.
* **Result:** A 50MB file named `my_vault.sfm`.

### Open / Verify a Vault

Checks if the password is correct by attempting to decrypt the first block.

```bash
# Syntax: open <filename>
./sfm_tool open my_vault.sfm

```

* **Success:** Prints `[Success] Password Correct! Container is valid.`
* **Failure:** Prints `[Access Denied] Incorrect Password.`

---

## 📂 Project Structure

* `src/core/`: The "Engine" logic (Cryptography, File I/O).
* `src/format/`: The "Blueprints" (Header structures, Constants).
* `src/tools/`: Prototypes and experimental scripts.
* `tests/`: Unit tests for architecture verification.
