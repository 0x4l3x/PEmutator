# PEMutator

**PEMutator** is a Python utility designed for **Portable Executable (PE) mutation** and **mass variant generation**. It allows to modify PE files (EXEs, DLLs) to alter their cryptographic hashes and structural signatures while attempting to maintain execution integrity.

The tool supports both **Single-File** precision adjustments and **Bulk Processing** for generating massive datasets of variants.

> **⚠️ Disclaimer**: This tool is intended for educational purposes, security research, and authorized red teaming simulations only. The authors take no responsibility for misuse.

## 🌟 Key Features

  * **Two Operation Modes**:
      * `single`: Granular control over a single file.
      * `bulk`: Automated mass generation of variants from a directory of mixed files.
  * **Smart Detection**: Uses Google's **Magika** AI to identify PE files in bulk mode, ignoring non-executable files.
  * **Mutation Engines**:
      * **Safe Mode (Raw Patching)**: Low-risk modifications (TimeDateStamp, Overlay, Section Renaming).
      * **Aggressive Mode (LIEF Rebuild)**: Structural changes (Import manipulation, Junk sections, ASLR disabling).
  * **Reporting**: Generates detailed Markdown reports and AES-256 encrypted ZIP archives for safe transport.

## 🛠️ Installation

**Prerequisites:** Python 3.8+

Install the required dependencies:

```bash
pip install lief pefile pyzipper magika
```

## 📖 Usage

Run the script with the `-h` flag to see all options:

```bash
python pemutator.py -h
```

### 1\. Single File Mode

Mutate a specific file with precise controls.

**Syntax:**

```bash
python pemutator.py single -i <INPUT> -o <OUTPUT> [OPTIONS]
```

**Examples:**

   * **Mutation only w an Specific Date:**

     ```bash
     python pemutator.py single -i Muestra1.exe -o Muestra1_v2.exe --set-date 15/11/2023
     ```

  * **Safe Mutation (Random Date):**

    ```bash
    python pemutator.py single -i payload.exe -o payload_v2.exe --safe --random-date
    ```

  * **Aggressive Mutation (Specific Date & Validation):**

    ```bash
    python pemutator.py single -i payload.exe -o payload_v2.exe --aggressive --set-date 25/12/2023 --validate
    ```

  * **Manual Granular Control:**

    ```bash
    python pemutator.py single -i payload.exe -o payload_v2.exe --rename-sections --overlay --verbose
    ```

### 2\. Bulk Processing Mode

Generate multiple unique variants for every PE file found in a directory.

**Syntax:**

```bash
python pemutator.py bulk -i <INPUT_DIR> -o <OUTPUT_DIR> -n <VARIANTS> -d <DATE> [OPTIONS]
```

**Example:**
Generate **5 variants** for every PE file in `samples/`, set their compile date to **Jan 1st, 2024**, using **Aggressive** mode:

```bash
python pemutator.py bulk -i ./samples -o ./output -n 5 -d 01/01/2024 --mode aggressive
```

**Bulk Output Structure:**
The tool creates an organized output structure:

```text
output/
├── file1_01.exe          # Raw variants
├── file1_02.exe
└── ...
output_compressed/
├── samples_variant_01.zip # All variant #1s grouped together
├── samples_variant_02.zip # All variant #2s grouped together
└── processing_report.md   # Detailed logs and stats
```

*Note: ZIP archives are encrypted with the password: `infected`*

## ⚙️ Technical Details: Safe vs. Aggressive

### 🛡️ Safe Mode (`--safe`)

Uses **Raw Binary Patching**. It modifies the file bytes directly without parsing/rebuilding the PE structure. This is safer for complex binaries (like packers or obfuscated files) but results in shallower changes.

1.  **Timestamp Patching**: Updates `TimeDateStamp` in the COFF header.
2.  **Section Renaming**: Renames non-critical sections (e.g., `.data` -\> `.xwdqy`) within the section table limits.
3.  **Overlay Appending**: Appends random junk bytes to the end of the file (EOF) to change the file size and hash.

### 🔥 Aggressive Mode (`--aggressive`)

Uses **LIEF (Library to Instrument Executable Formats)**. It parses the binary into an object model, modifies the structure, and rebuilds it.

1.  **Import Manipulation**: Adds benign imports (e.g., `kernel32.dll!GetTickCount`) to the Import Table.
2.  **Junk Section**: Creates a new PE section filled with random data and marks it as initialized data.
3.  **Disable ASLR**: Removes the `DYNAMIC_BASE` flag from DLL Characteristics.
4.  **Flag Modification**: Adds `MEM_READ` characteristics to sections.
5.  *Includes all Safe Mode modifications (Timestamp, Overlay, etc.) after rebuilding.*

## 📋 Granular Arguments (Single Mode)

If you do not wish to use the presets (`--safe` / `--aggressive`), you can mix and match these flags:

| Flag | Description |
| :--- | :--- |
| `--rename-sections` | Randomizes names of non-critical sections. |
| `--overlay` | Appends 64-512 bytes of random data to EOF. |
| `--set-date DD/MM/YYYY` | Sets the PE compilation timestamp to a specific date (random time). |
| `--random-date` | Sets a random timestamp between 2015 and 2024. |
| `--imphash` | **(LIEF)** Adds a benign API import to change the Import Hash. |
| `--junk-section` | **(LIEF)** Adds a new dummy section. |
| `--disable-aslr` | **(LIEF)** Strips ASLR compatibility. |
| `--modify-flags` | **(LIEF)** Adds Read permissions to sections. |
| `--validate` | Parses the output file to ensure it is still a valid PE. |
