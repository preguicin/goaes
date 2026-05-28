# AES-128 File Processor

A lightweight Go command-line tool for encrypting and decrypting files using the AES-128 algorithm. It supports both standard **ECB (Electronic Codebook)** and **CBC (Cipher Block Chaining)** block cipher modes.

The application can be run in two distinct modes: **CLI Flag Mode** for automated scripting and fast execution, or **Interactive Mode** for step-by-step user prompts.

---

## Getting Started

### Prerequisites
* Go 1.18 or higher installed.

### Compilation
Build the executable using the Go toolchain:
```bash
go build main.go
```

---

## Usage Modes

The tool automatically detects how you want to run it based on the presence of command-line flags.

### 1. Interactive Mode

If you pass the `-i` flag, or if you run the program without providing the minimum required arguments (`-mode`, `-op`, and `-in`), the application defaults to an interactive CLI wizard (written in Portuguese) to guide you through the process.

```bash
./goaes -i
# OR simply run:
./goaes
```

**Example Wizard Flow:**

```text
--- AES-128 File Processor (Interactive Mode) ---
Escolha o modo de operação ([1] ECB ou [2] CBC): 2
Escolha a ação ([C]ifrar ou [D]ecifrar): C
Caminho do arquivo de entrada: plaintext.txt
Nome do arquivo de saída: encrypted.bin
Informe a chave (16 números decimais separados por vírgula):
> 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16
Informe o IV (16 números decimais separados por vírgula):
> 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
Sucesso: Arquivo cifrado.
Arquivo salvo em: encrypted.bin

```

---

### 2. CLI Flag Mode

For script automation

```bash
./goaes [flags]

```

#### Available Flags

| Flag | Type | Description | Required? |
| --- | --- | --- | --- |
| `-i` | boolean | Force run in Interactive Mode. | Optional |
| `-mode` | string | Block cipher mode: `ecb` or `cbc`. | **Required** in CLI mode |
| `-op` | string | Action to perform: `encrypt` or `decrypt`. | **Required** in CLI mode |
| `-in` | string | Path to the source input file. | **Required** in CLI mode |
| `-out` | string | Path to save the resulting output file. | **Required** in CLI mode |
| `-key` | string | 16 comma-separated decimal bytes (0-255). | **Required** in CLI mode |
| `-iv` | string | 16 comma-separated decimal bytes (0-255). | **Required** for `cbc` mode |
| `-p` | boolean | Prints encrypted blocks out to the terminal as Hex. | Optional |

---

## 💡 Key and IV Formatting Note

Both the `-key` and `-iv` flags require exactly **16 decimal numbers (bytes)** between `0` and `255`, separated by commas without spaces.

* **Valid Format Example:** `143,22,89,0,255,12,43,9,101,202,33,44,55,66,77,88`

---

## 📋 Examples

### Encrypt a file using CBC mode and print the Hex blocks

```bash
./goaes \
  -mode cbc \
  -op encrypt \
  -in document.txt \
  -out document.enc \
  -key 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 \
  -iv 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 \
  -p

```

### Decrypt a file using ECB mode

```bash
./goaes \
  -mode ecb \
  -op decrypt \
  -in document.enc \
  -out restored.txt \
  -key 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16
```
