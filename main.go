package main

import (
	"bufio"
	"flag"
	"fmt"
	"goaes/aes"
	"os"
	"strconv"
	"strings"
)

func main() {
	// 1. Define standard CLI flags
	interactive := flag.Bool("i", false, "Run in interactive mode")
	modeFlag := flag.String("mode", "", "Operation mode: ecb or cbc")
	opFlag := flag.String("op", "", "Action: encrypt or decrypt")
	inFlag := flag.String("in", "", "Input file path")
	outFlag := flag.String("out", "", "Output file path")
	keyFlag := flag.String("key", "", "Key (16 comma-separated decimal numbers)")
	ivFlag := flag.String("iv", "", "IV (16 comma-separated decimal numbers, required for CBC)")
	printFlag := flag.Bool("p", false, "Print blocks as hex")

	flag.Parse()

	var mode aes.BlockType
	var op string
	var pathIn, pathOut string
	var key, iv [16]byte
	var err error

	if *interactive || (*modeFlag == "" && *opFlag == "" && *inFlag == "") {
		runInteractive(&mode, &op, &pathIn, &pathOut, &key, &iv)
	} else {
		if *modeFlag != "ecb" && *modeFlag != "cbc" {
			fmt.Println("Error: -mode must be 'ecb' or 'cbc'")
			flag.Usage()
			return
		}
		if *modeFlag == "ecb" {
			mode = aes.ECB
		} else {
			mode = aes.CBC
		}

		op = strings.ToUpper(*opFlag)
		if op != "ENCRYPT" && op != "DECRYPT" {
			fmt.Println("Error: -op must be 'encrypt' or 'decrypt'")
			return
		}

		if op == "ENCRYPT" {
			op = "C"
		} else {
			op = "D"
		}

		if *inFlag == "" || *outFlag == "" {
			fmt.Println("Error: -in and -out paths are required.")
			return
		}
		pathIn = *inFlag
		pathOut = *outFlag

		key, err = parseDecimalInput(*keyFlag)
		if err != nil {
			fmt.Printf("Error parsing key flag: %v\n", err)
			return
		}

		if mode == aes.CBC {
			iv, err = parseDecimalInput(*ivFlag)
			if err != nil {
				fmt.Printf("Error parsing IV flag: %v\n", err)
				return
			}
		}
	}

	data, err := os.ReadFile(pathIn)
	if err != nil {
		fmt.Printf("Erro ao ler arquivo: %v\n", err)
		return
	}

	c, err := aes.NewCipher(key, mode, iv)
	if err != nil {
		fmt.Printf("Erro ao inicializar cifra: %v\n", err)
		return
	}

	var result []byte
	switch op {
	case "C":
		result = c.Encrypt(data)
		fmt.Println("Sucesso: Arquivo cifrado.")
		if *printFlag {
			hexStrs := aes.ResultAsHexStr(result)
			for i, hs := range hexStrs {
				fmt.Printf("Block(%d): %s", i, hs)
			}
		}
	case "D":
		result, err = c.Decrypt(data)
		if err != nil {
			fmt.Printf("Erro ao decifrar: %v\n", err)
			return
		}
		fmt.Println("Sucesso: Arquivo decifrado.")
	}

	err = os.WriteFile(pathOut, result, 0644)
	if err != nil {
		fmt.Printf("Erro ao salvar arquivo: %v\n", err)
		return
	}
	fmt.Printf("Arquivo salvo em: %s\n", pathOut)
}

// Relocated interactive logic to keep main clean
func runInteractive(mode *aes.BlockType, op *string, pathIn *string, pathOut *string, key *[16]byte, iv *[16]byte) {
	reader := bufio.NewReader(os.Stdin)
	var err error

	fmt.Println("--- AES-128 File Processor (Interactive Mode) ---")

	fmt.Print("Escolha o modo de operação ([1] ECB ou [2] CBC): ")
	modeInput, _ := reader.ReadString('\n')
	modeInput = strings.TrimSpace(modeInput)

	switch modeInput {
	case "1":
		*mode = aes.ECB
	case "2":
		*mode = aes.CBC
	default:
		fmt.Println("Modo inválido.")
		os.Exit(1)
	}

	fmt.Print("Escolha a ação ([C]ifrar ou [D]ecifrar): ")
	opInput, _ := reader.ReadString('\n')
	*op = strings.ToUpper(strings.TrimSpace(opInput))
	if *op != "C" && *op != "D" {
		fmt.Println("Operação inválida.")
		os.Exit(1)
	}

	fmt.Print("Caminho do arquivo de entrada: ")
	in, _ := reader.ReadString('\n')
	*pathIn = strings.TrimSpace(in)

	fmt.Print("Nome do arquivo de saída: ")
	out, _ := reader.ReadString('\n')
	*pathOut = strings.TrimSpace(out)

	fmt.Print("Informe a chave (16 números decimais separados por vírgula):\n> ")
	keyInput, _ := reader.ReadString('\n')
	*key, err = parseDecimalInput(keyInput)
	if err != nil {
		fmt.Printf("Erro na chave: %v\n", err)
		os.Exit(1)
	}

	if *mode == aes.CBC {
		fmt.Print("Informe o IV (16 números decimais separados por vírgula):\n> ")
		ivInput, _ := reader.ReadString('\n')
		*iv, err = parseDecimalInput(ivInput)
		if err != nil {
			fmt.Printf("Erro no IV: %v\n", err)
			os.Exit(1)
		}
	}
}

func parseDecimalInput(input string) ([16]byte, error) {
	var result [16]byte
	input = strings.TrimSpace(input)
	if input == "" {
		return result, fmt.Errorf("entrada vazia")
	}
	parts := strings.Split(input, ",")

	if len(parts) != 16 {
		return result, fmt.Errorf("deve conter exatamente 16 valores (recebido: %d)", len(parts))
	}

	for i, part := range parts {
		val, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil || val < 0 || val > 255 {
			return result, fmt.Errorf("valor inválido na posição %d: %s", i, part)
		}
		result[i] = byte(val)
	}

	return result, nil
}
