package main

import (
	"bufio"
	"fmt"
	"goaes/aes"
	"os"
	"strconv"
	"strings"
)

func main() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("--- AES-128 File Processor ---")

	fmt.Print("Escolha o modo de operação ([1] ECB ou [2] CBC): ")
	modeInput, _ := reader.ReadString('\n')
	modeInput = strings.TrimSpace(modeInput)

	var mode aes.BlockType
	switch modeInput {
	case "1":
		mode = aes.ECB
	case "2":
		mode = aes.CBC
	default:
		fmt.Println("Modo inválido.")
		return
	}

	fmt.Print("Escolha a ação ([C]ifrar ou [D]ecifrar): ")
	opInput, _ := reader.ReadString('\n')
	op := strings.ToUpper(strings.TrimSpace(opInput))

	fmt.Print("Caminho do arquivo de entrada: ")
	pathIn, _ := reader.ReadString('\n')
	pathIn = strings.TrimSpace(pathIn)

	fmt.Print("Nome do arquivo de saída: ")
	pathOut, _ := reader.ReadString('\n')
	pathOut = strings.TrimSpace(pathOut)

	fmt.Print("Informe a chave (16 números decimais separados por vírgula):\n> ")
	keyInput, _ := reader.ReadString('\n')
	key, err := parseDecimalInput(keyInput)
	if err != nil {
		fmt.Printf("Erro na chave: %v\n", err)
		return
	}

	var iv [16]byte
	if mode == aes.CBC {
		fmt.Print("Informe o IV (16 números decimais separados por vírgula):\n> ")
		ivInput, _ := reader.ReadString('\n')
		iv, err = parseDecimalInput(ivInput)
		if err != nil {
			fmt.Printf("Erro no IV: %v\n", err)
			return
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
	case "D":
		result, err = c.Decrypt(data)
		if err != nil {
			fmt.Printf("Erro ao decifrar: %v\n", err)
			return
		}
		fmt.Println("Sucesso: Arquivo decifrado.")
	default:
		fmt.Println("Operação inválida.")
		return
	}

	err = os.WriteFile(pathOut, result, 0644)
	if err != nil {
		fmt.Printf("Erro ao salvar arquivo: %v\n", err)
		return
	}
	fmt.Printf("Arquivo salvo em: %s\n", pathOut)
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
