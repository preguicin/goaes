package aes_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"os"
	"testing"

	myaes "goaes/aes"
)

func TestPDFEncryptionParity(t *testing.T) {
	// 1. Configurações de teste
	key := []byte("CHAVEMISTERIOSA!") // 16 bytes
	iv := []byte("StandardTestIV12")  // 16 bytes
	inputPath := "./test/file.pdf"

	plaintext, err := os.ReadFile(inputPath)
	if err != nil {
		t.Skipf("Pulando teste: arquivo %s não encontrado", inputPath)
	}

	// --- TESTE COM BIBLIOTECA PADRÃO (GO) ---

	paddedPlaintext := myaes.PadPKCS7(plaintext, 16)

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("Erro ao criar cifra std: %v", err)
	}

	stdCiphertext := make([]byte, len(paddedPlaintext))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(stdCiphertext, paddedPlaintext)

	// --- TESTE COM SUA IMPLEMENTAÇÃO ---
	var myKey [16]byte
	var myIv [16]byte
	copy(myKey[:], key)
	copy(myIv[:], iv)

	myCipher, err := myaes.NewCipher(myKey, myaes.CBC, myIv)
	if err != nil {
		t.Fatalf("Erro ao criar sua cifra: %v", err)
	}

	// Sua implementação parece já lidar com o Padding internamente no Encrypt
	myCiphertext := myCipher.Encrypt(plaintext)

	// --- COMPARAÇÃO ---

	if !bytes.Equal(stdCiphertext, myCiphertext) {
		t.Errorf("Arquivos cifrados não coincidem!")
		t.Errorf("Tamanho Std: %d, Tamanho Own: %d", len(stdCiphertext), len(myCiphertext))
		t.Fatalf("Diferença detectada. Primeiros bytes:\nStd: %x\nOwn: %x",
			stdCiphertext[:32], myCiphertext[:32])
	}

	// --- TESTE DE DESCRIPTOGRAFIA ---

	decrypted, err := myCipher.Decrypt(myCiphertext)
	if err != nil {
		t.Fatalf("Sua descriptografia falhou: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatal("O arquivo descriptografado não é idêntico ao PDF original!")
	}

	t.Logf("Sucesso! Arquivo de %d bytes processado e validado com a biblioteca padrão.", len(plaintext))
}
