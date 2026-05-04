package aes_test

import (
	"crypto/aes"
	"fmt"
	gaes "goaes/aes"
	"testing"
)

func TestEncryptMatchesStdlib(t *testing.T) {
	key := []byte{'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P'}
	data := []byte{'D', 'E', 'S', 'E', 'N', 'V', 'O', 'L', 'V', 'I', 'M', 'E', 'N', 'T', 'O', '!'}

	// --- your implementation ---
	c := gaes.Cipher{
		Key:       key,
		BlockType: gaes.ECB,
		IV:        make([]byte, 16),
	}
	got := c.Encrypt(data)

	// --- stdlib ---
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("stdlib NewCipher: %v", err)
	}
	// data is exactly 16 bytes, so PKCS7 adds a full padding block (16 x 0x10)
	// we need to encrypt both blocks to match your output length
	padded := make([]byte, 32)
	copy(padded, data)
	for i := 16; i < 32; i++ {
		padded[i] = 0x10
	}
	want := make([]byte, 32)
	block.Encrypt(want[0:16], padded[0:16])
	block.Encrypt(want[16:32], padded[16:32])

	fmt.Printf("got:  % x\n", got)
	fmt.Printf("want: % x\n", want)

	if len(got) != len(want) {
		t.Fatalf("length mismatch: got %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("byte %d differs: got %02x, want %02x", i, got[i], want[i])
		}
	}
}
