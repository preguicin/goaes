package main

import (
	"fmt"
	aes "goaes/aes"
)

func main() {

	key := [16]byte{'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P'}
	data := []byte{'D', 'E', 'S', 'E', 'N', 'V', 'O', 'L', 'V', 'I', 'M', 'E', 'N', 'T', 'O'}

	c, err := aes.NewCipher(key, aes.ECB, [16]byte{})

	if err != nil {
		fmt.Printf("Err: %s\n", err.Error())
	}
	c.Encrypt(data)
}
