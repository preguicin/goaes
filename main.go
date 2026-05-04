package main

import (
	"fmt"
	"goaes/aes"
)

func main() {

	key := []byte{'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P'}
	data := []byte{'D', 'E', 'S', 'E', 'N', 'V', 'O', 'L', 'V', 'I', 'M', 'E', 'N', 'T', 'O', '!'}

	c := aes.Cipher{
		Key:       key,
		BlockType: aes.ECB,
		IV:        make([]byte, 16),
	}

	res := c.Encrypt(data)

	fmt.Printf("% x", res)
}
