package main

import (
	"fmt"
	"goaes/aes"
)

func main() {
	var key [16]byte
	copy(key[:], "ABCDEFGHIJKLMNOP")

	data := []byte("DESENVOLVIMENTO!")

	c, err := aes.NewCipher(key, aes.ECB, [16]byte{})

	if err != nil {
		fmt.Printf("Err: %s\n", err.Error())
	}
	res := c.Encrypt(data)
	res2, err := c.Decrypt(res)
	fmt.Printf("%v\n", string(res2))
}
