package aes

import (
	"errors"
	"fmt"
)

type BlockType uint8

const (
	CBC BlockType = iota
	ECB
)

type Cipher struct {
	Key       [16]byte
	BlockType BlockType
	IV        [16]byte
}

func NewCipher(key [16]byte, bt BlockType, iv [16]byte) (*Cipher, error) {
	if bt == CBC && len(iv) < 16 {
		return nil, errors.New("IV cant be empty or invalid in CBC mode")
	}

	return &Cipher{
		Key:       key,
		BlockType: bt,
		IV:        iv,
	}, nil
}

func (c *Cipher) Encrypt(src []byte) []byte {
	text := make([]byte, len(src))
	copy(text, src)
	text = PadPKCS7(text, 16)

	blocks := breakIntoBlocks(text)
	keySchedule := c.expandKeys()

	var previousBlock [16]byte = c.IV

	var res = make([]byte, 0)
	for _, block := range blocks {
		if c.BlockType == CBC {
			for i := range block {
				block[i] ^= previousBlock[i]
			}
		}
		aesEncrypt(&block, keySchedule)
		if c.BlockType == CBC {
			previousBlock = block
		}
		res = append(res, block[:]...)
	}

	return res
}

func aesEncrypt(block *[16]byte, keySchedule *[176]byte) {
	addRoundKey(block, keySchedule[0:16])
	for i := 1; i < 10; i++ {
		bIdx := i * 16
		subBytes(block)
		shiftRows(block)

		mixColumns(block)
		addRoundKey(block, keySchedule[bIdx:bIdx+16])
	}
	subBytes(block)
	shiftRows(block)
	addRoundKey(block, keySchedule[160:176])
}

func mixColumns(block *[16]byte) {
	var result [16]byte

	for i := range 16 {
		c := i % 4
		r := i / 4

		var acc byte = 0
		for k := range 4 {
			mVal := multMatrix[r*4+k]
			bVal := block[c*4+k]
			acc ^= galoisMultiplication(bVal, mVal)
		}
		result[c*4+r] = acc
	}
	*block = result
}
func galoisMultiplication(term1 byte, term2 byte) byte {
	if term1 == 0 || term2 == 0 {
		return 0
	}
	if term1 == 1 {
		return term2
	}
	if term2 == 1 {
		return term1
	}

	res1 := tableL[int(term1)]
	res2 := tableL[int(term2)]

	res := int(res1) + int(res2)

	if res > 0xFF {
		res -= 0xFF
	}

	return tableE[res]
}
func shiftRows(block *[16]byte) {
	temp := *block

	for row := range 4 {
		for col := range 4 {
			sourceCol := (col + row) % 4
			sourceIdx := (sourceCol * 4) + row
			destIdx := (col * 4) + row

			block[destIdx] = temp[sourceIdx]
		}
	}
}
func subBytes(block *[16]byte) {
	for i := range block {
		block[i] = sbox[block[i]]
	}
}
func addRoundKey(block *[16]byte, key []byte) {
	for i := range block {
		block[i] ^= key[i]
	}
}

func (c *Cipher) Decrypt(src []byte) ([]byte, error) {
	text := make([]byte, len(src))
	copy(text, src)

	blocks := breakIntoBlocks(text)
	keySchedule := c.expandKeys()

	var res = make([]byte, 0)
	var previousBlock [16]byte = c.IV
	for _, block := range blocks {
		var currentCiphertext [16]byte
		copy(currentCiphertext[:], block[:])

		aesDecrypt(&block, keySchedule)

		if c.BlockType == CBC {
			for i := range block {
				block[i] ^= previousBlock[i]
			}
		}
		res = append(res, block[:]...)

		if c.BlockType == CBC {
			previousBlock = currentCiphertext
		}
	}
	res, err := unpadPKCS7(res)

	return res, err
}

func aesDecrypt(block *[16]byte, keySchedule *[176]byte) {
	addRoundKey(block, keySchedule[160:176])
	invShiftRows(block)
	invSubBytes(block)

	for i := 9; i > 0; i-- {
		bIdx := i * 16
		addRoundKey(block, keySchedule[bIdx:bIdx+16])
		invMixColumns(block)
		invShiftRows(block)
		invSubBytes(block)
	}
	addRoundKey(block, keySchedule[0:16])
}

func invMixColumns(block *[16]byte) {
	var result [16]byte

	for i := range 16 {
		c := i % 4
		r := i / 4

		var acc byte = 0
		for k := range 4 {
			mVal := invMultMatrix[r*4+k]
			bVal := block[c*4+k]
			acc ^= galoisMultiplication(bVal, mVal)
		}
		result[c*4+r] = acc
	}
	*block = result
}
func invSubBytes(block *[16]byte) {
	for i := range block {
		block[i] = rsbox[block[i]]
	}
}
func invShiftRows(block *[16]byte) {
	temp := *block
	for row := range 4 {
		for col := range 4 {
			sourceCol := (col - row + 4) % 4
			sourceIdx := (sourceCol * 4) + row
			destIdx := (col * 4) + row

			block[destIdx] = temp[sourceIdx]
		}
	}
}
func unpadPKCS7(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, fmt.Errorf("data is empty")
	}

	paddingLen := int(data[length-1])

	if paddingLen == 0 || paddingLen > length {
		return nil, fmt.Errorf("invalid padding length")
	}

	for i := range paddingLen {
		if data[length-1-i] != byte(paddingLen) {
			return nil, fmt.Errorf("invalid padding characters")
		}
	}

	return data[:length-paddingLen], nil
}

func PadPKCS7(data []byte, blockSize int) []byte {
	paddingLen := blockSize - (len(data) % blockSize)
	padding := make([]byte, paddingLen)
	for i := range padding {
		padding[i] = byte(paddingLen)
	}
	return append(data, padding...)
}
func (c *Cipher) expandKeys() *[176]byte {
	var keys [176]byte
	copy(keys[:], c.Key[:])

	for i := 1; i < 11; i++ {
		idx := i * 16
		lastword := make([]byte, 4)
		copy(lastword, keys[idx-4:idx])

		//Rotate word
		lastword[0], lastword[1], lastword[2], lastword[3] = lastword[1], lastword[2], lastword[3], lastword[0]

		//Subword
		for j := range lastword {
			lastword[j] = sbox[lastword[j]]
		}

		//XOR  roundkey
		lastword[0] ^= rcon[(idx/16)-1]

		//XOR  with current rounkey against last roundkey first word
		for j := range lastword {
			keys[idx+j] = keys[(idx-16)+j] ^ lastword[j]
		}

		//Other words
		for k := 1; k < 4; k++ {
			for j := range 4 {
				curr := idx + (k * 4) + j
				keys[curr] = keys[curr-16] ^ keys[curr-4]
			}
		}
	}

	return &keys
}

func breakIntoBlocks(data []byte) [][16]byte {
	numBlocks := len(data) / 16
	blocks := make([][16]byte, 0, numBlocks)

	for i := 0; i < len(data); i += 16 {
		var block [16]byte
		copy(block[:], data[i:i+16])
		blocks = append(blocks, block)
	}

	return blocks
}

func ResultAsHexStr(data []byte) []string {
	blocks := breakIntoBlocks(data)
	result := make([]string, 0)

	for _, b := range blocks {
		str := fmt.Sprintf("% x", b)
		result = append(result, str)
	}

	return result
}
