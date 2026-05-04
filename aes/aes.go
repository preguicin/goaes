package aes

import (
	"fmt"
)

type BlockType uint8

const (
	CBC BlockType = iota
	ECB
)

type Cipher struct {
	Key       []byte
	BlockType BlockType
	IV        []byte
}

func (c *Cipher) Encrypt(data []byte) []byte {
	rData := make([]byte, len(data))
	copy(rData, data)

	keySchedule := c.expandKeys()
	paddedData := padPKCS7(rData, 16)
	blocks := breakIntoBlocks(paddedData)

	var previousBlock []byte = c.IV

	for i := range blocks {
		if c.BlockType == CBC {
			for b := range 16 {
				blocks[i][b] ^= previousBlock[b]
			}
		}

		encryptSingleBlock(blocks[i], keySchedule)

		if c.BlockType == CBC {
			previousBlock = blocks[i]
		}
	}

	result := make([]byte, len(blocks)*16)
	for i, block := range blocks {
		copy(result[i*16:(i+1)*16], block)
	}
	return result
}

func encryptSingleBlock(cblock []byte, keySchedule []byte) {
	// Add initial Round Key (Round 0)
	addRoundKey(cblock, keySchedule[0:16])

	// Rounds 1 to 9
	for i := 1; i < 10; i++ {
		bIdx := i * 16
		subBytes(cblock)
		shiftRows(cblock)
		mixCollumns(cblock) // No mixColumns in the final round
		addRoundKey(cblock, keySchedule[bIdx:bIdx+16])
	}

	subBytes(cblock)
	shiftRows(cblock)
	addRoundKey(cblock, keySchedule[160:176])
}

func mixCollumns(block []byte) {
	bmatrix := make([]byte, 16)

	for i := range bmatrix {
		row := i / 4
		col := i % 4

		var acc byte = 0
		for j := range 4 {
			blockIdx := col*4 + j
			mmIdx := (row * 4) + j

			term1 := block[blockIdx]
			term2 := multMatrix[mmIdx]

			if term1 == 0 || term2 == 0 {
				continue
			}
			if term1 == 1 {
				acc ^= term2
			} else if term2 == 1 {
				acc ^= term1
			} else {
				acc ^= galoisMultiplication(term1, term2)
			}
		}
		bmatrix[i] = acc
	}
	copy(block, bmatrix)
}

func galoisMultiplication(term1 byte, term2 byte) byte {
	res := int(tableL[term1]) + int(tableL[term2])

	if res >= 0xFF {
		res -= 0xFF
	}

	res = int(tableE[res])
	return byte(res)
}

func addRoundKey(block []byte, key []byte) {
	for i := range 16 {
		block[i] ^= key[i]
	}
}

func subBytes(block []byte) {
	for i := range 16 {
		block[i] = sbox[block[i]]
	}
}

func shiftRows(block []byte) {
	temp := make([]byte, 16)
	copy(temp, block)

	for row := range 4 {
		for col := range 4 {
			sourceCol := (col + row) % 4
			sourceIdx := (sourceCol * 4) + row
			destIdx := (col * 4) + row

			block[destIdx] = temp[sourceIdx]
		}
	}
}

func (c *Cipher) expandKeys() []byte {
	keys := make([]byte, 176)
	copy(keys, c.Key[:])

	for i := 16; i < 176; i += 16 {
		lastword := make([]byte, 4)
		copy(lastword, keys[i-4:i])

		//Rotate word
		lastword[0], lastword[1], lastword[2], lastword[3] = lastword[1], lastword[2], lastword[3], lastword[0]

		//Subword
		for j := range lastword {
			lastword[j] = sbox[lastword[j]]
		}

		lastword[0] ^= rcon[(i/16)-1]

		//XOR 5 with rounkey last roundkey first word
		for j := range lastword {
			keys[i+j] = keys[(i-16)+j] ^ lastword[j]
		}

		//XOR Last key words with cur key words
		for k := 1; k < 4; k++ {
			for j := range 4 {
				curr := i + (k * 4) + j
				keys[curr] = keys[curr-16] ^ keys[curr-4]
			}
		}
	}

	return keys
}

func padPKCS7(data []byte, blockSize int) []byte {
	paddingLen := blockSize - (len(data) % blockSize)
	padding := make([]byte, paddingLen)
	for i := range padding {
		padding[i] = byte(paddingLen)
	}
	return append(data, padding...)
}

func unpadPKCS7(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, fmt.Errorf("data is empty")
	}

	paddingLen := int(data[length-1])

	if paddingLen > length || paddingLen == 0 {
		return nil, fmt.Errorf("invalid padding")
	}

	for i := length - paddingLen; i < length; i++ {
		if data[i] != byte(paddingLen) {
			return nil, fmt.Errorf("invalid padding bytes")
		}
	}
	return data[:length-paddingLen], nil
}

func breakIntoBlocks(data []byte) [][]byte {
	var blocks [][]byte = make([][]byte, 0)

	for i := 0; i < len(data); i += 16 {
		block := make([]byte, 16)
		copy(block, data[i:i+16])
		blocks = append(blocks, block)
	}

	return blocks
}
