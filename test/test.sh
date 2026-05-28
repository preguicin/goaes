#!/bin/sh

# 1. Define variables
DEC_KEY="65,69,73,77,66,70,74,78,67,71,75,79,68,72,76,80"
DEC_IV="0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0"

HEX_KEY=$(echo $DEC_KEY | tr ',' '\n' | xargs printf "%02x")
HEX_IV=$(echo $DEC_IV | tr ',' '\n' | xargs printf "%02x")

echo "Using HEX_KEY: $HEX_KEY"

if [ ! -f "input.txt" ]; then
    echo "Creating dummy input.txt for testing..."
    echo "Hello AES-128-ECB Cross-Testing Framework!" > input.txt
fi

echo "----------------------------------------"
echo "TEST 1: Go Encrypt -> OpenSSL Decrypt"
echo "----------------------------------------"

go run ../main.go -mode cbc -op encrypt -in input.txt -out go_encrypted.bin -key "$DEC_KEY" -iv "$DEC_IV"
openssl aes-128-cbc -d -in go_encrypted.bin -out openssl_decrypted.txt -K "$HEX_KEY" -iv "$HEX_IV"

cmp -s input.txt openssl_decrypted.txt && echo "✓ TEST 1 PASSED: OpenSSL successfully decrypted Go's ciphertext!" || echo "✗ TEST 1 FAILED: Decrypted file does not match original."


echo -e "\n----------------------------------------"
echo "TEST 2: OpenSSL Encrypt -> Go Decrypt"
echo "----------------------------------------"

openssl aes-128-cbc -e -in input.txt -out openssl_encrypted.bin -K "$HEX_KEY" -iv "$HEX_IV"
go run ../main.go -mode cbc -op decrypt -in openssl_encrypted.bin -out go_decrypted.txt -key "$DEC_KEY" -iv "$DEC_IV"

cmp -s input.txt go_decrypted.txt && echo "✓ TEST 2 PASSED: Go successfully decrypted OpenSSL's ciphertext!" || echo "✗ TEST 2 FAILED: Decrypted file does not match original."


echo -e "\n----------------------------------------"
echo "TEST 3: Direct Ciphertext Binary Compare"
echo "----------------------------------------"
cmp -s go_encrypted.bin openssl_encrypted.bin && echo "✓ TEST 3 PASSED: Ciphertexts are a 100% binary match!" || echo "✗ TEST 3 FAILED: Ciphertexts differ (Check padding implementation)."
