DEC_KEY="1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16"
DEC_IV="0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0"

HEX_KEY=$(echo $DEC_KEY | tr ',' '\n' | xargs printf "%02x")
HEX_IV=$(echo $DEC_IV | tr ',' '\n' | xargs printf "%02x")

./goaes -mode cbc -op encrypt -in input.pdf -out go_encrypted.bin -key "$DEC_KEY" -iv "$DEC_IV"

openssl aes-128-cbc -e -in input.pdf -out openssl_encrypted.bin -K "$HEX_KEY" -iv "$HEX_IV"

cmp -s go_encrypted.bin openssl_encrypted.bin && echo "✓ Outputs are identical!" || echo "✗ Outputs differ."
