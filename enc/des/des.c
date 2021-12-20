/*
 * https://sandilands.info/sgordon/demo-of-symmetric-key-encryption-using-openssl
 *#Generate a secret key (as well as an initialisation vector
 *cat /dev/urandom | xxd -l 8 -g 8
 *   0000000: a499056833bb3ac1                   ...h3.:.
 *openssl rand 8 -hex
 *   001e53e887ee55f1
 *#encrypt
 *openssl enc -des-ecb -e -in plaintext.txt -out ciphertext.bin -iv a499056833bb3ac1 -K 001e53e887ee55f1 -nopad
 *#decrypt
 *openssl enc -des-ecb -d -in ciphertext.bin -out received.txt -iv a499056833bb3ac1 -K 001e53e887ee55f1 -nopad
 *
 */
