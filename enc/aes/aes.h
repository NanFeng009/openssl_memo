#ifndef _AES_H

int encrypt_aes_ecb(unsigned char * plaintext, int plaintext_length,
                unsigned char * key, unsigned char * ciphertext)

int decrypt_aes_ecb(unsigned char * ciphertext, int ciphertext_length,
                unsigned char * key, unsigned char * plaintext)

#endif
