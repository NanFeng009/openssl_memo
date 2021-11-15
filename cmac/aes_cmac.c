#include <stdio.h>
#include <stddef.h>
#include "openssl/cmac.h"
#include "openssl/err.h"


/*
 * openssl mac -cipher AES-128-CBC -macopt hexkey:c4654ef3f858b84d090e6b23abbf2521  -in msg.bin CMAC
 *
 * gcc -g aes_cmac.c -lcrypto
 */

int main()
{
	void * pState = NULL;

	uint8_t p_src[] = {0x00,0x51,0x45,0x5f,0x49,0x44,0x5f,0x44,0x45,0x52,0x00,0x00,0x00,0x00,0x00,0x80};
	uint8_t p_key[] = {0xc4,0x65,0x4e,0xf3,0xf8,0x58,0xb8,0x4d,0x09,0x0e,0x6b,0x23,0xab,0xbf,0x25,0x21};
	uint8_t p_mac[16];
	int mactlen;

	do {
		pState = CMAC_CTX_new();
		if(pState == NULL)
			break;

		if(!CMAC_Init((CMAC_CTX*)pState, (const void *)p_key, 16, EVP_aes_128_cbc(), NULL))
			break;

		if(!CMAC_Update((CMAC_CTX*)pState, p_src, 16))
			break;

		if(!CMAC_Final((CMAC_CTX*)pState, (unsigned char*)p_mac, &mactlen))
			break;

	}while(0);

	if(pState == NULL){
		CMAC_CTX_free((CMAC_CTX*)pState);

	}
}
