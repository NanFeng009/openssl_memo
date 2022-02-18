/*
 *
 * gcc -g evp_base64.c -lcrypto -o evp_base64
 *
 *#base64 encoding & decoding
 *openssl enc -base64 -in text.plain -out text.base64
 *openssl enc -base64 -d -in text.base64 -out text.plain
 *
 *
 *
 *printf "Hello world"|openssl base64
 *
 */


#include <sys/types.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <alloca.h>

#define MSG_ERR_STRM stderr

#define B64_ENCODE_BUF_LEN(sn) (1 + ((sn + 2) / 3 * 4)) // +1 for the terminating null that EVP_EncodeBlock adds on
#define B64_DECODE_BUF_LEN(bn) ((bn / 4) * 3) // follow crypto/ct/ct_b64.c

/*--------------------------------------------------------------------------------
 * Lean b64 encoding wrapper using the openssl b64 encoding facility
 */
int base64_encode(const char* str, int slen, char* b64str, int b64slen)
{
	int b64len;
	b64len = B64_ENCODE_BUF_LEN(slen);
	if (b64slen < b64len)
	{
		fprintf(MSG_ERR_STRM, "b64_encode : encoding output buffer is too small.\n");
		return -1;
	}
	memset(b64str, 0, b64slen);
	if( (b64len = EVP_EncodeBlock((unsigned char*)b64str, (unsigned char*)str, slen)) < 0)
	{
		fprintf(MSG_ERR_STRM, "b64_encode : EVP_EncodeBlock failed (%d)\n", b64len);
		return -1;
	}
	return b64len;
}

/*--------------------------------------------------------------------------------
 * Lean b64 decoding wrapper using the openssl b64 decoding facility
 */
int base64_decode(const char* b64str, int b64slen, char* str, int slen)
{
	int len;
	len = B64_DECODE_BUF_LEN(b64slen);
	if (len > slen)
	{
		fprintf(MSG_ERR_STRM, "b64_decode : decoding output buffer too small.\n");
		return -1;
	}
	memset(str, 0, slen);
	if( (len = EVP_DecodeBlock((unsigned char*)str, (unsigned char*)b64str, b64slen)) < 0)
	{
		fprintf(MSG_ERR_STRM, "b64_decode : EVP_DecodeBlock failed (%d)\n", len);
		return -1;
	}
	return len;
}


int main()
{
	const char *plain_msg = "Hello world";
	unsigned int plain_msg_len = strlen(plain_msg);
	printf("--- plain text ---\n");
	printf("plain_msg = %s, len = %ld\n", plain_msg, strlen(plain_msg));

	// --- encode ---
	printf("--- encode ---\n");
	int encoded_msg_len = B64_ENCODE_BUF_LEN(plain_msg_len);
	char * encoded_msg_buff = (char *)alloca(encoded_msg_len);
	int  b64_ret_len = base64_encode(plain_msg, plain_msg_len, encoded_msg_buff, encoded_msg_len);
	printf("\tb64_ret_len = %d\n", b64_ret_len);
	printf("\tencoded_msg_buff = %s\n", encoded_msg_buff);

	// --- decode ---
	printf("--- decode ---\n");
	int to_decode_msg_len = strlen(encoded_msg_buff);
	int decode_msg_len = B64_DECODE_BUF_LEN(to_decode_msg_len ); 
	char * decode_msg_buf = (char *)alloca(decode_msg_len);
	int d64_ret_len = base64_decode(encoded_msg_buff, to_decode_msg_len, decode_msg_buf, decode_msg_len);
	printf("\tdecode_msg_len = %d, d64_ret_len = %d\n", decode_msg_len, d64_ret_len);
	printf("\tdecode_msg_buf = %s\n", decode_msg_buf);
	




}
