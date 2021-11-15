/*
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

char *base64_encode(const char *msg, size_t sz)
{
	BIO *b64, *bmem;
	char *bstr, *dup;
	int len;

	b64= BIO_new(BIO_f_base64());
	bmem= BIO_new(BIO_s_mem());

	/* Single line output, please */
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

	BIO_push(b64, bmem);

	if ( BIO_write(b64, msg, (int) sz) == -1 ) {
		BIO_free(bmem);
		BIO_free(b64);
		return NULL;
	}

	BIO_flush(b64);

	len= BIO_get_mem_data(bmem, &bstr);
	dup= (char *) malloc(len+1);
	if ( dup == NULL ) {
		BIO_free(bmem);
		BIO_free(b64);
		return NULL;
	}

	memcpy(dup, bstr, len);
	dup[len]= 0;

	BIO_free(bmem);
	BIO_free(b64);

	return dup;
}


char *base64_decode(const char *msg, size_t *sz)
{
	BIO *b64, *bmem;
	char *buf;
	size_t len= strlen(msg);

	buf= (char *) malloc(len+1);
	if ( buf == NULL ) return NULL;
	memset(buf, 0, len+1);

	b64= BIO_new(BIO_f_base64());
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

	bmem= BIO_new_mem_buf(msg, (int) len);

	BIO_push(b64, bmem);

	*sz= BIO_read(b64, buf, (int) len);
	if ( *sz == -1 ) {
		free(buf);
		return NULL;
	}

	BIO_free_all(bmem);

	return buf;
}

int main()
{
	const char *msg = "Hello world";
	char * encrypt_msg = base64_encode(msg, strlen(msg));
	printf("encrypt_msg is\n\t %s\n", encrypt_msg);
	size_t sz;
	char * plain_msg = base64_decode(encrypt_msg, &sz);
	printf("plain msg is\n\t %s\n", plain_msg);

	if(encrypt_msg)
		free(encrypt_msg);
	if(plain_msg)
		free(plain_msg);

}
