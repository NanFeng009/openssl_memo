#include <openssl/asn1.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/safestack.h>
#include <stdio.h>
#include <string.h>

/*
 * gcc dump_cert.c -lssl -lcrypto -ldl -L/usr/local/lib
 */
/*
 * https://github.com/libtor/openssl/blob/master/demos/x509/mkcert.c
 */

/* 从disk上面读取16进制格式的cert*/

int main()
{
		const unsigned char  cert_data[] = {
#include "base64_2_hex.txt"
		};

		int cert_data_size = sizeof( cert_data);

		char * file_name = "raw_format.pem";
		X509 * px = NULL;


		const unsigned char * my_cert = cert_data;
		px = d2i_X509(NULL, &my_cert, cert_data_size);
		if(px == NULL)
				printf("error to covert to X509\n");
		else
				printf("successfully to cover to x509\n");

		FILE * f  = fopen(file_name, "wb");
		if(f == NULL)
				printf("open file failed\n");
		PEM_write_X509(f, px);

		X509_free(px);

		fclose(f);


		return 0;

}

