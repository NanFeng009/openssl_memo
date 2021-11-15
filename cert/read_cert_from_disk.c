#include <stdio.h>
#include <string.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h> //PEM_read_X509, PEM_write_X509

/* 读取cert，cert的格式是网页传输时候的格式PEM */

int main()
{
		char *pem_name = "wwwintelcom.crt";
		FILE *fp = fopen(pem_name, "r");
		if(!fp)
		{
		      fprintf(stderr, "unable to open: %s\n", pem_name);
		      return EXIT_FAILURE;
		}
		X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
		if(!cert)
		{
		      fprintf(stderr, "unable to parse certificate in: %s\n", pem_name);
		      fclose(fp);
		      return EXIT_FAILURE;
		}
		/******************** parse cert ***********************/
		PEM_write_X509(stdout, cert);
		X509_print_fp(stdout, cert);
		/******************** parse cert ***********************/

		X509_free(cert);
		fclose(fp);
}

