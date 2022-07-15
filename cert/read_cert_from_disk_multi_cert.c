#include <stdio.h>
#include <openssl/x509v3.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

/* 读取含有多个cert的证书, 存入othercerts*/ 
/*
 * cat root.pem intermediate.pem leaf.pem >CA.pem
 *
 * reference crypto/x509/by_file.c
 *
 * gcc read_cert_from_disk_multi_cert.c -o read_cert_from_disk_multi_cert -lcrypto 
 *
 */
int main(int argc, char **argv)
{

		char *file = "CA.pem";
		STACK_OF(X509_INFO) *inf;
		STACK_OF(X509)* chain;
		X509_INFO *itmp;
		BIO *in;
		int i, count = 0;
		
		in = BIO_new_file(file, "r");

		inf = PEM_X509_INFO_read_bio(in, NULL, NULL, "");
		BIO_free(in);

		for (i = 0; i <sk_X509_INFO_num(inf); i++) {
			itmp = sk_X509_INFO_value(inf, i);
				if(itmp->x509)
				{
						sk_X509_push(chain, itmp->x509);
						count++;
				}

		}


		sk_X509_INFO_pop_free(inf, X509_INFO_free);


		return count;
}
