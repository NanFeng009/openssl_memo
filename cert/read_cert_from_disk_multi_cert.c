#include <stdio.h>
#include <openssl/x509v3.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

/* 读取含有多个cert的证书, 存入othercerts*/ 
int main(int argc, char **argv)
{
		char *name = "OSCP_KEY.pem";
		BIO *certs = NULL;
		STACK_OF(X509_INFO) *allcerts = NULL;
		STACK_OF(X509)* othercerts = NULL;
		int ret = 0;

		OpenSSL_add_all_algorithms();
		//certs = BIO_new_file(name, "r");
		certs = BIO_new_file(argv[1], "r");
		othercerts = sk_X509_new_null();

		allcerts = PEM_X509_INFO_read_bio(certs, NULL, NULL, NULL);
		for(int i = 0; i < sk_X509_INFO_num(allcerts); i++)
		{
				X509_INFO *xi = sk_X509_INFO_value(allcerts, i);
				if(xi->x509)
				{
						sk_X509_push(othercerts, xi->x509);
						ret++;
						xi->x509 = NULL;
				}
		}

		sk_X509_INFO_pop_free(allcerts, X509_INFO_free);
		BIO_free(certs);


		return 0;
}
