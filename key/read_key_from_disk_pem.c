#include<stdio.h>
#include<openssl/pem.h>

int main()
{
		EVP_PKEY *pkey;
		char *pub_name = "pub.pem";
		char *pri_name = "pri.pem";
		/*read pub key from pem */
		FILE *fp = fopen(pub_name, "r");
		if(!fp)
		{
				fprintf(stderr, "unable to open: %s\n", pri_name);
				return 1;
		}

		fprintf(stdout, "------ The public key --\n");
		pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
		RSA_print_fp(stdout, pkey->pkey.rsa, 0);
		EVP_PKEY_free(pkey);

		/*read pri key from pem */
		fp = fopen(pri_name, "r");
		if(!fp)
		{
				fprintf(stderr, "unable to open: %s\n", pri_name);
				return 1;
		}

		fprintf(stdout, "-------- The private key --\n");
		pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
		RSA_print_fp(stdout, pkey->pkey.rsa, 0);
		EVP_PKEY_free(pkey);

		fclose(fp);
		
		return 0;
}


