#include<stdio.h>
#include<openssl/pem.h>
#include<openssl/x509v3.h>

#define KEY_BITS 512

/* 生成EVP_KEY，然后分别存储pub和pri keys in PEM格式 到disk*/

static void callback(int p, int n, void *arg)
{
		char c='B';

		if (p == 0) c='.';
		if (p == 1) c='+';
		if (p == 2) c='*';
		if (p == 3) c='\n';
		fputc(c, stderr);
}

int main(int argc, char **argv)
{
		EVP_PKEY *pkey = NULL;
		RSA *rsa;
		FILE * fp;
		char * pub_name = "pub.pem";
		char * pri_name = "pri.pem";
		char * pri_hex = "pri_hex.pem";

		pkey = EVP_PKEY_new();
		if(pkey == NULL)
		{
				abort();
				return 1;
		}
		rsa = RSA_generate_key(KEY_BITS, RSA_F4, callback, NULL); 
		if(!EVP_PKEY_assign_RSA(pkey, rsa))
		{
				abort();
				return 1;
		}
		rsa = NULL;

		/* write private key in pem format to disk*/
		PEM_write_PrivateKey(stdout, pkey, NULL, NULL, 0, NULL, NULL);
		fp = fopen(pri_name, "wb");
		PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL);
		fclose(fp);

		/* write public key in pem format to disk*/
		PEM_write_PUBKEY(stdout, pkey);
		fp = fopen(pub_name, "wb");
		PEM_write_PUBKEY(fp, pkey);
		fclose(fp);


		EVP_PKEY_free(pkey);

		return 0;
}
