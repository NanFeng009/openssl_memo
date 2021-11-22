/*
 *# generate a private key with the correct length
 *openssl genrsa -out pri.pem 3072
 *# generate corresponding public key
 *openssl rsa -in pri.pem -pubout -out pub.pem
 *
 *
 *# create a self-signed certificate
 *openssl req -new -x509 -key pri.pem -out cert.pem -days 360
 *
 *
 * gcc -o key key.c -lcrypto
 */

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <stddef.h>

#define RSA_3072_PUBLIC_KEY_SIZE 3072

int main()
{
	EVP_PKEY* pkey = NULL;
	RSA* rsa = NULL;
	BIO* bio = NULL;
	BIGNUM* e = NULL;
	int res;


	e = BN_new();
	if(!e)
		printf("failed to allocates and initializes a BIGNUM structure\n");
	res = BN_set_word(e, (BN_ULONG)RSA_F4);  //RSA_F4 - publicExponent: 65537 (0x10001)
	if(!res)
		printf("BN_set_word failed to set the RSA_F4 to e\n");

	rsa = RSA_new();
	if(!rsa)
		printf("failed to allocate a RSA structure\n");
	res = RSA_generate_key_ex(
			rsa, 
			RSA_3072_PUBLIC_KEY_SIZE, //modulus bit length
			e,
			NULL); //callbak argument - not needed in this case
	if(!res)
		printf("fail to generate RSA key pair\n");

	pkey = EVP_PKEY_new();
	if(!pkey)
		printf("fail to allocate an empty EVP_PKEY structure\n");
	//set RSA key in EVP_PKEY structure
	EVP_PKEY_assign_RSA(pkey, rsa); 

	/*
	 * write out the public&private key in PEM format in char array for exchanging with other
	 */
	uint8_t public_key[3072]; //allocate a big enough memory 
	uint8_t private_key[3072];
	bio = BIO_new(BIO_s_mem());
	PEM_write_bio_PUBKEY(bio, pkey);
	BIO_read(bio, public_key, 3072);
	BIO_free(bio);
	bio = NULL;
	bio = BIO_new(BIO_s_mem());
	PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL);
	BIO_read(bio, private_key, 3072);
	BIO_free(bio);
	bio = NULL;
#ifdef PRINT_KEY
	printf("public key(len %d) is \n%s\n", strlen(public_key), public_key);
	printf("private key(len %d) is \n%s\n", strlen(private_key), private_key);
#endif

	/*
	 * write out the public&private key in disk
	 */
	FILE * fp;
	char * pub_name = "pub.pem";
	char * pri_name = "pri.pem";
	fp = fopen(pri_name, "wb");
	PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL);
	fclose(fp);

	fp = fopen(pub_name, "wb");
	PEM_write_PUBKEY(fp, pkey);
	fclose(fp);

	//free all data structure
	if(e)
		BN_free(e);
	if(pkey)
		EVP_PKEY_free(pkey); // when this is called, rsa is also freed
}


