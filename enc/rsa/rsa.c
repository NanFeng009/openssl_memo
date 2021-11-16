/*
 * https://sandilands.info/sgordon/public-key-encryption-and-digital-signatures-using-openssl 
 * #alice generate the private & public key
 * openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_pubexp:3 -pkeyopt rsa_keygen_bits:1024 -out privkey-alice.pem
 * #view the private & public key
 * openssl pkey -in privkey-alice.pem -text
 * #extrace the public key to a file
 * openssl pkey -in privkey-alice.pem -out pubkey-alice.pem -pubout
 *
 * #alice generate and sign message file
 * printf "This is alice example message" >>message-alice.txt
 * #calculate the hash and then sign it(1. get hash(openssl dgst -sha1 message-ID.txt), 2. encrypt)
 * openssl dgst -sha1 -sign privkey-alice.pem -out sign-alice.bin message-alice.txt
 * #encrypt the message using Bob's public key,
 * #Note that direct RSA encryption should only be used on small files, with length less than the length of the key
 * openssl pkeyutl -encrypt -in message-alice.txt -pubin pubkey-bob.pem -out ciphertext-alice.bin
 *
 *
 * #Bob generate the private and public key
 * openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_pubexp:3 -pkeyopt rsa_keygen_bits:1024 -out privkey-bob.pem
 * #view the private and public key
 * openssl pkey -in privkey-bob.pem -text
 * #output the public key to a file
 * openssl pkey -in privkey-bob.pem -out pubkey-bob.pem -pubout
 *
 *
 * #Bob decrypt message file and verify
 * openssl pkeyutl -decrypt -in ciphertext-alice.bin -inkey privkey-bob.pem -out received-alice.txt
 * openssl dgst -sha1 -verify pubkey-alice.pem -signature sign-alice.bin received-alice.txt
 */

#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
int	main()
{
	RSA				*r;
	int				bits=1024,ret,len,flen,i;
	unsigned long	e=RSA_3;
	BIGNUM			*bne;
	unsigned char	*key,*p;
	BIO				*b;
	unsigned char	from[500],to[500],out[500];
	const int padding = RSA_NO_PADDING;

	bne=BN_new();
	ret=BN_set_word(bne,e);
	r=RSA_new();
	ret=RSA_generate_key_ex(r,bits,bne,NULL);
	if(ret!=1)
	{
		printf("RSA_generate_key_ex err!\n");
		return -1;
	}
	/* 私钥i2d */

	b=BIO_new(BIO_s_mem());
	ret=i2d_RSAPrivateKey_bio(b,r);
	key=malloc(1024);
	len=BIO_read(b,key,1024);
	BIO_free(b);
	/*
	 * save the key to file
	 */
	b=BIO_new_file("rsa.key","w");     
	ret=i2d_RSAPrivateKey_bio(b,r);
	BIO_free(b);

	/*
	 * get RSA modulus size, here is 128
	 */
	flen=RSA_size(r);

	/*
	 * prepare the plain text
	 */
	for(i=0;i<flen;i++)
		memset(&from[i],i,1);

	len=RSA_private_encrypt(flen,from,to,r,padding); //same with flen = 128
	if(len<=0)
	{
		printf("RSA_private_encrypt err!\n");
		return -1;
	}
	len=RSA_public_decrypt(len,to,out,r,padding); //same with flen = 128
	if(len<=0)
	{
		printf("RSA_public_decrypt err!\n");
		return -1;
	}
	if(memcmp(from,out,flen))
	{
		printf("err!\n");
		return -1;
	}
	printf("test ok!\n");
	RSA_free(r);
	return 0;
}

