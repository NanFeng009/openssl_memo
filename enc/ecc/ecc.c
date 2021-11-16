/*
 * https://jameshfisher.com/2017/04/14/openssl-ecc/
 * However, there are no tools for encrypting and decrypting! ECC doesn’t define these directly. 
 * Instead, ECC users use Diffie-Hellman (DH) key exchange to compute a shared secret, then communicate 
 * using that shared secret. This combination of ECC and DH is called ECDH.
 *
 *# see a list of supported curve names and descriptions
 * openssl ecparam -list_curves
 *# Alice generates her private key
 * openssl ecparam -name secp256k1 -genkey -noout -out alice_priv_key.pem
 * #view the private and public key
 * openssl pkey -in alice_priv_key.pem -text
 * # Alice extracts her public key from her private key
 * openssl ec -in alice_priv_key.pem -pubout -out alice_pub_key.pem
 * #view the public key
 * openssl pkey -in alice_pub_key.pem -pubin
 * 
 * # Alice & Bob derive the shared secret
 * openssl pkeyutl -derive -inkey alice_priv_key.pem -peerkey bob_pub_key.pem -out alice_shared_secret.bin
 * openssl pkeyutl -derive -inkey bob_priv_key.pem -peerkey alice_pub_key.pem -out bob_shared_secret.bin
 * 
 * # Alice encrypt file and Bob decrypt the file
 * echo 'I love you Bob' > plain.txt
 * openssl enc -aes256 -base64 -k $(base64 alice_shared_secret.bin) -e -in plain.txt -out cipher.txt
 * openssl enc -aes256 -base64 -k $(base64 bob_shared_secret.bin) -d -in cipher.txt -out plain_again.txt
 *
 */
// to use 192 bits curve compile with -DUSE_192
// or -DUSE_256 for 256 bits curve
// to use predefined points use -DUSE_PREDEFINED_POINTS or draft curve params will be used
// to create new private and public key use -DGENERATE_KEY otherwise embedded keys will be used
// link with -lssl -lcrypto
// -- ex.  gcc ecc_sample.c -g -o ecc_sample -lssl -lcrypto -DUSE_256 -DUSE_PREDEFINED_POINTS -DGENERATE_KEY

#include <string.h>
#include <openssl/ec.h>      // for EC_GROUP_new_by_curve_name, EC_GROUP_free, EC_KEY_new, EC_KEY_set_group, EC_KEY_generate_key, EC_KEY_free
#include <openssl/ecdsa.h>   // for ECDSA_do_sign, ECDSA_do_verify
#include <openssl/obj_mac.h> // for NID_secp192k1

#define BN_OUTPUT_SIZE      (8)

static int create_signature(unsigned char* hash)
{
	int function_status = -1;
	EC_KEY *eckey=EC_KEY_new();
	if (NULL == eckey)
	{
		printf("Failed to create new EC Key\n");
		function_status = -1;
	}
	else
	{
		BN_CTX *ctx = NULL;
		BIGNUM *p = NULL, *a = NULL, *b = NULL, *x = NULL, *y = NULL, *z = NULL, *order = NULL;
		EC_GROUP *group = NULL;
		EC_POINT *P = NULL;
		BIGNUM *private_key = NULL, *pub_x = NULL, *pub_y = NULL;
		EC_POINT *public_key = NULL;
		EC_KEY *prv_key = NULL, *pub_key = NULL;

		ctx = BN_CTX_new();
		p = BN_new();
		a = BN_new();
		b = BN_new();
		x = BN_new();
		y = BN_new();
		z = BN_new();
		order = BN_new();
		pub_x = BN_new();
		pub_y = BN_new();

#if USE_PREDEFINED_POINTS
#if USE_192
		BN_hex2bn(&p,                 "fffffffffffffffffffffffffffffffeffffffffffffffff");
		printf("P:\t%s \n", BN_bn2hex(p) );

		BN_hex2bn(&a,                 "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC");
		printf("a:\t%s \n", BN_bn2hex(a) );

		BN_hex2bn(&b,                 "64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1");
		printf("b:\t%s \n", BN_bn2hex(b) );

		BN_hex2bn(&x,                 "188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012");
		printf("x:\t%s \n", BN_bn2hex(x) );

		BN_hex2bn(&y,                 "07192b95ffc8da78631011ed6b24cdd573f977a11e794811");
		printf("y:\t%s \n", BN_bn2hex(y) );

		BN_hex2bn(&order,             "FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831");
		printf("order:\t%s \n", BN_bn2hex(order) );
#elif USE_256
		/* curve points grabbed from Atmel Start example */

		BN_hex2bn(&p,                 "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");
		printf("P:\t%s \n", BN_bn2hex(p) );

		BN_hex2bn(&a,                 "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC");
		printf("a:\t%s \n", BN_bn2hex(a) );

		/* b point is not available in Atmel Start project, this point is grabbed from somewhere else */
		BN_hex2bn(&b,                 "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B");
		printf("b:\t%s \n", BN_bn2hex(b) );

		BN_hex2bn(&x,                 "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296");
		printf("x:\t%s \n", BN_bn2hex(x) );

		BN_hex2bn(&y,                 "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");
		printf("y:\t%s \n", BN_bn2hex(y) );

		BN_hex2bn(&order,             "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
		printf("order:\t%s \n", BN_bn2hex(order) );
#else
		fprintf(stderr, "You must define either USE_192 or USE_256\n");
		goto free;
#endif //end USE_192
		group = EC_GROUP_new_curve_GFp(p, a, b, ctx);


		P = EC_POINT_new(group);
		EC_POINT_set_to_infinity(group, P);
		if(EC_POINT_is_at_infinity(group, P))
			printf("P is at infinity\n");

		EC_POINT_set_compressed_coordinates_GFp(group, P, x, 1, ctx);

		if(EC_POINT_is_on_curve(group, P, ctx))
			printf("P is on the curve\n");

		EC_GROUP_set_generator(group, P, order, BN_value_one());
		EC_POINT_set_affine_coordinates_GFp(group, P, x, y, ctx);
#else //non define USE_PREDEFINED_POINTS

#if USE_192
		group= EC_GROUP_new_by_curve_name(NID_secp192k1);
#elif USE_256
		group= EC_GROUP_new_by_curve_name(NID_secp256k1);
#else 
		fprintf(stderr, "You must define either USE_192 or USE_256\n");
		goto free;
#endif // end USE_192


#endif
		/* Checks whether the parameter in the EC_GROUP define a valid ec group */
		if(!EC_GROUP_check(group,ctx)) {
			fprintf(stdout, "EC_GROUP_check() failed\n");
			goto free;
		}
		else {
			fprintf(stdout, "Valid EC group\n");
		}

		if (NULL == group)
		{
			printf("Failed to create new EC Group\n");
			function_status = -1;
			goto free;
		}
		else
		{

			int set_group_status = EC_KEY_set_group(eckey,group);
			const int set_group_success = 1;

			if (set_group_success != set_group_status)
			{
				printf("Failed to set group for EC Key\n");
				function_status = -1;
				goto free;
			}
			else
			{

#ifdef GENERATE_KEY
				const int gen_success = 1;
				int gen_status = EC_KEY_generate_key(eckey);
				if (gen_success != gen_status)
				{
					printf("Failed to generate EC Key\n");
					function_status = -1;
				}
				else
				{
					/* Verifies that a private and/or public key is valid */
					if (!EC_KEY_check_key(eckey)) {
						fprintf(stdout, "EC_KEY_check_key() failed\n");
					}
					else {
						fprintf(stdout, "Generated Keys:\n\n");

						private_key = (BIGNUM *)EC_KEY_get0_private_key(eckey);
						if(private_key)
							fprintf(stdout, "private key = %s\n",BN_bn2hex(private_key));

						public_key = (EC_POINT *)EC_KEY_get0_public_key(eckey);
						if(public_key) {
							if(EC_POINT_get_affine_coordinates_GFp(group,public_key,pub_x,pub_y,ctx) == 1)
								if(pub_x && pub_y)
									fprintf(stdout, "public key = ( %s , %s )\n",
											BN_bn2hex(pub_x),BN_bn2hex(pub_y));
								else
									fprintf(stdout, "EC_POINT_get_affine_coordinates_GFp Failed!\n");
						}
						private_key = NULL;
					}
				}

#else  // non define GENERATE_KEY, use hardcode key

				private_key = BN_new();

#if USE_256
				/* private and public keys from Atmel Start project */
				BN_hex2bn(&private_key, "9043c2ae427713e868d912862c7bbf58611507f730f0360b2d95c9c42da00390");
				BN_hex2bn(&pub_x,       "23551BC3DB0A2418B010F313959DAB96C0AE9AA43DC742A9B6C8D773E029942A");
				BN_hex2bn(&pub_y,       "2C712546615518F95B3CE1B1D171623FE689084ACE032852F2E14EA5C43784F5");
#elif USE_192
				BN_hex2bn(&private_key, "1A8D598FC15BF0FD89030B5CB1111AEB92AE8BAF5EA475FB");
				BN_hex2bn(&pub_x,       "62B12D60690CDCF330BABAB6E69763B471F994DD702D16A5");
				BN_hex2bn(&pub_y,       "63BF5EC08069705FFFF65E5CA5C0D69716DFCB3474373902");
#endif // USE_256
				EC_KEY_set_private_key(eckey, private_key);

				EC_KEY_set_public_key_affine_coordinates(eckey, pub_x, pub_y);

				fprintf(stdout, "Embedded Keys:\n\n");

				if(private_key)
					fprintf(stdout, "private key = %s\n",BN_bn2hex(private_key));

				if(pub_x && pub_y)
					fprintf(stdout, "public key = ( %s , %s )\n",
							BN_bn2hex(pub_x),BN_bn2hex(pub_y));

				/* Verifies that a private and/or public key is valid */
				if (!EC_KEY_check_key(eckey)) {
					fprintf(stdout, "EC_KEY_check_key() failed\n");
					goto free;
				}
				else {
					fprintf(stdout, "Valid EC_KEY.\n");
				}
#endif //GENERATE_KEY
			}
		}

		ECDSA_SIG *signature = ECDSA_do_sign(hash, strlen(hash), eckey);
		if (NULL == signature)
		{
			printf("Failed to generate EC Signature\n");
			function_status = -1;
		}
		else
		{
			/* TO USE PRECALCULATED R AND S VALUES OPEN TWO LINES BELOW AND PUT THE VALUES INTO THEM */
			//BN_hex2bn(&signature->r, "09260C8CFD9017732D7B2196F223CAC93CF4B9B52EEE5614E4868A9E5E6F0DDE");
			//BN_hex2bn(&signature->s, "275BED75C1FC4F260E269350344034D0E8020475F01640DDA171003F14F964E3");
			printf("Signature R: %s\n", BN_bn2hex(ECDSA_SIG_get0_r(signature)));
			printf("Signature S: %s\n", BN_bn2hex(ECDSA_SIG_get0_s(signature)));

			int verify_status = ECDSA_do_verify(hash, strlen(hash), signature, eckey);
			const int verify_success = 1;
			if (verify_success != verify_status)
			{
				printf("Failed to verify EC Signature\n");
				function_status = -1;
			}
			else
			{
				printf("Verifed EC Signature\n");
				function_status = 1;
			}
		}

free:
		EC_GROUP_free(group);
		EC_KEY_free(eckey);
		BN_CTX_free(ctx);
		BN_free(p);
		BN_free(a);
		BN_free(b);
		BN_free(x);
		BN_free(y);
		BN_free(z);
		BN_free(order);
		BN_free(pub_x);
		BN_free(pub_y);
		BN_free(private_key);
		EC_POINT_free(P);
	}
	return function_status;
}

int main( int argc , char * argv[] )
{
	/*
	 * this is the hash of the message "abc"
	 * printf "abc"|sha256sum
	 */
	unsigned char hash[] = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";  
	int status = create_signature(hash);
	return(0) ;
}
