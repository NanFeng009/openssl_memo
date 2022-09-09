#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/err.h>

/*
 * TDX
 * xxd -ps -s 0x302 -l0x180 -i quote.dat
 * xxd -ps -s 0x482 -l0x40 -i quote.dat
 * SGX
 * sig: xxd -ps -s 0x3b4 -l0x40 -i quote.dat
 * msg: xxd -ps -s 0x234 -l0x180 -i quote.dat
 *
 */
int main()
{
		EVP_MD_CTX *ctx = NULL;
		EC_GROUP *group =NULL;
		EC_POINT *point = NULL;
		BIGNUM *bnX = NULL ;
		BIGNUM *bnY = NULL;
		BIGNUM *bnR = NULL;
		BIGNUM *bnS = NULL;
		EC_KEY *key = NULL;
		EVP_PKEY *evpKey = NULL;
		ECDSA_SIG * ecdsaSig = NULL;
		int res = 0;
		unsigned char *derSig = NULL;
		int derlen = -1;
		int expectedSize = -1;

		// from pck cert
		uint8_t rawKey[] = {
#include "key.dat"
		};	

		uint8_t sig[] = {
#include "sig.dat"
		};

		uint8_t msg[] = {
#include "msg.dat"
		};

		bnX = BN_new();
		bnY = BN_new();
		BN_bin2bn(rawKey, 32, bnX);
		BN_bin2bn(rawKey + 32, 32, bnY);

		group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
		point = EC_POINT_new(group);

		if(1 != EC_POINT_set_affine_coordinates_GFp(group, point, bnX, bnY, NULL))
		{
				long e = ERR_get_error();
				printf("Error set coordinate %ld\n", e);
				printf("\t%s\n", ERR_reason_error_string(e));
				return -__LINE__;
		}

		key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
		if(1 != EC_KEY_set_public_key(key, point))
		{
				long e = ERR_get_error();
				printf("Error set pulbic key %ld\n", e);
				printf("\t%s\n", ERR_reason_error_string(e));
				return -__LINE__;
		}

		//convert EC_KEY to EVP_PKEY
		evpKey = EVP_PKEY_new();
		if(evpKey == NULL)
		{
				printf("error get EVP key\n");
				return -__LINE__;
		}

		res = EVP_PKEY_set1_EC_KEY(evpKey, key);
		if(res == 0)
		{
				printf("Error convert key\n");
				return -__LINE__;
		}

		// raw ecdsa signature to DER
		bnR = BN_new();
		bnS = BN_new();
		BN_bin2bn(sig, 32, bnR);
		BN_bin2bn(sig + 32, 32, bnS);
		ecdsaSig = ECDSA_SIG_new();
		res = ECDSA_SIG_set0(ecdsaSig, bnR, bnS);
		if(res != 1)
		{
				printf("Error setting signature\n");
				return -__LINE__;
		}
		expectedSize = i2d_ECDSA_SIG(ecdsaSig, NULL);
		if(expectedSize < 0)
		{
				printf("Error i2d get size %ld\n", ERR_get_error());
				return -__LINE__;
		}
		derlen  = i2d_ECDSA_SIG(ecdsaSig, &derSig);
		if(derlen != expectedSize)
		{
				printf("Error i2d convert %ld\n", ERR_get_error());
				return -__LINE__;
		}


		// clean the error queue
		ERR_clear_error();

		ctx = EVP_MD_CTX_new();
		res = EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, evpKey);
		if(res != 1)
		{
				printf("Error setting context\n");
				return -__LINE__;
		}
		res = EVP_DigestVerifyUpdate(ctx, msg, sizeof(msg));
		if(res != 1)
		{
				printf("Error updateing context\n");
				return -__LINE__;
		}
		res = EVP_DigestVerifyFinal(ctx, derSig, expectedSize);
		if (res > 0) {
				printf( "Verified OK\n");
		} else if (res == 0) {
				long e = ERR_get_error();
				printf( "Verification failure %ld\n", e);
				printf("\t%s\n", ERR_reason_error_string(e));
				return -__LINE__;
		} else {
				long e = ERR_get_error();
				printf("Error verifying data %ld\n", e);
				printf("\t%s\n", ERR_reason_error_string(e));
				return -__LINE__;
		}
		// clean up 
		OPENSSL_free(derSig);
		BN_free(bnX);
		BN_free(bnY);
		EC_KEY_free(key);
		// will be free in ECDSA_SIG_free
//		BN_free(bnR);
//		BN_free(bnS);
		EVP_MD_CTX_free(ctx);
		EVP_PKEY_free(evpKey);
		EC_POINT_free(point);
		ECDSA_SIG_free(ecdsaSig);
		EC_GROUP_free(group);

		return 0;



}
