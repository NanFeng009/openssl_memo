#include <openssl/dh.h>
#include <memory.h>

/*
 * gcc -lcrypto dh_low.c
 */

/*
 * openssl genpkey -genparam -algorithm DH -out dhp.pem  #Generate the Diffie-Hellman global public parameters
 * openssl pkeyparam -in dhp.pem -text   				 #check parameter
 * openssl genpkey -paramfile dhp.pem -out dhkey1.pem    #generate private and public key
 * openssl pkey -in dhkey2.pem -text -noout              #check the key file
 * openssl pkey -in dhkey1.pem -pubout -out dhpub1.pem   #extrace pub key
 *
 * -- after exchange, get the shared secret --
 * openssl pkeyutl -derive -inkey dhkey1.pem -peerkey dhpub2.pem -out secret1.bin
 */

int	main()
{
	DH		*d1,*d2;
	BIO		*b;
	int		ret,size,i,len1,len2;
	char	sharekey1[128],sharekey2[128];

	/* 构造DH数据结构 */
	d1=DH_new();
	d2=DH_new();
	/* 生成d1的密钥参数，该密钥参数是可以公开的 */
	ret=DH_generate_parameters_ex(d1,64,DH_GENERATOR_2,NULL);
	if(ret!=1)
	{
		printf("DH_generate_parameters_ex err!\n");
		return -1;
	}
	/* 检查密钥参数 */
	ret=DH_check(d1,&i);
	if(ret!=1)
	{
		printf("DH_check err!\n");
		if(i&DH_CHECK_P_NOT_PRIME)
			printf("p value is not prime\n");
		if(i&DH_CHECK_P_NOT_SAFE_PRIME)
			printf("p value is not a safe prime\n");
		if (i&DH_UNABLE_TO_CHECK_GENERATOR)
			printf("unable to check the generator value\n");
		if (i&DH_NOT_SUITABLE_GENERATOR)
			printf("the g value is not a generator\n");
	}
	printf("DH parameters appear to be ok.\n");
	/* 密钥大小 */
	size=DH_size(d1);
	printf("DH key1 size : %d\n",size);
	/* 生成公私钥 */
	ret=DH_generate_key(d1);
	if(ret!=1)
	{
		printf("DH_generate_key err!\n");
		return -1;
	}
	/* p和g为公开的密钥参数，因此可以拷贝 */
	const BIGNUM *p, *q, *g;
#if OPENSSL_VERSION_NUMBER < 0x1010000L
	const BIGNUM *pub_key;
	 opaque the date struct in new version of openssl
	 d2->p=BN_dup(d1->p);
	 d2->g=BN_dup(d1->g);
#else
	DH_get0_pqg(d1, &p, NULL, &g);
	DH_set0_pqg(d2, BN_dup(p), NULL, BN_dup(g));
#endif

	/* 生成公私钥,用于测试生成共享密钥 */
	ret=DH_generate_key(d2);
	if(ret!=1)
	{
		printf("DH_generate_key err!\n");
		return -1;
	}
	/* 检查公钥 */
#if OPENSSL_VERSION_NUMBER < 0x1010000L
	ret=DH_check_pub_key(d1,d1->pub_key,&i);
#else
	ret=DH_check_pub_key(d1,DH_get0_pub_key(d1),&i);
#endif
	if(ret!=1)
	{
		if (i&DH_CHECK_PUBKEY_TOO_SMALL)
			printf("pub key too small \n");
		if (i&DH_CHECK_PUBKEY_TOO_LARGE)
			printf("pub key too large \n");
	}
	/* 计算共享密钥 */
#if OPENSSL_VERSION_NUMBER < 0x1010000L
	len1=DH_compute_key(sharekey1,d2->pub_key,d1);
	len2=DH_compute_key(sharekey2,d1->pub_key,d2);
#else
	len1=DH_compute_key(sharekey1,DH_get0_pub_key(d2),d1);
	len2=DH_compute_key(sharekey2,DH_get0_pub_key(d1),d2);
#endif
	if(len1!=len2)
	{
		printf("生成共享密钥失败1\n");
		return -1;
	}
	if(memcmp(sharekey1,sharekey2,len1)!=0)
	{
		printf("生成共享密钥失败2\n");
		return -1;
	}
	printf("生成共享密钥成功\n");
	b=BIO_new(BIO_s_file());
	BIO_set_fp(b,stdout,BIO_NOCLOSE);
	/* 打印密钥 */
	DHparams_print(b,d1);
	BIO_free(b);
	DH_free(d1);
	DH_free(d2);
	return 0;
}

