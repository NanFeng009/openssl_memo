#include <stdio.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define ECDSA_MAX_SIG_SIZE 256

#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#if !defined(SWAP_ENDIAN_DW)
    #define SWAP_ENDIAN_DW(dw)    ((((dw) & 0x000000ff) << 24)              \
    | (((dw) & 0x0000ff00) << 8)                                            \
    | (((dw) & 0x00ff0000) >> 8)                                            \
    | (((dw) & 0xff000000) >> 24))
#endif
#if !defined(SWAP_ENDIAN_32B)
    #define SWAP_ENDIAN_32B(ptr)                                            \
{                                                                           \
    unsigned int temp = 0;                                                  \
    temp = SWAP_ENDIAN_DW(((unsigned int*)(ptr))[0]);                       \
    ((unsigned int*)(ptr))[0] = SWAP_ENDIAN_DW(((unsigned int*)(ptr))[7]);  \
    ((unsigned int*)(ptr))[7] = temp;                                       \
    temp = SWAP_ENDIAN_DW(((unsigned int*)(ptr))[1]);                       \
    ((unsigned int*)(ptr))[1] = SWAP_ENDIAN_DW(((unsigned int*)(ptr))[6]);  \
    ((unsigned int*)(ptr))[6] = temp;                                       \
    temp = SWAP_ENDIAN_DW(((unsigned int*)(ptr))[2]);                       \
    ((unsigned int*)(ptr))[2] = SWAP_ENDIAN_DW(((unsigned int*)(ptr))[5]);  \
    ((unsigned int*)(ptr))[5] = temp;                                       \
    temp = SWAP_ENDIAN_DW(((unsigned int*)(ptr))[3]);                       \
    ((unsigned int*)(ptr))[3] = SWAP_ENDIAN_DW(((unsigned int*)(ptr))[4]);  \
    ((unsigned int*)(ptr))[4] = temp;                                       \
}
#endif

void extractRSFromSignature(const unsigned char *signature, size_t signatureLen) {
    ECDSA_SIG *ecdsaSig = NULL;
    BIGNUM *r = NULL;
    BIGNUM *s = NULL;
    unsigned char *rBuffer = NULL;
    unsigned char *sBuffer = NULL;
    int rBufferLen, sBufferLen;

    // Retrieve the ECDSA_SIG structure from the signature
    const unsigned char *p = signature;
    ecdsaSig = d2i_ECDSA_SIG(NULL, &p, signatureLen);
    if (ecdsaSig == NULL) {
        // Handle error
        return;
    }

    // Extract the "r" and "s" values from the ECDSA_SIG structure
    ECDSA_SIG_get0(ecdsaSig, &r, &s);

    // Convert the "r" value to a little-endian buffer
    rBufferLen = BN_num_bytes(r);
    rBuffer = (unsigned char *)OPENSSL_malloc(rBufferLen);
    if (rBuffer == NULL) {
        // Handle error
        ECDSA_SIG_free(ecdsaSig);
        return;
    }
    BN_bn2lebinpad(r, rBuffer, rBufferLen);

    // Convert the "s" value to a little-endian buffer
    sBufferLen = BN_num_bytes(s);
    sBuffer = (unsigned char *)OPENSSL_malloc(sBufferLen);
    if (sBuffer == NULL) {
        // Handle error
        OPENSSL_free(rBuffer);
        ECDSA_SIG_free(ecdsaSig);
        return;
    }
    BN_bn2lebinpad(s, sBuffer, sBufferLen);

    // Now you can use the "rBuffer" and "sBuffer" containing the little-endian "r" and "s" values
        // Print the "r" and "s" values
    printf("r: ");
    for (int i = 0; i < rBufferLen; i++) {
        printf("0x%02x,", rBuffer[i]);
    }
    printf("\n");
    printf("s: ");
    for (int i = 0; i < sBufferLen; i++) {
        printf("0x%02x,", sBuffer[i]);
    }
    printf("\n");
    printf("---------------------------------------\n");
    SWAP_ENDIAN_32B(rBuffer);
    printf("revert r: ");
    for (int i = 0; i < rBufferLen; i++) {
        printf("0x%02x,", rBuffer[i]);
    }
    SWAP_ENDIAN_32B(sBuffer);
    printf("\nrevert s: ");
    for (int i = 0; i < rBufferLen; i++) {
        printf("0x%02x,", sBuffer[i]);
    }
    printf("\n");

    // Cleanup
    OPENSSL_free(rBuffer);
    OPENSSL_free(sBuffer);
    ECDSA_SIG_free(ecdsaSig);
}

// Function to generate an ECDSA signature
int generate_ecdsa_signature(const char *private_key, const char *msg, size_t msg_len, unsigned char *signature, size_t *signature_len)
{
    EC_KEY *ec_key = NULL;
    EVP_PKEY *pkey = NULL;
    int ret = 0;

    // Convert private key from hexadecimal to binary
    EC_GROUP *ec_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (ec_group == NULL)
    {
        printf("Error creating EC group.\n");
        return 0;
    }

    BIGNUM *priv_key_bn = BN_new();
    // convert a positive interget in little-endian into a BIGNUM
    // priv_key_bn = BN_lebin2bn(private_key, 32, 0);
    if (BN_bin2bn(private_key, 32, priv_key_bn) == 0)
    {
        printf("Error converting private key from hexadecimal.\n");
        BN_free(priv_key_bn);
        EC_GROUP_free(ec_group);
        return 0;
    }

    ec_key = EC_KEY_new();
    if (ec_key == NULL)
    {
        printf("Error creating EC key.\n");
        BN_free(priv_key_bn);
        EC_GROUP_free(ec_group);
        return 0;
    }

    if (EC_KEY_set_group(ec_key, ec_group) != 1)
    {
        printf("Error setting EC key group.\n");
        BN_free(priv_key_bn);
        EC_KEY_free(ec_key);
        EC_GROUP_free(ec_group);
        return 0;
    }

    if (EC_KEY_set_private_key(ec_key, priv_key_bn) != 1)
    {
        printf("Error setting private key.\n");
        BN_free(priv_key_bn);
        EC_KEY_free(ec_key);
        EC_GROUP_free(ec_group);
        return 0;
    }

    // Create EVP_PKEY from EC key
    pkey = EVP_PKEY_new();
    if (pkey == NULL)
    {
        printf("Error creating EVP_PKEY.\n");
        BN_free(priv_key_bn);
        EC_KEY_free(ec_key);
        EC_GROUP_free(ec_group);
        return 0;
    }

    if (EVP_PKEY_assign_EC_KEY(pkey, ec_key) != 1)
    {
        printf("Error assigning EC key to EVP_PKEY.\n");
        BN_free(priv_key_bn);
        EVP_PKEY_free(pkey);
        EC_GROUP_free(ec_group);
        return 0;
    }

    // Create EVP_MD_CTX and initialize with SHA-256
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();

    if (mdctx == NULL)
    {
        printf("Error creating EVP_MD_CTX.\n");
        BN_free(priv_key_bn);
        EVP_PKEY_free(pkey);
        EC_GROUP_free(ec_group);
        return 0;
    }

    // Hash the message
    if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey) != 1)
    {
        printf("Error initializing signing operation.\n");
        BN_free(priv_key_bn);
        EVP_PKEY_free(pkey);
        EC_GROUP_free(ec_group);
        EVP_MD_CTX_free(mdctx);
        return 0;
    }
    if (EVP_DigestSignUpdate(mdctx, msg, msg_len) != 1)
    {
        printf("Error adding data to signing operation.\n");
        BN_free(priv_key_bn);
        EVP_PKEY_free(pkey);
        EC_GROUP_free(ec_group);
        EVP_MD_CTX_free(mdctx);
        return 0;
    }
    // Obtain the size of the signature
    if (EVP_DigestSignFinal(mdctx, NULL, signature_len) != 1)
    {
        printf("Error obtaining signature length.\n");
        BN_free(priv_key_bn);
        EVP_PKEY_free(pkey);
        EC_GROUP_free(ec_group);
        EVP_MD_CTX_free(mdctx);
        return 0;
    }

    // Sign the message
    if (EVP_DigestSignFinal(mdctx, signature, signature_len) != 1)
    {
        printf("Error signing the message.\n");
        BN_free(priv_key_bn);
        EVP_PKEY_free(pkey);
        EC_GROUP_free(ec_group);
        EVP_MD_CTX_free(mdctx);
        return 0;
    }
    printf("signature mesage length is %ld\n", *signature_len);

    ret = 1;
    // Cleanup
    BN_free(priv_key_bn);
    EVP_PKEY_free(pkey);
    EC_GROUP_free(ec_group);
    EVP_MD_CTX_free(mdctx);

    return ret;
}
// Usage example
int main()
{
    // Insert the private key in hexadecimal format
    const char private_key[] = {
        #include "prikey.txt"
        };
    const char msg[] = {
        #include "msg.dat"
    };
    // Create a buffer to hold the signature
    unsigned char signature[ECDSA_MAX_SIG_SIZE];
    size_t signature_len = 0;

    // Generate ECDSA signature
    int result = generate_ecdsa_signature(private_key, msg, sizeof(msg), signature, &signature_len);
    if (result)
    {
        printf("Signature: ");
        for (size_t i = 0; i < signature_len; i++)
        {
            printf("0x%02x,", signature[i]);
        }
        printf("\n");
        extractRSFromSignature(signature, signature_len);
    }
    else
    {
        printf("Failed to generate ECDSA signature.\n");
    }

    return 0;
}
