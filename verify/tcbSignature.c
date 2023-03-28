#include <stdio.h>
#include <stdlib.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

/*
 * may need padding the signature with 0x00
 */
// Path to the x509 certificate file
const char *cert_path = "./ec_cert.pem";

// Path to the message file
const char *msg_path = "message.txt";

// Path to the signature file
// May 0x00 bytes to the front of r/s to make it an unsigned integer
const char *sig_path = "./sig.bin";

int main(void) {
    X509 *cert = NULL;
    EVP_PKEY *pkey = NULL;
    FILE *msg_file = NULL;
    FILE *sig_file = NULL;
    unsigned char *msg = NULL;
    unsigned char *sig = NULL;
    size_t msg_len, sig_len;

    // Load the X509 certificate
    FILE *cert_file = fopen(cert_path, "r");
    if (!cert_file) {
        fprintf(stderr, "Error opening certificate file\n");
        return EXIT_FAILURE;
    }
    PEM_read_X509(cert_file, &cert, NULL, NULL);
    fclose(cert_file);

    // Load the message
    msg_file = fopen(msg_path, "rb");
    if (!msg_file) {
        fprintf(stderr, "Error opening message file\n");
        return EXIT_FAILURE;
    }
    fseek(msg_file, 0, SEEK_END);
    msg_len = ftell(msg_file);
    rewind(msg_file);
    msg = (unsigned char *)malloc(msg_len + 1);
    fread(msg, 1, msg_len, msg_file);
    fclose(msg_file);

    // Load the signature
    sig_file = fopen(sig_path, "rb");
    if (!sig_file) {
        fprintf(stderr, "Error opening signature file\n");
        return EXIT_FAILURE;
    }
    fseek(sig_file, 0, SEEK_END);
    sig_len = ftell(sig_file);
    rewind(sig_file);
    sig = (unsigned char *)malloc(sig_len);
    fread(sig, 1, sig_len, sig_file);
    fclose(sig_file);

    // Verify the signature
    pkey = X509_get_pubkey(cert);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!EVP_VerifyInit(ctx, EVP_sha256())) {
        fprintf(stderr, "Error initializing verify context\n");
        return EXIT_FAILURE;
    }
    if (!EVP_VerifyUpdate(ctx, msg, msg_len)) {
        fprintf(stderr, "Error updating verify context\n");
        return EXIT_FAILURE;
    }
    int rc = EVP_VerifyFinal(ctx, sig, sig_len, pkey);
    if (rc == 1) {
        printf("Signature verification successful.\n");
    } else if (rc == 0) {
        printf("Signature verification failed.\n");
    } else {
        printf("Error during signature verification.\n");
    }

    // Cleanup
    EVP_PKEY_free(pkey);
    X509_free(cert);
    free(msg);
    free(sig);
    EVP_MD_CTX_free(ctx);

    return EXIT_SUCCESS;
}

