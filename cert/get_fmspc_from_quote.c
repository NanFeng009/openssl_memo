/**
 * gcc -g fgetline.c -lcrypto -Wall -Wextra -Wformat=2 -Wunused -Wno-unused-parameter -Wshadow
 * https://www.openssl.org/docs/man1.1.1/man1/openssl-asn1parse.html
 * https://www.openssl.org/docs/man1.1.1/man3/ASN1_generate_nconf.html
 * openssl asn1parse -genconf asn1.cnf -noout -out asn1.der
 * openssl asn1parse -genstr 'UTF8:Hello World'
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#define BEGINSTR "-----BEGIN CERTIFICATE-----"
#define BEGINLEN ((int)(sizeof(BEGINSTR) - 1))
#define FMSPC_SIZE 6

const void *__memmem(const void *haystack, size_t haystack_len,
                   const void *const needle, const size_t needle_len)
{
    if (haystack == NULL)
        return NULL; // or assert(haystack != NULL);
    if (haystack_len == 0)
        return NULL;
    if (needle == NULL)
        return NULL; // or assert(needle != NULL);
    if (needle_len == 0)
        return NULL;

    for (const char *h = haystack;
         haystack_len >= needle_len;
         ++h, --haystack_len)
    {
        if (!memcmp(h, needle, needle_len))
        {
            return h;
        }
    }
    return NULL;
}
/**
 * @brief read a Intel DCAP quote, parse the PCK cert and return FMSPC from it
 *
 * @param dcap_quote_file
 * @param p_fmspc_from_quote
 * @param fmspc_from_quote_size
 * @return int
 */
int extrace_fmspc_from_dcap_quote(const char *dcap_quote_file, char *p_fmspc_from_quote, unsigned int fmspc_from_quote_size)
{
    FILE *dcap_quote_stream;
    char *line = NULL;
    size_t len = 0;
    ssize_t nread;
    BIO *bio_certs;
    int ret = 0;
    STACK_OF(X509) *sk_cert = NULL;
    STACK_OF(X509_INFO) *ski = NULL;
    X509 *cert = NULL;
    X509_INFO *x509_info;
    int found_cert = 0;
    X509_NAME *nm;
    ASN1_OBJECT *sgx_ext_oid = NULL;

    if(p_fmspc_from_quote == NULL || fmspc_from_quote_size < FMSPC_SIZE){
        return -1;
    }

    dcap_quote_stream = fopen(dcap_quote_file, "r");
    if (dcap_quote_stream == NULL)
    {
        perror("fopen");
        return -1;
    }

    bio_certs = BIO_new(BIO_s_mem());
    while ((nread = getline(&line, &len, dcap_quote_stream)) != -1)
    {
        if (!found_cert)
        {
            const char *header = __memmem(line, nread, BEGINSTR, BEGINLEN);
            if (header != NULL)
            {
                BIO_write(bio_certs, header, strlen(header));
                found_cert = 1;
            }
            continue;
        }
        BIO_write(bio_certs, line, strlen(line));
    }


    sk_cert = sk_X509_new_null();
    /* This loads from a file, a stack of x509/crl/pkey sets */
    ski = PEM_X509_INFO_read_bio(bio_certs, NULL, NULL, NULL);

    while (sk_X509_INFO_num(ski))
    {
        x509_info = sk_X509_INFO_shift(ski);
        if (x509_info->x509 != NULL)
        {
            sk_X509_push(sk_cert, x509_info->x509);
            x509_info->x509 = NULL;
        }
        X509_INFO_free(x509_info);
    }
    nm = X509_NAME_new();

    X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC, "Intel SGX PCK Certificate", -1, -1, 0);
    X509_NAME_add_entry_by_txt(nm, "O", MBSTRING_ASC, "Intel Corporation", -1, -1, 0);
    X509_NAME_add_entry_by_txt(nm, "L", MBSTRING_ASC, "Santa Clara", -1, -1, 0);
    X509_NAME_add_entry_by_txt(nm, "ST", MBSTRING_ASC, "CA", -1, -1, 0);
    X509_NAME_add_entry_by_txt(nm, "C", MBSTRING_ASC, "US", -1, -1, 0);

    sgx_ext_oid = OBJ_txt2obj("1.2.840.113741.1.13.1", 1);

    for (int i = 0; i < sk_X509_num(sk_cert); i++)
    {
        cert = sk_X509_value(sk_cert, i);
        X509_NAME *subject_in_stack = X509_get_subject_name(cert);
        if (X509_NAME_cmp(nm, subject_in_stack) == 0)
        {
            int sgx_ext_index = X509_get_ext_by_OBJ(cert, sgx_ext_oid, -1);
            if (sgx_ext_index >= 0)
            {
                X509_EXTENSION *sgx_ext = X509_get_ext(cert, sgx_ext_index);
                ASN1_OCTET_STRING *encoded = X509_EXTENSION_get_data(sgx_ext);
                int len0 = ASN1_STRING_length(encoded);
                const unsigned char *data = ASN1_STRING_get0_data(encoded);

                STACK_OF(ASN1_TYPE) *seq1 = d2i_ASN1_SEQUENCE_ANY(NULL, &data, len0);
                int seq_len1 = sk_ASN1_TYPE_num(seq1);
                for (int i = 0; i < seq_len1; i++)
                {
                    ASN1_TYPE *seq1_value = sk_ASN1_TYPE_value(seq1, i);
                    // currently all 5 setions have V_ASN1_SEQUENCE type, double confirm
                    if (seq1_value->type == V_ASN1_SEQUENCE)
                    {
                        const unsigned char *p = seq1_value->value.sequence->data;
                        int len1 = seq1_value->value.sequence->length;
                        STACK_OF(ASN1_TYPE) *seq2 = d2i_ASN1_SEQUENCE_ANY(NULL, &p, len1);
                        int seq_len2 = sk_ASN1_TYPE_num(seq2);
                        if (seq_len2 > 1)
                        {
                            ASN1_TYPE *seq2_value = sk_ASN1_TYPE_value(seq2, 0);
                            if (seq2_value->type == V_ASN1_OBJECT)
                            {
                                ASN1_OBJECT *_fmspc_obj = OBJ_txt2obj("1.2.840.113741.1.13.1.4", 0);
                                ASN1_OBJECT *asn2_obj = seq2_value->value.object;
                                if (OBJ_cmp(asn2_obj, _fmspc_obj) == 0)
                                {
                                    ASN1_TYPE *seq22_value = sk_ASN1_TYPE_value(seq2, 1);
                                    if (seq22_value->type == V_ASN1_OCTET_STRING)
                                    {
                                        ASN1_OCTET_STRING *octet_string = seq22_value->value.octet_string;
                                        const unsigned char *p_fmspc = ASN1_STRING_get0_data(octet_string);
                                        int len2 = ASN1_STRING_length(octet_string);
                                        memcpy(p_fmspc_from_quote, p_fmspc, len2);
                                        ret = 1;
                                    }
                                }
                                ASN1_OBJECT_free(_fmspc_obj);
                            }
                        }
                        sk_ASN1_TYPE_pop_free(seq2, ASN1_TYPE_free);
                    }
                }
                sk_ASN1_TYPE_pop_free(seq1, ASN1_TYPE_free);
            }
            break;
        }
    }
    sk_X509_pop_free(sk_cert, X509_free);
    free(line);
    fclose(dcap_quote_stream);
    BIO_free(bio_certs);
    X509_NAME_free(nm);
    return ret;
}


int main(int argc, char *argv[])
{
    char fmspc[6];
    extrace_fmspc_from_dcap_quote("./quote.dat", fmspc, 6);
    for (int i = 0; i < 6; i++)
    printf("%02x", fmspc[i]);
    printf("\n");

}
