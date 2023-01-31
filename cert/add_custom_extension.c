/**
 * X509V3_EXT_add_nconf -> X509V3_EXT_add_nconf_sk -> X509V3_EXT_nconf_int -> v3_generic_extension -> generic_asn1 -> ASN1_generate_v3 -> generate_v3 -> asn1_str2type
 */
#include <openssl/asn1.h>
#include <openssl/x509.h>

int main()
{
    X509_EXTENSION *ext = NULL;
    ASN1_OCTET_STRING *data = NULL;
    ASN1_OBJECT *obj = NULL;

    // Define the Object Identifier (OID) for the custom extension
    obj = OBJ_txt2obj("1.2.3.4.5.6.7.8", 0);

    // Convert the string to an ASN1_OCTET_STRING
    data = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(data, (unsigned char *)"Custom Extension Data", 23);

    // Create the X509_EXTENSION with the OID and ASN1_OCTET_STRING
    ext = X509_EXTENSION_create_by_OBJ(NULL, obj, 0, data);
    
    // Add extension to cert
    X509_add_ext(x509cert, ext, -1)
    
    // Free the ASN1_OCTET_STRING and ASN1_OBJECT
    ASN1_OCTET_STRING_free(data);
    ASN1_OBJECT_free(obj);

    // Use the X509_EXTENSION as needed

    // Free the X509_EXTENSION when done
    X509_EXTENSION_free(ext);

    return 0;
}
