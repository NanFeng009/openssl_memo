/*
 * gcc cert_key_verify.c -o cert_key_verify -lcrypto
 */
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

int sig_verify(const char* cert_pem, const char* intermediate_pem)
{
	BIO *b = BIO_new(BIO_s_mem());
	BIO_puts(b, intermediate_pem);
	X509 * issuer = PEM_read_bio_X509(b, NULL, NULL, NULL);
	EVP_PKEY *signing_key=X509_get_pubkey(issuer);

	BIO *c = BIO_new(BIO_s_mem());
	BIO_puts(c, cert_pem);
	X509 * x509 = PEM_read_bio_X509(c, NULL, NULL, NULL);

	int result = X509_verify(x509, signing_key);

	EVP_PKEY_free(signing_key);
	BIO_free(b);
	BIO_free(c);
	X509_free(x509);
	X509_free(issuer);

	return result;
}

void cert_info(const char* cert_pem)
{
	const X509_ALGOR *sig_alg;
	const ASN1_BIT_STRING *sig;

	BIO *b = BIO_new(BIO_s_mem());
	BIO_puts(b, cert_pem);
	X509 * x509 = PEM_read_bio_X509(b, NULL, NULL, NULL);

	BIO *bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);

	//Subject
	BIO_printf(bio_out,"Subject: ");
	X509_NAME_print(bio_out,X509_get_subject_name(x509),0);
	BIO_printf(bio_out,"\n");

	//Issuer
	BIO_printf(bio_out,"Issuer: ");
	X509_NAME_print(bio_out,X509_get_issuer_name(x509),0);
	BIO_printf(bio_out,"\n");

	//Public Key
	EVP_PKEY *pkey=X509_get_pubkey(x509);
	EVP_PKEY_print_public(bio_out, pkey, 0, NULL);
	EVP_PKEY_free(pkey);

	//Signature
	X509_get0_signature(&sig, &sig_alg, x509);
	X509_signature_print(bio_out, sig_alg, sig);
	BIO_printf(bio_out,"\n");

	BIO_free(bio_out);
	BIO_free(b);
	X509_free(x509);
}

//----------------------------------------------------------------------

int main(int argc, char **argv)
{
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_ciphers();
	OpenSSL_add_all_digests(); 
	const char cert[] = "-----BEGIN CERTIFICATE-----" "\n"
		"MIIFGzCCBKGgAwIBAgIQA8TAm6Yf9god6g9PkdJfazAKBggqhkjOPQQDAzBMMQsw" "\n"
		"CQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMSYwJAYDVQQDEx1EaWdp" "\n"
		"Q2VydCBFQ0MgU2VjdXJlIFNlcnZlciBDQTAeFw0xMzA5MzAwMDAwMDBaFw0xNjEw" "\n"
		"MDQxMjAwMDBaMGAxCzAJBgNVBAYTAlVTMQ0wCwYDVQQIEwRVdGFoMQ0wCwYDVQQH" "\n"
		"EwRMZWhpMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjEaMBgGA1UEAxMRYmxvZy5k" "\n"
		"aWdpY2VydC5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATmpgkfE9I8G/Eo" "\n"
		"IYPyu+X5Er6nll65D8gZ2OfTLCzebHwdybes1TDSde3E1V1tccz5aWqzJNgJrkPD" "\n"
		"+uzLc5r/o4IDTzCCA0swHwYDVR0jBBgwFoAUo53mH/naOU/AbuiRy5Wl2jHiCp8w" "\n"
		"HQYDVR0OBBYEFAjOkz5ghkAzC1h+65zS3yI6Y5ewMBwGA1UdEQQVMBOCEWJsb2cu" "\n"
		"ZGlnaWNlcnQuY29tMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcD" "\n"
		"AQYIKwYBBQUHAwIwaQYDVR0fBGIwYDAuoCygKoYoaHR0cDovL2NybDMuZGlnaWNl" "\n"
		"cnQuY29tL3NzY2EtZWNjLWcxLmNybDAuoCygKoYoaHR0cDovL2NybDQuZGlnaWNl" "\n"
		"cnQuY29tL3NzY2EtZWNjLWcxLmNybDCCAcQGA1UdIASCAbswggG3MIIBswYJYIZI" "\n"
		"AYb9bAEBMIIBpDA6BggrBgEFBQcCARYuaHR0cDovL3d3dy5kaWdpY2VydC5jb20v" "\n"
		"c3NsLWNwcy1yZXBvc2l0b3J5Lmh0bTCCAWQGCCsGAQUFBwICMIIBVh6CAVIAQQBu" "\n"
		"AHkAIAB1AHMAZQAgAG8AZgAgAHQAaABpAHMAIABDAGUAcgB0AGkAZgBpAGMAYQB0" "\n"
		"AGUAIABjAG8AbgBzAHQAaQB0AHUAdABlAHMAIABhAGMAYwBlAHAAdABhAG4AYwBl" "\n"
		"ACAAbwBmACAAdABoAGUAIABEAGkAZwBpAEMAZQByAHQAIABDAFAALwBDAFAAUwAg" "\n"
		"AGEAbgBkACAAdABoAGUAIABSAGUAbAB5AGkAbgBnACAAUABhAHIAdAB5ACAAQQBn" "\n"
		"AHIAZQBlAG0AZQBuAHQAIAB3AGgAaQBjAGgAIABsAGkAbQBpAHQAIABsAGkAYQBi" "\n"
		"AGkAbABpAHQAeQAgAGEAbgBkACAAYQByAGUAIABpAG4AYwBvAHIAcABvAHIAYQB0" "\n"
		"AGUAZAAgAGgAZQByAGUAaQBuACAAYgB5ACAAcgBlAGYAZQByAGUAbgBjAGUALjB7" "\n"
		"BggrBgEFBQcBAQRvMG0wJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0" "\n"
		"LmNvbTBFBggrBgEFBQcwAoY5aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0Rp" "\n"
		"Z2lDZXJ0RUNDU2VjdXJlU2VydmVyQ0EuY3J0MAwGA1UdEwEB/wQCMAAwCgYIKoZI" "\n"
		"zj0EAwMDaAAwZQIxAMNQ2j9Ua2jMEfRvhkhwRxF6NWVVFwxiV/D071rYkh1fNRFY" "\n"
		"1HRwzkxwfNR1och05gIweNMRY3kbaVp4Nv3LwiT2v/n9hm8IoOG8G4lXTWrwQHWA" "\n"
		"Rps5Urye1f8nmWtvxWeY" "\n"
		"-----END CERTIFICATE-----";
	const char intermediate[] = "-----BEGIN CERTIFICATE-----" "\n"
		"MIIDrDCCApSgAwIBAgIQCssoukZe5TkIdnRw883GEjANBgkqhkiG9w0BAQwFADBh" "\n"
		"MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3" "\n"
		"d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBD" "\n"
		"QTAeFw0xMzAzMDgxMjAwMDBaFw0yMzAzMDgxMjAwMDBaMEwxCzAJBgNVBAYTAlVT" "\n"
		"MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxJjAkBgNVBAMTHURpZ2lDZXJ0IEVDQyBT" "\n"
		"ZWN1cmUgU2VydmVyIENBMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE4ghC6nfYJN6g" "\n"
		"LGSkE85AnCNyqQIKDjc/ITa4jVMU9tWRlUvzlgKNcR7E2Munn17voOZ/WpIRllNv" "\n"
		"68DLP679Wz9HJOeaBy6Wvqgvu1cYr3GkvXg6HuhbPGtkESvMNCuMo4IBITCCAR0w" "\n"
		"EgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwNAYIKwYBBQUHAQEE" "\n"
		"KDAmMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQgYDVR0f" "\n"
		"BDswOTA3oDWgM4YxaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0R2xv" "\n"
		"YmFsUm9vdENBLmNybDA9BgNVHSAENjA0MDIGBFUdIAAwKjAoBggrBgEFBQcCARYc" "\n"
		"aHR0cHM6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzAdBgNVHQ4EFgQUo53mH/naOU/A" "\n"
		"buiRy5Wl2jHiCp8wHwYDVR0jBBgwFoAUA95QNVbRTLtm8KPiGxvDl7I90VUwDQYJ" "\n"
		"KoZIhvcNAQEMBQADggEBAMeKoENL7HTJxavVHzA1Nm6YVntIrAVjrnuaVyRXzG/6" "\n"
		"3qttnMe2uuzO58pzZNvfBDcKAEmzP58mrZGMIOgfiA4q+2Y3yDDo0sIkp0VILeoB" "\n"
		"UEoxlBPfjV/aKrtJPGHzecicZpIalir0ezZYoyxBEHQa0+1IttK7igZFcTMQMHp6" "\n"
		"mCHdJLnsnLWSB62DxsRq+HfmNb4TDydkskO/g+l3VtsIh5RHFPVfKK+jaEyDj2D3" "\n"
		"loB5hWp2Jp2VDCADjT7ueihlZGak2YPqmXTNbk19HOuNssWvFhtOyPNV6og4ETQd" "\n"
		"Ea8/B6hPatJ0ES8q/HO3X8IVQwVs1n3aAr0im0/T+Xc=" "\n"
		"-----END CERTIFICATE-----";
	cert_info(cert);
	cert_info(intermediate);
	sig_verify(cert,intermediate);
}
