#include <stdio.h>
#include <string.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h> //PEM_read_X509, PEM_write_X509

/* 读取如下base64格式的证书，以16进制格式存储在disk*/
char *pem_cert_str= "-----BEGIN CERTIFICATE-----\n"\
					 "MIIMbjCCC1agAwIBAgIQQc2kxlw+Z2U6r6n41uZK1jANBgkqhkiG9w0BAQsFADBE\n"\
					 "MQswCQYDVQQGEwJVUzEWMBQGA1UEChMNR2VvVHJ1c3QgSW5jLjEdMBsGA1UEAxMU\n"\
					 "R2VvVHJ1c3QgU1NMIENBIC0gRzMwHhcNMTcwNjEzMDAwMDAwWhcNMTgwOTEyMjM1\n"\
					 "OTU5WjCBjTELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFDASBgNV\n"\
					 "BAcMC1NhbnRhIENsYXJhMRowGAYDVQQKDBFJbnRlbCBDb3Jwb3JhdGlvbjEfMB0G\n"\
					 "A1UECwwWSW5mb3JtYXRpb24gVGVjaG5vbG9neTEWMBQGA1UEAwwNd3d3LmludGVs\n"\
					 "LmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL987pg8Krnv30W2\n"\
					 "c5CuEk0+j0PVakqLQMeOTT/axhPIkd8ZbbuNhIzG5KClSBq0qVUUzF8G8ortSaBN\n"\
					 "3jHOeJdAcY6EMHrkIOFR30B14tqlFP2yNegT2onwIIQww5jtbhdMRdZjQaoP6vnz\n"\
					 "n20i9TeCVdwJZzxc466ghjxKARQoPP/4OAQv36f47SqpufX4ZBuPRHDpGSDFp+7S\n"\
					 "WYA2r59zO+6025eza/M6ZRbKGEO0oo6Lf03Yt/Otl6BPLueZLknFwW8pdGaTbzkU\n"\
					 "gEMWq12bo452MzQD+uLxy345PO5aAjKXFh2tKM6zC1cu+Mw5o/UI0FHO13EoA5/P\n"\
					 "qnsqXMECAwEAAaOCCRAwggkMMIIGBgYDVR0RBIIF/TCCBfmCEHd3dy5pbnRlbC5j\n"\
					 "b20uYm+CDHd3dy5pbnRlbC5keoIMd3d3LmludGVsLmV1ggx3d3cuaW50ZWwuZWeC\n"\
					 "C2lxLmludGVsLm5sggx3d3cuaW50ZWwubmyCDHd3dy5pbnRlbC5lc4ILaXEuaW50\n"\
					 "ZWwuZXOCDHd3dy5pbnRlbC5jYYIMd3d3LmludGVsLm1lgh53d3cuYW1lcmljYXNn\n"\
					 "cmVhdGVzdG1ha2Vycy5jb22CDHd3dy5pbnRlbC5mcoILaXEuaW50ZWwuZnKCD2lx\n"\
					 "LmludGVsLmNvbS50coIQd3d3LmludGVsLmNvbS50coIMd3d3LmludGVsLmNoggx3\n"\
					 "d3cuaW50ZWwubWGCEHd3dy5pbnRlbC5jb20ubXiCEHd3dy5pbnRlbC5jb20uZWOC\n"\
					 "EHd3dy5pbnRlbC5jb20uYXKCD3d3dy5pbnRlbC5jby5jcoIMd3d3LmludGVsLm15\n"\
					 "ggx3d3cuaW50ZWwuYXSCDmlxLmludGVsLmNvLnVrgg93d3cuaW50ZWwuY28udWuC\n"\
					 "DHd3dy5pbnRlbC5iZYIQd3d3LmludGVsLmNvbS5icoIPaXEuaW50ZWwuY29tLmJy\n"\
					 "ggtpcS5pbnRlbC5jeoIMd3d3LmludGVsLmN6gg93d3cuaW50ZWwuY28ua3KCD3d3\n"\
					 "dy5pbnRlbC5jby5pbIIMd3d3LmludGVsLnNlggtpcS5pbnRlbC5sYYIMd3d3Lmlu\n"\
					 "dGVsLmxhgg9pcS5pbnRlbC5jb20uYXWCEHd3dy5pbnRlbC5jb20uYXWCC2lxLmlu\n"\
					 "dGVsLnJvghB3d3cuaW50ZWwuY29tLnBlghB3d3cuaW50ZWwuY29tLnZlggtpcS5p\n"\
					 "bnRlbC5kZYIMd3d3LmludGVsLmRlggx3d3cuaW50ZWwuaWWCDHd3dy5pbnRlbC5w\n"\
					 "a4IOaXEuaW50ZWwuY28uYWWCD3d3dy5pbnRlbC5jby5hZYIMd3d3LmludGVsLmlu\n"\
					 "ggtpcS5pbnRlbC5pboIPd3d3LmludGVsLmNvLnphgg5pcS5pbnRlbC5jby56YYIP\n"\
					 "d3d3LmludGVsLmNvLm56ggx3d3cuaW50ZWwuc2eCDHd3dy5pbnRlbC5reoIQd3d3\n"\
					 "LmludGVsLmNvbS5uZ4IQd3d3LmludGVsLmNvbS5weYIXc2ltcGxlY29yZS1wcmMu\n"\
					 "aW50ZWwuY26CEW5ld3Nyb29tLmludGVsLmNughBkaWFubmFvLmludGVsLmNuggx3\n"\
					 "d3cuaW50ZWwuY26CEHd3dy5pbnRlbC5jb20uY2+CDHd3dy5pbnRlbC5jbIIPd3d3\n"\
					 "LmludGVsLmNvLmpwgg5pcS5pbnRlbC5jby5qcIISZWNhcmQuaW50ZWwuY29tLnR3\n"\
					 "ghJidXlwYy5pbnRlbC5jb20udHeCEHd3dy5pbnRlbC5jb20udHeCDHd3dy5pbnRl\n"\
					 "bC5ydYILaXEuaW50ZWwucnWCEHd3dy5pbnRlbC5jb20ucHKCDHd3dy5pbnRlbC5w\n"\
					 "bIILaXEuaW50ZWwucGyCDHd3dy5pbnRlbC51YYIQd3d3LmludGVsLmNvbS51eYIM\n"\
					 "d3d3LmludGVsLm5nggx3d3cuaW50ZWwuaHWCC2lxLmludGVsLml0ggx3d3cuaW50\n"\
					 "ZWwuaXSCDHd3dy5pbnRlbC5waIIPd3d3LmludGVsLmNvLmlkggx3d3cuaW50ZWwu\n"\
					 "c2GCC2lxLmludGVsLnNhggx3d3cuaW50ZWwuaGuCDHd3dy5pbnRlbC52boIeZW1i\n"\
					 "ZWRkZWQuY29tbXVuaXRpZXMuaW50ZWwuY29tghN5dW0ucmVwb3MuaW50ZWwuY29t\n"\
					 "gglpbnRlbC5jb22CE3d3dy5rZW55YS5pbnRlbC5jb22CFnd3dy50aGFpbGFuZC5p\n"\
					 "bnRlbC5jb22CE2NxcHJldmlldy5pbnRlbC5jb22CEnRlc3Qtd3d3LmludGVsLmNv\n"\
					 "bYITYXB0LnJlcG9zLmludGVsLmNvbYIVd3d3LXN0YWdpbmcuaW50ZWwuY29tgg53\n"\
					 "d3czLmludGVsLmNvbYINd3d3LmludGVsLmNvbTAJBgNVHRMEAjAAMA4GA1UdDwEB\n"\
					 "/wQEAwIFoDArBgNVHR8EJDAiMCCgHqAchhpodHRwOi8vZ24uc3ltY2IuY29tL2du\n"\
					 "LmNybDCBnQYDVR0gBIGVMIGSMIGPBgZngQwBAgIwgYQwPwYIKwYBBQUHAgEWM2h0\n"\
					 "dHBzOi8vd3d3Lmdlb3RydXN0LmNvbS9yZXNvdXJjZXMvcmVwb3NpdG9yeS9sZWdh\n"\
					 "bDBBBggrBgEFBQcCAjA1DDNodHRwczovL3d3dy5nZW90cnVzdC5jb20vcmVzb3Vy\n"\
					 "Y2VzL3JlcG9zaXRvcnkvbGVnYWwwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUF\n"\
					 "BwMCMB8GA1UdIwQYMBaAFNJv95b0hT9yPDB9I9qFeJujfFp8MFcGCCsGAQUFBwEB\n"\
					 "BEswSTAfBggrBgEFBQcwAYYTaHR0cDovL2duLnN5bWNkLmNvbTAmBggrBgEFBQcw\n"\
					 "AoYaaHR0cDovL2duLnN5bWNiLmNvbS9nbi5jcnQwggF9BgorBgEEAdZ5AgQCBIIB\n"\
					 "bQSCAWkBZwB2AN3rHSt6DU+mIIuBrYFocH4ujp0B1VyIjT0RxM227L7MAAABXKJm\n"\
					 "Ar0AAAQDAEcwRQIgHiWzpE2GPNd8LZRYYF5qjpvCLTYItRN7D4CaQ+wzL6ICIQDi\n"\
					 "iHq01uscXMsdmwI9k13WX4IUe6a64yufYfhYr+3EAQB2AKS5CZC0GFgUh7sTosxn\n"\
					 "cAo8NZgE+RvfuON3zQ7IDdwQAAABXKJmAvAAAAQDAEcwRQIhAM1Y7ajkuS6LJAjO\n"\
					 "YlTFDKDYMBW3RIq1D8FyEUq6dRreAiAFd/Opm8gX4QwK1fOCzQNUYlbzYdHZzp+r\n"\
					 "X47xD6pY5gB1AO5Lvbd1zmC64UJpH6vhnmajD35fsHLYgwDEe4l6qP3LAAABXKJm\n"\
					 "BLMAAAQDAEYwRAIgB6POFcsm2PUWfh+Gnk0sNUA+pgqcaVpWAkTOhQP+67cCICMc\n"\
					 "TK/wKxqrjADYen/i9VttcBu7MiDpziWOrtkefs2eMA0GCSqGSIb3DQEBCwUAA4IB\n"\
					 "AQBCLWw50zHNkOdqm/gBzJVFOZPq3mrR6YUKWBLVd6bw2Pmixb7DkK8kwZWA1S19\n"\
					 "OAQLaNreWoYF9qrRkvzAX+ZHVcmjW4o0a7tZsO44xwHhEVdfH/vKn2q/hw5+05gh\n"\
					 "pbsRMNRaQyQ6GPCrT9GD4Vv9kqlN8eOk3lXnirK6CWMtTok+y3l9zFh2HWJmDyAU\n"\
					 "0v5MluuqKDQYHz+40gmbMm1fskJO0inPTtdP/c4+Kb4Ol6YV+iQelDj+u1bNsvUj\n"\
					 "mdyGGlqh46XCrbzE+nrvCkZgwRf9vEiL5RVBKxRZu/NvxwihHkyEDS7b8ZnKHzgU\n"\
					 "7JGWwj6sSLDhs4RHXC5Cs3iI\n"\
					 "-----END CERTIFICATE-----\n";
int main()
{
		FILE * fp;
		size_t cert_len = strlen(pem_cert_str);
		BIO * cert_bio = BIO_new(BIO_s_mem());
		BIO_write(cert_bio, pem_cert_str, cert_len);
		X509* certX509 = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL);
		if(!certX509)
		{
				fprintf(stderr, "unable to read cert from mem \n" );
				return EXIT_FAILURE;
		}
		/******************** parse cert ***********************/
		fp = fopen("base64_2_hex.txt", "w");
		unsigned char *buf = NULL;
		int len = i2d_X509(certX509, &buf);

		//store as HEX format in disk
		for(int i = 0; i < len; i++)
		{
				printf("0x%02X, ", *(buf + i));
				fprintf(fp, "0x%02X, ", *(buf + i));
		}
		fclose(fp);
		/******************** parse cert ***********************/
		printf("\n");
		BIO_free(cert_bio);
		X509_free(certX509);

}

