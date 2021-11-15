# security_openssl
# PEM file format
-----BEGIN RSA PUBLIC KEY-----
BASE64 ENCODED DATA
-----END RSA PUBLIC KEY-----
# View PEM encoded certificate
Use the command that has the extension of your certificate replacing cert.xxx with the name of your certificate

> openssl x509 -in cert.pem -text -noout

> openssl x509 -in cert.cer -text -noout

> openssl x509 -in cert.crt -text -noout

If you get the following error it means that you are trying to view a DER encoded certifciate and need to use the commands in the **View DER encoded certificate  below**

## unable to load certificate
*12626:error:0906D06C:PEM routines:PEM_read_bio:no start line:pem_lib.c:647:Expecting: TRUSTED CERTIFICATE*

*View DER encoded Certificate*
> openssl x509 -in certificate.der -inform der -text -noout

*Transform*
Transforms can take one type of encoded certificate to another. (ie. PEM To DER conversion)

- PEM to DER
> openssl x509 -in cert.crt -outform der -out cert.der
- DER to PEM
> openssl x509 -in cert.crt -inform der -outform pem -out cert.pem
# View KEY 
> openssl rsa -in key.pem -text -noout

- more example can be found in here
sdk/tlibcrypto/sgxssl
