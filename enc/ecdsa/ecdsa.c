/*
 *
 *#Create private key
 *openssl ecparam -genkey -name secp256k1 -noout -out private.pem
 *#Create public key
 *openssl ec -in private.pem -pubout -out public.pem
 *#Create the text file
 *printf "Hello world">plain.txt
 *#get the signature against hash(file)
 *openssl dgst -sha1 -sign private.pem -out signature.bin plain.txt
 *#verify the
 *openssl dgst -sha1 -verify public.pem -signature signature.bin plain.txt
 *#view the signature
 *openssl asn1parse -inform DER -in signature.bin
 *
 *#view the public key
 *pkey -in public.pem -text -noout -pubin
 *#view the private & public key
 *openssl ec -in private.pem -text -noout
 */
