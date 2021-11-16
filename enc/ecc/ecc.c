/*
 * https://jameshfisher.com/2017/04/14/openssl-ecc/
 * However, there are no tools for encrypting and decrypting! ECC doesn’t define these directly. 
 * Instead, ECC users use Diffie-Hellman (DH) key exchange to compute a shared secret, then communicate 
 * using that shared secret. This combination of ECC and DH is called ECDH.
 *
 *# Alice generates her private key
 * openssl ecparam -name secp256k1 -genkey -noout -out alice_priv_key.pem
 * #view the private and public key
 * openssl pkey -in alice_priv_key.pem
 * 
 * # Alice extracts her public key from her private key
 * openssl ec -in alice_priv_key.pem -pubout -out alice_pub_key.pem
 * #view the public key
 * openssl pkey -in alice_pub_key.pem -pubin
 * 
 * # Alice & Bob derive the shared secret
 * openssl pkeyutl -derive -inkey alice_priv_key.pem -peerkey bob_pub_key.pem -out alice_shared_secret.bin
 * openssl pkeyutl -derive -inkey bob_priv_key.pem -peerkey alice_pub_key.pem -out bob_shared_secret.bin
 * 
 * # Alice encrypt file and Bob decrypt the file
 * echo 'I love you Bob' > plain.txt
 * openssl enc -aes256 -base64 -k $(base64 alice_shared_secret.bin) -e -in plain.txt -out cipher.txt
 * openssl enc -aes256 -base64 -k $(base64 bob_shared_secret.bin) -d -in cipher.txt -out plain_again.txt
 *
 */
