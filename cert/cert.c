/*
 * #create a self-signed certificate for alice
 * openssl req -x509 -nodes -newkey rsa:4096 -keyout key-alice.pem -out cert-alice.pem -days 365
 * 
 * #create a self-signed certificate for bob
 * openssl req -x509 -nodes -newkey rsa:4096 -keyout key-bob.pem -out cert-bob.pem -days 365
 * 
 * #prepare the text
 * printf "A private message from alice">message-alice.txt
 * 
 * #encrypt & decrypt message
 * openssl rsautl -encrypt -certin -inkey cert-bob.pem -in message-alice.txt -out ciphertext.ssl
 * openssl rsautl -decrypt -inkey key-bob.pem -in ciphertext.ssl -out decrypted.txt
 * 
 * #signing with RSA
 * openssl rsautl -sign -inkey key-alice.pem -in message-alice.txt -out message.sgn
 * openssl rsautl -verify -in message.sgn -certin -inkey cert-alice.pem
*/
