/*
 * #server side:
 * openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
 * openssl s_server -key key.pem -cert cert.pem -accept 44330 -Verify 1 -verifyCAfile client_root.pem
 *
 * #client side:
 * openssl s_client -connect 10.239.11.2:44330 -cert client_cert.pem -key client_key.pem
 *
 * client_root.pem-->client_cert.pem
 */


