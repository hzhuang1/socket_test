#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <netinet/tcp.h>
#include <linux/tls.h>

//#include "cert.h"

#define PORT 8443
#define CERTIFICATE_FILE "server.crt"
#define PRIVATE_KEY_FILE "server.key"
#define KEY_SIZE		EVP_MAX_KEY_LENGTH
#define IV_SIZE			EVP_MAX_IV_LENGTH

#define BUF_SIZE		1024

int create_socket(void)
{
	struct sockaddr_in server_addr;
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);

	if (sockfd < 0) {
		perror("Error opening socket");
		exit(EXIT_FAILURE);
	}

	bzero((char *) &server_addr, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
#if 1
	server_addr.sin_addr.s_addr = INADDR_ANY;
	server_addr.sin_port = htons(PORT);
#else
	server_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	server_addr.sin_port = htons(PORT);
#endif

	if (bind(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
		perror("bind failed");
		exit(EXIT_FAILURE);
	}

	//if (listen(sockfd, 5) < 0) {
	if (listen(sockfd, 1) < 0) {
		perror("listen");
		exit(EXIT_FAILURE);
	}

	return sockfd;
}

int socket_send_msg(void)
{
	int server_fd, new_socket;
	ssize_t bytes_sent;
	int ret;
	char buffer[BUF_SIZE] = {0};
	char *msg = "Hello from socket server!";

	server_fd = create_socket();

	printf("Waiting for a connection...\n");

	if ((new_socket = accept(server_fd, NULL, NULL)) < 0) {
		perror("accept");
		exit(EXIT_FAILURE);
	}

	ret = read(new_socket, buffer, sizeof(buffer) - 1);
	if (ret <= 0) {
		fprintf(stderr, "Fail to receive data from socket.\n");
		exit(EXIT_FAILURE);
	}

	printf("Received: %s\n", buffer);
	bytes_sent = send(new_socket, msg, strlen(msg), 0);
	if (bytes_sent < 0)
		perror("send");
	else
		printf("Sent %zd bytes\n", bytes_sent);

	// 清理和关闭
	close(new_socket);
	close(server_fd);

	return 0;
}

int socket_send_fdata(void)
{
	int server_fd, new_socket;
	int file_fd;
	struct stat st;
	ssize_t bytes_sent;
	ssize_t ret;
	char buffer[BUF_SIZE] = {0};
	size_t buf_sz;

	server_fd = create_socket();

	printf("Waiting for a connection...\n");

	if ((new_socket = accept(server_fd, NULL, NULL)) < 0) {
		perror("accept");
		exit(EXIT_FAILURE);
	}

	file_fd = open("testfile.txt", O_RDONLY);
	if (file_fd < 0) {
		perror("open");
		exit(EXIT_FAILURE);
	}

	if (fstat(file_fd, &st) < 0) {
		perror("fstat");
		exit(EXIT_FAILURE);
	}

	if (st.st_size > BUF_SIZE)
		buf_sz = BUF_SIZE;
	else
		buf_sz = st.st_size;
	ret = read(file_fd, buffer, buf_sz);
	if (ret <= 0) {
		fprintf(stderr, "fail to read file\n");
		exit(EXIT_FAILURE);
	} else if (ret != (ssize_t)buf_sz) {
		fprintf(stderr, "read data size not matched (%ld:%ld)\n", ret, buf_sz);
		exit(EXIT_FAILURE);
	}

	bytes_sent = send(new_socket, buffer, buf_sz, 0);
	if (bytes_sent < 0) {
		perror("send");
	} else {
		printf("Sent %zd bytes\n", bytes_sent);
	}

	close(file_fd);
	close(new_socket);
	close(server_fd);

	return 0;
}

int socket_send_file(void)
{
	int server_fd, new_socket;
	int file_fd;
	struct stat st;
	ssize_t bytes_sent;
	size_t buf_sz;

	server_fd = create_socket();

	printf("Waiting for a connection...\n");

	if ((new_socket = accept(server_fd, NULL, NULL)) < 0) {
		perror("accept");
		exit(EXIT_FAILURE);
	}

	file_fd = open("testfile.txt", O_RDONLY);
	if (file_fd < 0) {
		perror("open");
		exit(EXIT_FAILURE);
	}

	if (fstat(file_fd, &st) < 0) {
		perror("fstat");
		exit(EXIT_FAILURE);
	}

	if (st.st_size > BUF_SIZE)
		buf_sz = BUF_SIZE;
	else
		buf_sz = st.st_size;

	bytes_sent = sendfile(new_socket, file_fd, NULL, buf_sz);
	if (bytes_sent < 0) {
		perror("send");
	} else {
		printf("Sent %zd bytes\n", bytes_sent);
	}

	close(file_fd);
	close(new_socket);
	close(server_fd);

	return 0;
}

int ssl_send(void)
{
	SSL_CTX *ctx;
	SSL *ssl;
	int server_fd, new_socket;
	int file_fd;
	struct stat st;
	ssize_t bytes_sent;
	int ret;

	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	ctx = SSL_CTX_new(TLS_server_method());
	if (ctx == NULL) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	if (SSL_CTX_use_certificate_file(ctx, CERTIFICATE_FILE, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, PRIVATE_KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	if (!SSL_CTX_check_private_key(ctx)) {
		fprintf(stderr, "Private key does not match the public certificate\n");
		exit(EXIT_FAILURE);
	}

	server_fd = create_socket();

	printf("Waiting for a connection...\n");

	if ((new_socket = accept(server_fd, NULL, NULL)) < 0) {
		perror("accept");
		exit(EXIT_FAILURE);
	}

	ssl = SSL_new(ctx);
	SSL_set_fd(ssl, new_socket);

	if (SSL_accept(ssl) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	file_fd = open("testfile.txt", O_RDONLY);
	if (file_fd < 0) {
		perror("open");
		exit(EXIT_FAILURE);
	}

	if (fstat(file_fd, &st) < 0) {
		perror("fstat");
		exit(EXIT_FAILURE);
	}

#if 0
	bytes_sent = sendfile(new_socket, file_fd, &offset, st.st_size);
	if (bytes_sent < 0) {
		perror("sendfile");
	} else {
		printf("Sent %zd bytes\n", bytes_sent);
	}
#else
	{
		char buffer[1024];
		ret = SSL_read(ssl, buffer, sizeof(buffer) - 1);
		if (ret <= 0) {
			int ssl_error;
			ssl_error = SSL_get_error(ssl, ret);
			printf("SSL_read ret:%d(%d, %d)\n", ret, ssl_error, SSL_ERROR_SYSCALL);
			ERR_print_errors_fp(stderr);
			exit(EXIT_FAILURE);
		}
		printf("Received: %s\n", buffer);
	}
	{
		char *msg = "Hello from SSL server!";
		bytes_sent = SSL_write(ssl, msg, strlen(msg));
		if (bytes_sent < 0) {
			perror("SSL_write");
		} else {
			printf("Sent %zd bytes\n", bytes_sent);
		}
	}
#endif

	// 清理和关闭
	close(file_fd);
	SSL_shutdown(ssl);
	SSL_free(ssl);
	SSL_CTX_free(ctx);
	close(new_socket);

	return 0;
}

int ssl_send_fdata(void)
{
	SSL_CTX *ctx;
	SSL *ssl;
	int server_fd, new_socket;
	int file_fd;
	struct stat st;
	ssize_t bytes_sent;
	ssize_t ret;

	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	ctx = SSL_CTX_new(TLS_server_method());
	if (ctx == NULL) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	if (SSL_CTX_use_certificate_file(ctx, CERTIFICATE_FILE, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, PRIVATE_KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	if (!SSL_CTX_check_private_key(ctx)) {
		fprintf(stderr, "Private key does not match the public certificate\n");
		exit(EXIT_FAILURE);
	}

	server_fd = create_socket();

	printf("Waiting for a connection...\n");

	if ((new_socket = accept(server_fd, NULL, NULL)) < 0) {
		perror("accept");
		exit(EXIT_FAILURE);
	}

	ssl = SSL_new(ctx);
	SSL_set_fd(ssl, new_socket);

	if (SSL_accept(ssl) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	file_fd = open("testfile.txt", O_RDONLY);
	if (file_fd < 0) {
		perror("open");
		exit(EXIT_FAILURE);
	}

	if (fstat(file_fd, &st) < 0) {
		perror("fstat");
		exit(EXIT_FAILURE);
	}

#if 0
	bytes_sent = sendfile(new_socket, file_fd, &offset, st.st_size);
	if (bytes_sent < 0) {
		perror("sendfile");
	} else {
		printf("Sent %zd bytes\n", bytes_sent);
	}
#else
	{
		char buffer[BUF_SIZE];
		size_t buf_sz;

		if (st.st_size > BUF_SIZE)
			buf_sz = BUF_SIZE;
		else
			buf_sz = st.st_size;
		ret = read(file_fd, buffer, buf_sz);
		if (ret <= 0) {
			fprintf(stderr, "fail to read file\n");
			exit(EXIT_FAILURE);
		} else if (ret != (ssize_t)buf_sz) {
			fprintf(stderr, "unmatched file size\n");
			exit(EXIT_FAILURE);
		}
		bytes_sent = SSL_write(ssl, buffer, buf_sz);
		if (bytes_sent < 0)
			perror("SSL_write");
		else
			printf("Sent %zd bytes\n", bytes_sent);
	}
#endif

	// 清理和关闭
	close(file_fd);
	SSL_shutdown(ssl);
	SSL_free(ssl);
	SSL_CTX_free(ctx);
	close(new_socket);

	return 0;
}

int ssl_send_file(void)
{
	SSL_CTX *ctx;
	SSL *ssl;
	int server_fd, new_socket;
	int file_fd;
	struct stat st;
	ssize_t bytes_sent;
	size_t buf_sz;

	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	ctx = SSL_CTX_new(TLSv1_2_server_method());
	if (ctx == NULL) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	if (SSL_CTX_use_certificate_file(ctx, CERTIFICATE_FILE, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, PRIVATE_KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	if (!SSL_CTX_check_private_key(ctx)) {
		fprintf(stderr, "Private key does not match the public certificate\n");
		exit(EXIT_FAILURE);
	}

	server_fd = create_socket();

	printf("Waiting for a connection...\n");

	if ((new_socket = accept(server_fd, NULL, NULL)) < 0) {
		perror("accept");
		exit(EXIT_FAILURE);
	}

	ssl = SSL_new(ctx);
	SSL_set_fd(ssl, new_socket);

	if (SSL_accept(ssl) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	file_fd = open("testfile.txt", O_RDONLY);
	if (file_fd < 0) {
		perror("open");
		exit(EXIT_FAILURE);
	}

	if (fstat(file_fd, &st) < 0) {
		perror("fstat");
		exit(EXIT_FAILURE);
	}

	if (st.st_size > BUF_SIZE)
		buf_sz = BUF_SIZE;
	else
		buf_sz = st.st_size;
	printf("ktls send:%d, ktls recv:%d\n",
		BIO_get_ktls_send(SSL_get_wbio(ssl)),
		BIO_get_ktls_recv(SSL_get_rbio(ssl)));
	bytes_sent = SSL_sendfile(ssl, file_fd, 0, buf_sz, 0);
	printf("bytes_sent:%ld\n", bytes_sent);
	//bytes_sent = sendfile(new_socket, file_fd, NULL, buf_sz);
	if (bytes_sent < 0) {
		int ssl_error;
		//perror("SSL_write");
		ssl_error = SSL_get_error(ssl, bytes_sent);
		printf("SSL_read ret:%d(%d, %d)\n", bytes_sent, ssl_error, SSL_ERROR_SYSCALL);
	} else
		printf("Sent %zd bytes\n", bytes_sent);

	// 清理和关闭
	close(file_fd);
	SSL_shutdown(ssl);
	SSL_free(ssl);
	SSL_CTX_free(ctx);
	close(new_socket);

	return 0;
}

static void ssl_encrypt(const unsigned char *ptext, size_t ptext_len,
			unsigned char *ctext, size_t *ctext_len,
			const unsigned char *key, const unsigned char *iv)
{
	EVP_CIPHER_CTX *ctx;
	int len;
	int ret;

	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL) {
		fprintf(stderr, "Fail to create cipher ctx.\n");
		abort();
	}
	ret = EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key, iv);
	if (ret != 1) {
		fprintf(stderr, "Fail to init ctx with chacha20.\n");
		abort();
	}
	ret = EVP_EncryptUpdate(ctx, ctext, &len, ptext, ptext_len);
	if (ret != 1) {
		fprintf(stderr, "Fail on encrypt.\n");
		abort();
	}
	*ctext_len = len;
	ret = EVP_EncryptFinal_ex(ctx, ctext + len, &len);
	if (ret != 1) {
		fprintf(stderr, "Fail on encrypt final.\n");
		abort();
	}
	*ctext_len += len;

	EVP_CIPHER_CTX_free(ctx);
}

int socket_enc_send(void)
{
	SSL_CTX *ctx;
	int server_fd, new_socket;
	ssize_t bytes_sent;
	unsigned char key[KEY_SIZE], iv[IV_SIZE];
	int ret;

	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	ctx = SSL_CTX_new(TLS_server_method());
	if (ctx == NULL) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	if (SSL_CTX_use_certificate_file(ctx, CERTIFICATE_FILE, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, PRIVATE_KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	if (!SSL_CTX_check_private_key(ctx)) {
		fprintf(stderr, "Private key does not match the public certificate\n");
		exit(EXIT_FAILURE);
	}

	server_fd = create_socket();

	printf("Waiting for a connection...\n");

	if ((new_socket = accept(server_fd, NULL, NULL)) < 0) {
		perror("accept");
		exit(EXIT_FAILURE);
	}

	{
		unsigned char encrypted[1024];
		size_t encrypted_len;
		char *msg = "Hello from SSL server!";

		ret = RAND_bytes(key, KEY_SIZE);
		if (ret != 1) {
			fprintf(stderr, "Fail to get key.\n");
			abort();
		}
		ret = RAND_bytes(iv, IV_SIZE);
		if (ret != 1) {
			fprintf(stderr, "fail to get iv.\n");
			abort();
		}
		bytes_sent = send(new_socket, key, KEY_SIZE, 0);
		if (bytes_sent < 0)
			perror("sent key");
		else
			printf("Sent %zd bytes for key\n", bytes_sent);
		bytes_sent = send(new_socket, iv, IV_SIZE, 0);
		if (bytes_sent < 0)
			perror("sent iv");
		else
			printf("Sent %zd bytes for iv\n", bytes_sent);
		ssl_encrypt((const unsigned char *)msg, strlen(msg), encrypted, &encrypted_len,
			key, iv);
		bytes_sent = send(new_socket, &encrypted_len, sizeof(encrypted_len), 0);
		if (bytes_sent < 0)
			perror("send");
		else
			printf("Sent %zd bytes for encrypted length\n", bytes_sent);
		bytes_sent = send(new_socket, encrypted, encrypted_len, 0);
		if (bytes_sent < 0) {
			perror("send");
		} else {
			printf("Sent %zd bytes for encrypted data\n", bytes_sent);
		}
	}

	// 清理和关闭
	close(new_socket);

	return 0;
}

#if 0
// TODO: test
int gnutls_anon_send(void)
{
	int server_fd, new_socket;
	//int file_fd;
	//struct stat st;
	//off_t offset = 0;
	//ssize_t bytes_sent;
	int ret;
	//struct tls12_crypto_info_aes_gcm_128 crypto_info;
	//gnutls_datum_t mac_key;
	//gnutls_datum_t iv_read, iv_write;
	//gnutls_datum_t cipher_key_read, cipher_key_write;
	//unsigned char seq_number_read[8], seq_number_write[8];
	//gnutls_dtls_prestate_st prestate;
	//gnutls_certificate_credentials_t x509_cred;
	gnutls_session_t session;
	//gnutls_anon_
	//const char *priority = "SECURE128:+VERS-TLS1.3:-CIPHER-ALL:+CHACHA20-POLY1305:+COMP-NULL";
	const char *priority = "NONE:+VERS-TLS1.0:+AES-128-CBC:+SHA1:+SIGN-ALL:+COMP-NULL:+RSA";

	gnutls_global_init();

	server_fd = create_socket();

	printf("Waiting for a connection...\n");

	if ((new_socket = accept(server_fd, NULL, NULL)) < 0) {
		perror("accept");
		exit(EXIT_FAILURE);
	}

	gnutls_init(&session, GNUTLS_SERVER);
	gnutls_transport_set_int(session, new_socket);
	gnutls_priority_set_direct(session, priority, NULL);

	do {
		ret = gnutls_handshake(session);
		if (ret < 0) {
			fprintf(stderr, "server handshake failed: %s (%d)\n",
				gnutls_strerror(ret), ret);
			exit(EXIT_FAILURE);
		}
	} while (0);

	{
		char buffer[1024] = {0};
		printf("gnutls recv\n");
		ret = gnutls_record_recv(session, buffer, sizeof(buffer) - 1);
		if (ret <= 0) {
			fprintf(stderr, "gnutls_record_recv() failed: %s (%d)\n",
				gnutls_strerror(ret), ret);
			exit(EXIT_FAILURE);
		}

		printf("Received: %s\n", buffer);
	}
#if 0
	{
		char *msg = "Hello from socket server!";
		bytes_sent = send(new_socket, msg, strlen(msg), 0);
		if (bytes_sent < 0) {
			perror("send");
		} else {
			printf("Sent %zd bytes\n", bytes_sent);
		}
	}
#endif

	gnutls_bye(session, GNUTLS_SHUT_RDWR);
	// 清理和关闭
	//close(file_fd);
	close(new_socket);
	gnutls_deinit(session);
	//gnutls_certificate_free_credentials(x509_cred);
	gnutls_global_deinit();

	return 0;
}

// TODO: fix handshake issue
int gnutls_cert_send(const char *prio)
{
	int server_fd, new_socket;
	int file_fd;
	struct stat st;
	ssize_t bytes_sent;
	int ret;
	gnutls_certificate_credentials_t x509_cred;
	gnutls_session_t session;

	gnutls_global_init();
	gnutls_certificate_allocate_credentials(&x509_cred);
	ret = gnutls_certificate_set_x509_key_mem(
		x509_cred, &server_cert, &server_key, GNUTLS_X509_FMT_PEM);
	if (ret < 0) {
		fprintf(stderr, "fail to set x509 key\n");
		exit(EXIT_FAILURE);
	}

	server_fd = create_socket();

	printf("Waiting for a connection...\n");

	if ((new_socket = accept(server_fd, NULL, NULL)) < 0) {
		perror("accept");
		exit(EXIT_FAILURE);
	}

	gnutls_init(&session, GNUTLS_SERVER);
	// no timeout
	gnutls_handshake_set_timeout(session, 0);
	ret = gnutls_priority_set_direct(session, prio, NULL);
	if (ret < 0) {
		fprintf(stderr, "fail to set priority\n");
		exit(EXIT_FAILURE);
	}

	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, x509_cred);
	gnutls_transport_set_int(session, new_socket);

	do {
		ret = gnutls_handshake(session);
	} while (ret < 0 && gnutls_error_is_fatal(ret) == 0);
	if (ret < 0) {
		fprintf(stderr, "fail on server handshake:%s\n",
			gnutls_strerror(ret));
		exit(EXIT_FAILURE);
	}

	file_fd = open("testfile.txt", O_RDONLY);
	if (file_fd < 0) {
		perror("open");
		exit(EXIT_FAILURE);
	}

	if (fstat(file_fd, &st) < 0) {
		perror("fstat");
		exit(EXIT_FAILURE);
	}

	{
		char buffer[BUF_SIZE] = { 0 };
		size_t buf_sz;
		ssize_t ret;
		if (st.st_size > BUF_SIZE)
			buf_sz = BUF_SIZE;
		else
			buf_sz = st.st_size;
		ret = read(file_fd, buffer, sizeof(buffer));
		if (ret <= 0) {
			fprintf(stderr, "fail to read\n");
			exit(EXIT_FAILURE);
		} else if (ret != (ssize_t)buf_sz) {
			fprintf(stderr, "unmatched data loaded\n");
			exit(EXIT_FAILURE);
		}
		bytes_sent = gnutls_record_send(session, buffer, buf_sz);
		if (bytes_sent < 0) {
			perror("send");
		} else {
			printf("Sent %zd bytes\n", bytes_sent);
		}
	}

	gnutls_bye(session, GNUTLS_SHUT_RDWR);
	// 清理和关闭
	close(file_fd);
	close(new_socket);
	gnutls_deinit(session);
	gnutls_certificate_free_credentials(x509_cred);
	gnutls_global_deinit();
	close(server_fd);

	return 0;
}

// TODO: test
int gnutls_ktls_send(void)
{
	int server_fd, new_socket;
	int file_fd;
	struct stat st;
	//off_t offset = 0;
	ssize_t bytes_sent;
	int ret;
	//struct tls12_crypto_info_aes_gcm_128 crypto_info;
	//gnutls_datum_t mac_key;
	//gnutls_datum_t iv_read, iv_write;
	//gnutls_datum_t cipher_key_read, cipher_key_write;
	//unsigned char seq_number_read[8], seq_number_write[8];
	//gnutls_dtls_prestate_st prestate;
	gnutls_certificate_credentials_t x509_cred;
	gnutls_session_t session;

	gnutls_global_init();
	gnutls_certificate_allocate_credentials(&x509_cred);
	gnutls_certificate_set_x509_key_file(x509_cred,
				CERTIFICATE_FILE, PRIVATE_KEY_FILE,
				GNUTLS_X509_FMT_PEM);

	server_fd = create_socket();

	printf("Waiting for a connection...\n");

	if ((new_socket = accept(server_fd, NULL, NULL)) < 0) {
		perror("accept");
		exit(EXIT_FAILURE);
	}

	gnutls_init(&session, GNUTLS_SERVER);
	gnutls_transport_set_int(session, new_socket);
	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, x509_cred);

#if 0
	ret = gnutls_record_get_state(session, 1, &mac_key, &iv_read, &cipher_key_read, seq_number_read);
	if (ret < 0) {
		perror("failed to get receiving state from GNU TLS session");
		exit(EXIT_FAILURE);
	}
	ret = gnutls_record_get_state(session, 0, &mac_key, &iv_write, &cipher_key_write, seq_number_write);
	if (ret < 0) {
		perror("failed to get sending state from GNU TLS session");
		exit(EXIT_FAILURE);
	}
	setsockopt(new_socket, SOL_TCP, TCP_ULP, "tls", sizeof("tls"));
	memset(&crypto_info, 0, sizeof(crypto_info));
	crypto_info.info.version = TLS_1_2_VERSION;
	crypto_info.info.cipher_type = TLS_CIPHER_AES_GCM_128;
	memcpy(crypto_info.iv, seq_number_write, TLS_CIPHER_AES_GCM_128_IV_SIZE);
	memcpy(crypto_info.rec_seq, seq_number_write, TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE);
	if (cipher_key_write.size != TLS_CIPHER_AES_GCM_128_KEY_SIZE) {
		perror("mismatch in send key size");
		exit(EXIT_FAILURE);
	}
	memcpy(crypto_info.key, cipher_key_write.data, TLS_CIPHER_AES_GCM_128_KEY_SIZE);
	memcpy(crypto_info.salt, iv_write.data, TLS_CIPHER_AES_GCM_128_SALT_SIZE);
	setsockopt(new_socket, SOL_TLS, TLS_TX, &crypto_info, sizeof(crypto_info));
#endif

	do {
		ret = gnutls_handshake(session);
	} while (ret < 0 && gnutls_error_is_fatal(ret) == 0);

	file_fd = open("testfile.txt", O_RDONLY);
	if (file_fd < 0) {
		perror("open");
		exit(EXIT_FAILURE);
	}

	if (fstat(file_fd, &st) < 0) {
		perror("fstat");
		exit(EXIT_FAILURE);
	}

	printf("prepare to receive\n");
	exit(0);
	{
		char buffer[1024] = {0};
		ret = gnutls_record_recv(session, buffer, sizeof(buffer) - 1);
		if (ret <= 0) {
			ERR_print_errors_fp(stderr);
			exit(EXIT_FAILURE);
		}

		printf("Received: %s\n", buffer);
	}
	{
		char *msg = "Hello from socket server!";
		bytes_sent = send(new_socket, msg, strlen(msg), 0);
		if (bytes_sent < 0) {
			perror("send");
		} else {
			printf("Sent %zd bytes\n", bytes_sent);
		}
	}

	gnutls_bye(session, GNUTLS_SHUT_RDWR);
	// 清理和关闭
	close(file_fd);
	close(new_socket);
	gnutls_deinit(session);
	gnutls_certificate_free_credentials(x509_cred);
	gnutls_global_deinit();

	return 0;
}
#endif

int socket_send_ssl_enc(void)
{
	int server_fd, new_socket;
	int file_fd;
	struct stat st;
	//off_t offset = 0;
	ssize_t bytes_sent;
	int ret;

	server_fd = create_socket();

	printf("Waiting for a connection...\n");

	if ((new_socket = accept(server_fd, NULL, NULL)) < 0) {
		perror("accept");
		exit(EXIT_FAILURE);
	}

	file_fd = open("testfile.txt", O_RDONLY);
	if (file_fd < 0) {
		perror("open");
		exit(EXIT_FAILURE);
	}

	if (fstat(file_fd, &st) < 0) {
		perror("fstat");
		exit(EXIT_FAILURE);
	}

	{
		char buffer[1024] = {0};
		ret = read(new_socket, buffer, sizeof(buffer) - 1);
		if (ret <= 0) {
			ERR_print_errors_fp(stderr);
			exit(EXIT_FAILURE);
		}

		printf("Received: %s\n", buffer);
	}
	{
		char *msg = "Hello from socket server!";
		bytes_sent = send(new_socket, msg, strlen(msg), 0);
		if (bytes_sent < 0) {
			perror("send");
		} else {
			printf("Sent %zd bytes\n", bytes_sent);
		}
	}

	// 清理和关闭
	close(file_fd);
	close(new_socket);

	return 0;
}

int main(void) {
	int ret;

	ret = ssl_send_file();
	//ret = gnutls_cert_send(PRIO_STRING);
	if (ret)
		exit(EXIT_FAILURE);
	return 0;
}
