#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <linux/tls.h>

//#include "cert.h"

//#define HOST "localhost"
//#define HOST "172.18.0.2"
//#define HOST "172.29.210.156"
#define HOST "127.0.0.1"
#define PORT	8443 // 假设服务器在4433端口上监听
#define KEY_SIZE		EVP_MAX_KEY_LENGTH
#define IV_SIZE			EVP_MAX_IV_LENGTH

#define BUF_SIZE		1024

int socket_recv_msg(void)
{
	int sockfd;
	struct sockaddr_in address;
	int opt = 1;
	char buffer[BUF_SIZE] = {0};
	const char *message = "Hello from SSL client!";
	int ret;

	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
		perror("socket failed");
		exit(EXIT_FAILURE);
	}

	// 设置socket为非阻塞模式（可选）
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
		perror("setsockopt");
		exit(EXIT_FAILURE);
	}

	address.sin_family = AF_INET;
	address.sin_port = htons(PORT);
	if (inet_pton(AF_INET, HOST, &address.sin_addr) <= 0) {
		perror("invalid IP address");
		exit(EXIT_FAILURE);
	}

	if (connect(sockfd, (struct sockaddr *)&address, sizeof(address))<0) {
		perror("connect failed");
		exit(EXIT_FAILURE);
	}

	// 发送消息到服务器
	if (send(sockfd, message, strlen(message), 0) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	printf("waiting server message\n");

	// 接收来自服务器的消息
	ret = read(sockfd, buffer, sizeof(buffer) - 1);
	if (ret <= 0) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	printf("Received: %s\n", buffer);

	// 关闭socket
	close(sockfd);

	return 0;
}

// respond to socket_send_fdata() & socket_send_file() in server
int socket_recv_fdata(void)
{
	int sockfd;
	struct sockaddr_in address;
	int opt = 1;
	char buffer[BUF_SIZE] = {0};
	const char *message = "Hello from SSL client!";
	int ret;

	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
		perror("socket failed");
		exit(EXIT_FAILURE);
	}

	// 设置socket为非阻塞模式（可选）
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
		perror("setsockopt");
		exit(EXIT_FAILURE);
	}

	address.sin_family = AF_INET;
	address.sin_port = htons(PORT);
	if (inet_pton(AF_INET, HOST, &address.sin_addr) <= 0) {
		perror("invalid IP address");
		exit(EXIT_FAILURE);
	}

	if (connect(sockfd, (struct sockaddr *)&address, sizeof(address))<0) {
		perror("connect failed");
		exit(EXIT_FAILURE);
	}

	// 发送消息到服务器
	if (send(sockfd, message, strlen(message), 0) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	printf("waiting server message\n");

	// 接收来自服务器的消息
	ret = read(sockfd, buffer, sizeof(buffer) - 1);
	if (ret <= 0) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	printf("Received: %s\n", buffer);

	// 关闭socket
	close(sockfd);

	return 0;
}

int ssl_recv(void)
{
	SSL_CTX *ctx;
	SSL *ssl;
	int sockfd;
	struct sockaddr_in address;
	int opt = 1;
	char buffer[1024] = {0};
	const char *message = "Hello from SSL client!";
	int ret;

	// 初始化OpenSSL
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	//ctx = SSL_CTX_new(TLSv1_2_client_method()); // 使用TLSv1.2
	ctx = SSL_CTX_new(TLS_client_method()); // 使用TLS
	if (ctx == NULL) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	if (SSL_CTX_load_verify_locations(ctx, "server.crt", NULL) != 1) {
		perror("CA failed");
		exit(EXIT_FAILURE);
	}

	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

	// 创建socket
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
		perror("socket failed");
		exit(EXIT_FAILURE);
	}

	// 设置socket为非阻塞模式（可选）
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
		perror("setsockopt");
		exit(EXIT_FAILURE);
	}

	address.sin_family = AF_INET;
	//address.sin_addr.s_addr = INADDR_ANY;
	address.sin_port = htons(PORT);
	if (inet_pton(AF_INET, HOST, &address.sin_addr) <= 0) {
		perror("invalid IP address");
		exit(EXIT_FAILURE);
	}

	// 连接到服务器
	if (connect(sockfd, (struct sockaddr *)&address, sizeof(address))<0) {
		perror("connect failed");
		exit(EXIT_FAILURE);
	}

	ssl = SSL_new(ctx); // 创建新的SSL结构
	SSL_set_fd(ssl, sockfd); // 绑定SSL结构到socket描述符

	// 建立SSL连接
	if (SSL_connect(ssl) == -1) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	long verify_result = SSL_get_verify_result(ssl);
	if (verify_result != X509_V_OK) {
		perror("SSL failed");
		exit(EXIT_FAILURE);
	}
	// 发送消息到服务器
	if (SSL_write(ssl, message, strlen(message)) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	printf("waiting server message\n");

	// 接收来自服务器的消息
	ret = SSL_read(ssl, buffer, sizeof(buffer) - 1);
	if (ret <= 0) {
		int ssl_error;
		ssl_error = SSL_get_error(ssl, ret);
		printf("SSL_read ret:%d(%d, %d)\n", ret, ssl_error, SSL_ERROR_SYSCALL);
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	printf("Received: %s\n", buffer);

	// 关闭SSL连接和socket
	SSL_shutdown(ssl);
	close(sockfd);

	// 清理
	SSL_free(ssl);
	SSL_CTX_free(ctx);

	return 0;
}

int ssl_recv_fdata(void)
{
	SSL_CTX *ctx;
	SSL *ssl;
	int sockfd;
	struct sockaddr_in address;
	int opt = 1;
	char buffer[BUF_SIZE] = {0};
	int ret;

	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	ctx = SSL_CTX_new(TLSv1_2_client_method()); // 使用TLS
	if (ctx == NULL) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	if (SSL_CTX_load_verify_locations(ctx, "server.crt", NULL) != 1) {
		perror("CA failed");
		exit(EXIT_FAILURE);
	}

	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

	// 创建socket
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
		perror("socket failed");
		exit(EXIT_FAILURE);
	}

	// 设置socket为非阻塞模式（可选）
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
		perror("setsockopt");
		exit(EXIT_FAILURE);
	}

	address.sin_family = AF_INET;
	//address.sin_addr.s_addr = INADDR_ANY;
	address.sin_port = htons(PORT);
	if (inet_pton(AF_INET, HOST, &address.sin_addr) <= 0) {
		perror("invalid IP address");
		exit(EXIT_FAILURE);
	}

	// 连接到服务器
	if (connect(sockfd, (struct sockaddr *)&address, sizeof(address))<0) {
		perror("connect failed");
		exit(EXIT_FAILURE);
	}

	ssl = SSL_new(ctx); // 创建新的SSL结构
	SSL_set_fd(ssl, sockfd); // 绑定SSL结构到socket描述符

	// 建立SSL连接
	if (SSL_connect(ssl) == -1) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	long verify_result = SSL_get_verify_result(ssl);
	if (verify_result != X509_V_OK) {
		perror("SSL failed");
		exit(EXIT_FAILURE);
	}
	printf("waiting server message\n");

	// 接收来自服务器的消息
	ret = SSL_read(ssl, buffer, sizeof(buffer) - 1);
	//ret = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
	if (ret <= 0) {
		int ssl_error;
		ssl_error = SSL_get_error(ssl, ret);
		printf("SSL_read ret:%d(%d, %d)\n", ret, ssl_error, SSL_ERROR_SYSCALL);
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	printf("Received: %s\n", buffer);

	// 关闭SSL连接和socket
	SSL_shutdown(ssl);
	close(sockfd);

	// 清理
	SSL_free(ssl);
	SSL_CTX_free(ctx);

	return 0;
}

static void ssl_decrypt(unsigned char *ctext, size_t ctext_len,
			unsigned char *ptext, size_t *ptext_len,
			const unsigned char *key, const unsigned char *iv)
{
	EVP_CIPHER_CTX *ctx;
	int len;
	int ret;

	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL) {
		fprintf(stderr, "fail to create cipher ctx.\n");
		abort();
	}
	ret = EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key, iv);
	if (ret != 1) {
		fprintf(stderr, "Fail to init chacha20.\n");
		abort();
	}
	ret = EVP_DecryptUpdate(ctx, ptext, &len, ctext, ctext_len);
	if (ret != 1) {
		fprintf(stderr, "Fail to update decrypt.\n");
		abort();
	}
	*ptext_len = len;
	ret = EVP_DecryptFinal_ex(ctx, ptext + len, &len);
	if (ret != 1) {
		fprintf(stderr, "Fail to finish decrypt.\n");
		abort();
	}
	*ptext_len += len;

	EVP_CIPHER_CTX_free(ctx);
}

int socket_dec_recv(void)
{
	SSL_CTX *ctx;
	int sockfd;
	struct sockaddr_in address;
	int opt = 1;

	// 初始化OpenSSL
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	ctx = SSL_CTX_new(TLS_client_method()); // 使用TLS
	if (ctx == NULL) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	if (SSL_CTX_load_verify_locations(ctx, "server.crt", NULL) != 1) {
		perror("CA failed");
		exit(EXIT_FAILURE);
	}

	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

	// 创建socket
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
		perror("socket failed");
		exit(EXIT_FAILURE);
	}

	// 设置socket为非阻塞模式（可选）
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
		perror("setsockopt");
		exit(EXIT_FAILURE);
	}

	address.sin_family = AF_INET;
	//address.sin_addr.s_addr = INADDR_ANY;
	address.sin_port = htons(PORT);
	if (inet_pton(AF_INET, HOST, &address.sin_addr) <= 0) {
		perror("invalid IP address");
		exit(EXIT_FAILURE);
	}

	// 连接到服务器
	if (connect(sockfd, (struct sockaddr *)&address, sizeof(address))<0) {
		perror("connect failed");
		exit(EXIT_FAILURE);
	}

#if 0
	ssl = SSL_new(ctx); // 创建新的SSL结构
	SSL_set_fd(ssl, sockfd); // 绑定SSL结构到socket描述符

	// 建立SSL连接
	if (SSL_connect(ssl) == -1) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	long verify_result = SSL_get_verify_result(ssl);
	if (verify_result != X509_V_OK) {
		perror("SSL failed");
		exit(EXIT_FAILURE);
	}
	// 发送消息到服务器
	if (SSL_write(ssl, message, strlen(message)) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
#endif
	printf("waiting server message\n");

	// 接收来自服务器的消息
	{
		size_t encrypted_len, ptext_len;
		unsigned char encrypted[1024], ptext[1024];
		unsigned char key[KEY_SIZE], iv[IV_SIZE];
		int bytes_recv;

		bytes_recv = recv(sockfd, key, KEY_SIZE, 0);
		if (bytes_recv <= 0) {
			fprintf(stderr, "fail to recv key\n");
			abort();
		}
		printf("Receive %d bytes\n", bytes_recv);
		bytes_recv = recv(sockfd, iv, IV_SIZE, 0);
		if (bytes_recv <= 0) {
			fprintf(stderr, "fail to recv iv\n");
			abort();
		}
		printf("Receive %d bytes\n", bytes_recv);
		bytes_recv = recv(sockfd, &encrypted_len, sizeof(encrypted_len), 0);
		if (bytes_recv <= 0) {
			fprintf(stderr, "fail to recv\n");
			abort();
		}
		printf("Receive %d bytes\n", bytes_recv);
		bytes_recv = recv(sockfd, encrypted, encrypted_len, 0);
		if (bytes_recv <= 0) {
			fprintf(stderr, "fail to recv encrypted\n");
			abort();
		}
		printf("Receive %d bytes\n", bytes_recv);
		ssl_decrypt(encrypted, encrypted_len, ptext, &ptext_len, key, iv);
		printf("Received: %s\n", ptext);
	}

	// 关闭SSL连接和socket
	//SSL_shutdown(ssl);
	close(sockfd);

	// 清理
	//SSL_free(ssl);
	SSL_CTX_free(ctx);

	return 0;
}

#if 0
int gnutls_recv(void)
{
	int sockfd, new_socket;
	struct sockaddr_in address;
	int opt = 1;
	const char *message = "Hello from TLS client!";
	int ret;
	//struct tls12_crypto_info_aes_gcm_128 crypto_info;
	//gnutls_certificate_credentials_t x509_cred;
	gnutls_session_t session;
	//const char *priority = "SECURE128:+VERS-TLS1.3:-CIPHER-ALL:+CHACHA20-POLY1305:+COMP-NULL";
	const char *priority = "NONE:+VERS-TLS1.0:+AES-128-CBC:+SHA1:+SIGN-ALL:+COMP-NULL:+RSA";

	gnutls_global_init();

	// 创建socket
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
		perror("socket failed");
		exit(EXIT_FAILURE);
	}

	// 设置socket为非阻塞模式（可选）
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
		perror("setsockopt");
		exit(EXIT_FAILURE);
	}

	address.sin_family = AF_INET;
	address.sin_port = htons(PORT);
	if (inet_pton(AF_INET, HOST, &address.sin_addr) <= 0) {
		perror("invalid IP address");
		exit(EXIT_FAILURE);
	}

	// 连接到服务器
	if (connect(sockfd, (struct sockaddr *)&address, sizeof(address))<0) {
		perror("connect failed");
		exit(EXIT_FAILURE);
	}

	gnutls_init(&session, GNUTLS_CLIENT);
	gnutls_transport_set_int(session, new_socket);
	gnutls_priority_set_direct(session, priority, NULL);

	do {
		ret = gnutls_handshake(session);
		if (ret < 0) {
			fprintf(stderr, "client handshake failed: %s (%d)\n",
				gnutls_strerror(ret), ret);
			exit(EXIT_FAILURE);
		}
	} while (0);

	// 发送消息到服务器
	ret = gnutls_record_send(session, message, strlen(message));
	if (ret <= 0) {
		fprintf(stderr, "gnutls_record_send() failed: %s (%d)\n",
			gnutls_strerror(ret), ret);
		exit(EXIT_FAILURE);
	}
	printf("waiting server message\n");

#if 0
	// 接收来自服务器的消息
	ret = read(sockfd, buffer, sizeof(buffer) - 1);
	if (ret <= 0) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	printf("Received: %s\n", buffer);
#endif

	// 关闭socket
	close(sockfd);

	return 0;
}

int gnutls_cert_recv(const char *prio)
{
	int sockfd, new_socket;
	struct sockaddr_in address;
	int opt = 1;
	char buffer[BUF_SIZE] = {0};
	const char *message = "Hello from TLS client!";
	int ret;
	gnutls_certificate_credentials_t x509_cred;
	gnutls_session_t session;

	gnutls_global_init();
	gnutls_certificate_allocate_credentials(&x509_cred);

	// 创建socket
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
		perror("socket failed");
		exit(EXIT_FAILURE);
	}

	// 设置socket为非阻塞模式（可选）
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
		perror("setsockopt");
		exit(EXIT_FAILURE);
	}

	address.sin_family = AF_INET;
#if 1
	address.sin_port = htons(PORT);
	if (inet_pton(AF_INET, HOST, &address.sin_addr) <= 0) {
		perror("invalid IP address");
		exit(EXIT_FAILURE);
	}
#else
	address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	address.sin_port = htons(PORT);;
#endif

	// 连接到服务器
	if (connect(sockfd, (struct sockaddr *)&address, sizeof(address))<0) {
		perror("connect failed");
		exit(EXIT_FAILURE);
	}

	gnutls_init(&session, GNUTLS_CLIENT);
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
		fprintf(stderr, "fail on client handshake: %s\n",
			gnutls_strerror(ret));
		exit(EXIT_FAILURE);
	}

	printf("waiting server message\n");

	// 接收来自服务器的消息
	{
		char buffer[BUF_SIZE] = {0};
		printf("gnutls recv\n");
		ret = gnutls_record_recv(session, buffer, sizeof(buffer));
		if (ret < 0) {
			fprintf(stderr, "gnutls_record_recv() failed: %s (%d)\n",
				gnutls_strerror(ret), ret);
			ERR_print_errors_fp(stderr);
			exit(EXIT_FAILURE);
		}

		printf("Received: %s\n", buffer);
	}

	gnutls_bye(session, GNUTLS_SHUT_RDWR);
	// 关闭socket
	close(sockfd);

	gnutls_deinit(session);
	gnutls_certificate_free_credentials(x509_cred);
	gnutls_global_deinit();

	return 0;
}
#endif

int main() {
	int ret;

	ret = ssl_recv_fdata();
	//ret = gnutls_cert_recv(PRIO_STRING);
	return ret;
}
