#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "common.h"

#define PORT		8443
#define SERVER_ADDR	"127.0.0.1"

#define BUF_SIZE	1024
#define STOP_MSG	"stop hdr"
#define DATA_MSG	"data hdr"
#define MSG_HDR_LEN	8

#define NSECS_IN_SEC	(1000000000)
#define MSECS_IN_SEC	(1000000)

//#define TIMER_INTERVAL	2
#define TIMER_INTERVAL	10

#define CERTIFICATE_FILE "server.crt"
#define PRIVATE_KEY_FILE "server.key"

//#define ONLY_ONE_MESSAGE	1	// one data message

typedef void (*client_t)(int sockfd, int fd, void *src, size_t len);
typedef void (*server_t)(int sockfd, void *dst, size_t len);
typedef void (*client_ssl_t)(SSL *ssl, int fd, void *src, size_t len);
typedef void (*server_ssl_t)(SSL *ssl, void *dst, size_t len);

typedef struct {
	unsigned char cmd[MSG_HDR_LEN];
	int count;				// sequence number
	int length;				// length of the whole message
	struct timespec start;
	int payload_sz;
} msg_t;

static int stop_flag = 0;
static int msg_count = 0;
static int ssl_ktls_flag = 0;

static int stop_test(int sockfd, struct timespec start)
{
	int ret;
	msg_t msg;

	memcpy(&msg.cmd[0], STOP_MSG, MSG_HDR_LEN);
	msg.count = msg_count;
	msg.length = sizeof(msg);
	memcpy(&msg.start, &start, sizeof(struct timespec));
	ret = send(sockfd, &msg, msg.length, 0);
	if (ret < msg.length)
		perror("stop");
	return ret;
}

static int stop_ssl_test(SSL *ssl, struct timespec start)
{
	int ret;
	msg_t msg;

	memcpy(&msg.cmd[0], STOP_MSG, MSG_HDR_LEN);
	msg.count = msg_count;
	msg.length = sizeof(msg);
	memcpy(&msg.start, &start, sizeof(struct timespec));
	ret = SSL_write(ssl, &msg, msg.length);
	if (ret < msg.length)
		perror("stop");
	return ret;
}

static void timer_handler(int sig, siginfo_t *si, void *uc)
{
	stop_flag = 1;
	(void)sig;
	(void)si;
	(void)uc;
}

static int start_timer(struct timespec *start)
{
	struct sigaction sa;
	sigset_t mask;
	struct sigevent sev;
	timer_t timerid;
	struct itimerspec its = { 0 };

	// establish handler for timer signal
	sa.sa_flags = SA_SIGINFO;
	sa.sa_sigaction = timer_handler;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGRTMIN, &sa, NULL) == -1) {
		perror("sigaction");
		return -errno;
	}

	// block timer signal temporarily
	sigemptyset(&mask);
	sigaddset(&mask, SIGRTMIN);
	if (sigprocmask(SIG_SETMASK, &mask, NULL) == -1) {
		perror("block timer signal");
		return -errno;
	}

	// create timer
	sev.sigev_notify = SIGEV_SIGNAL;
	sev.sigev_signo = SIGRTMIN;
	sev.sigev_value.sival_ptr = &timerid;
	if (timer_create(CLOCK_REALTIME, &sev, &timerid) == -1) {
		perror("timer");
		return -errno;
	}

	// record start time
	if (clock_gettime(CLOCK_REALTIME, start) < 0) {
		perror("get time");
		return -errno;
	}

	// start the timer
	its.it_value.tv_sec = TIMER_INTERVAL;
	if (timer_settime(timerid, 0, &its, NULL) == -1) {
		perror("settime");
		return -errno;
	}

	// unblock timer signal
	if (sigprocmask(SIG_UNBLOCK, &mask, NULL) == -1) {
		perror("unblock timer signal");
		return -errno;
	}
	return 0;
}

int get_time_end(struct timespec *end)
{
	if (clock_gettime(CLOCK_REALTIME, end) < 0) {
		perror("get time");
		return -errno;
	}
	return 0;
}

void get_time_diff(struct timespec start, struct timespec end,
		   struct timespec *res)
{
	if (end.tv_nsec > start.tv_nsec) {
		res->tv_nsec = end.tv_nsec - start.tv_nsec;
		res->tv_sec = end.tv_sec - start.tv_sec;
	} else {
		res->tv_nsec = NSECS_IN_SEC + end.tv_nsec - start.tv_nsec;
		res->tv_sec = end.tv_sec - start.tv_sec - 1;
	}
}

void calc_perf(struct timespec res, int count, int data_sz)
{
	double total_sz;
	double total_msec;		// count in micro seconds

	total_sz = (double)data_sz * (double)count;
	total_msec = res.tv_sec * MSECS_IN_SEC + res.tv_nsec / 1000;
	printf("For %d-byte payload size, the bandwith is %.2fMB/s with %d count.\n",
	       data_sz, total_sz / total_msec, count);
}

static void set_message_header(void *src, size_t len, int frame_num)
{
	msg_t *msg = (msg_t *)src;

	memcpy(&msg->cmd[0], DATA_MSG, MSG_HDR_LEN);
	msg->count = frame_num;
	msg->length = len + sizeof(msg_t);
	msg->payload_sz = len;
}

int client_socket(void)
{
	struct sockaddr_in server_addr = { 0 };
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);

	if (sockfd < 0) {
		perror("fail to open client socket");
		exit(EXIT_FAILURE);
	}

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(PORT);

	if (inet_pton(AF_INET, SERVER_ADDR, &server_addr.sin_addr) <= 0) {
		perror("invalid address");
		goto out;
	}
	if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
		perror("connect failed");
		goto out;
	}
	return sockfd;
out:
	close(sockfd);
	exit(EXIT_FAILURE);
}

int server_socket(void)
{
	struct sockaddr_in server_addr = { 0 };
	int server_fd = socket(AF_INET, SOCK_STREAM, 0);
	int optval = 1;

	if (server_fd < 0) {
		perror("fail to open server socket");
		exit(EXIT_FAILURE);
	}

	// optval = 1, make address reusable
	if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval))) {
		perror("fail to set server address reuse");
		goto out;
	}

	server_addr.sin_family = AF_INET;
	//server_addr.sin_addr.s_addr = INADDR_ANY;
	server_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	server_addr.sin_port = htons(PORT);

	if (bind(server_fd, (const struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
		perror("bind failed");
		goto out;
	}

	if (listen(server_fd, 1) < 0) {
		perror("listen");
		goto out;
	}

	return server_fd;
out:
	close(server_fd);
	exit(EXIT_FAILURE);
}

// send one message
void client_sock_send(int sockfd, int fd, void *src, size_t len)
{
	int ret;

	ret = send(sockfd, src, len + sizeof(msg_t), 0);
	if (ret != (int)(len + sizeof(msg_t))) {
		printf("#%s, ret:%d, len:%ld, sizeof(msg_t):%ld, msg_count:%d\n", __func__, ret, len, sizeof(msg_t), msg_count);
		perror("send");
		exit(EXIT_FAILURE);
	}
	(void)fd;
}

// split to send message header and file data
void client_sock_send_fdata(int sockfd, int fd, void *src, size_t len)
{
	size_t res;
	int ret;

	ret = send(sockfd, src, sizeof(msg_t), 0);
	if (ret != (int)sizeof(msg_t)) {
		perror("send");
		exit(EXIT_FAILURE);
	}
	lseek(fd, 0, SEEK_SET);
	res = read(fd, src + sizeof(msg_t), len);
	if (res != len) {
		perror("read too less");
		exit(EXIT_FAILURE);
	}
	ret = send(sockfd, src + sizeof(msg_t), len, 0);
	if (ret != (int)len) {
		perror("send");
		exit(EXIT_FAILURE);
	}
}

// split to send message header and file
void client_sock_send_file(int sockfd, int fd, void *src, size_t len)
{
	size_t res;
	off_t offset = 0;
	int ret;

	ret = send(sockfd, src, sizeof(msg_t), 0);
	if (ret != (int)sizeof(msg_t)) {
		perror("send");
		exit(EXIT_FAILURE);
	}
	res = sendfile(sockfd, fd, &offset, len);
	if (res != len) {
		perror("sendfile");
		exit(EXIT_FAILURE);
	}
}

void client_ssl_send_fdata(SSL *ssl, int fd, void *src, size_t len)
{
	size_t res;
	int ret;

	ret = SSL_write(ssl, src, sizeof(msg_t));
	if (ret != (int)sizeof(msg_t)) {
		perror("send hdr");
		exit(EXIT_FAILURE);
	}
	lseek(fd, 0, SEEK_SET);
	res = read(fd, src + sizeof(msg_t), len);
	if (res != len) {
		perror("read too less");
		exit(EXIT_FAILURE);
	}
	ret = SSL_write(ssl, src + sizeof(msg_t), len);
	if (ret != (int)len) {
		perror("send data");
		exit(EXIT_FAILURE);
	}
}

void client_ssl_send_file(SSL *ssl, int fd, void *src, size_t len)
{
	int ret;

	ret = SSL_write(ssl, src, sizeof(msg_t));
	if (ret != (int)sizeof(msg_t)) {
		perror("send hdr");
		exit(EXIT_FAILURE);
	}
	lseek(fd, 0, SEEK_SET);
	ret = SSL_sendfile(ssl, fd, 0, len, 0);
	if (ret != (int)len) {
		printf("ret:%d\n", ret);
		perror("send file");
		exit(EXIT_FAILURE);
	}
}

// receive one message
void server_sock_recv(int fd, void *dst, size_t len)
{
	int ret;
	int new_frame = 1;
	msg_t *msg;
	size_t left = len + sizeof(msg_t);

	while (1) {
		ret = read(fd, dst, left);
		if (ret < 0) {
			perror("recv");
			exit(EXIT_FAILURE);
		} else if (ret > (int)left) {
			perror("recv too much");
			exit(EXIT_FAILURE);
		} else if (ret == 0) {
			perror("recv none");
			exit(EXIT_FAILURE);
		}
		left = left - ret;
		if (!left)
			return;
		if (new_frame) {
			msg = (msg_t *)dst;
			if (!memcmp(&msg->cmd[0], DATA_MSG, MSG_HDR_LEN))
				new_frame = 0;
			else if (!memcmp(&msg->cmd[0], STOP_MSG, MSG_HDR_LEN)) {
				// exit directly
				return;
			}
			if (left)
				continue;
		}
	};
}

void server_ssl_recv(SSL *ssl, void *dst, size_t len)
{
	int ret;
	int new_frame = 1;
	msg_t *msg;
	size_t left = len + sizeof(msg_t);
	size_t offset = 0;

	while (1) {
		ret = SSL_read(ssl, dst + offset, left);
		if (ret < 0) {
			perror("recv");
			exit(EXIT_FAILURE);
		} else if (ret > (int)left) {
			perror("recv too much");
			exit(EXIT_FAILURE);
		} else if (ret == 0) {
			perror("recv none");
			exit(EXIT_FAILURE);
		}
		offset += ret;
		left = left - ret;
		if (!left)
			return;
		if (new_frame) {
			msg = (msg_t *)dst;
			if (!memcmp(&msg->cmd[0], DATA_MSG, MSG_HDR_LEN))
				new_frame = 0;
			else if (!memcmp(&msg->cmd[0], STOP_MSG, MSG_HDR_LEN)) {
				// exit directly
				return;
			}
			if (left)
				continue;
		}
	};
}

static void start_sock(client_t client_send, server_t server_recv, int file_fd,
		       void *src, void *dst, size_t len)
{
	int fd[2];
	int sockfd;
	pid_t pid;
	struct timespec start, end, diff;
	int cnt = 0;
	msg_t *msg;

	fd[1] = server_socket();
	pid = fork();
	if (pid < 0) {
		perror("fork");
		exit(1);
	}

	if (pid) {
		// parent
		fd[0] = client_socket();	// create client sockfd
		if (start_timer(&start) < 0) {
			close(fd[0]);
			exit(EXIT_FAILURE);
		}

		memset(src, 0, len + sizeof(msg_t));
		set_message_header(src, len, msg_count);
		/*
		printf("src:\n");
		dump_buffer_hex(src, len);
		*/
#ifdef ONLY_ONE_MESSAGE
		client_send(fd[0], file_fd, src, len);
		msg_count++;
#else
		do {
			client_send(fd[0], file_fd, src, len);
			msg_count++;
		} while (stop_flag == 0);
#endif
		stop_test(fd[0], start);

		close(fd[0]);
		close(fd[1]);
		waitpid(-1, NULL, 0);
	} else {
		// child
		sockfd = accept(fd[1], NULL, NULL);
		if (sockfd < 0) {
			perror("accept");
			return;
		}

#ifdef ONLY_ONE_MESSAGE
		server_recv(sockfd, dst, len);
		printf("dst:\n");
		dump_buffer_hex(dst, len + sizeof(msg_t));

		msg = (msg_t *)dst;
		if (memcmp(msg->cmd, STOP_MSG, MSG_HDR_LEN) == 0) {
			if (cnt > msg->count) {
				perror("wrong count");
				exit(EXIT_FAILURE);
			}
		}
		(void)end;
		(void)diff;
#else
		while (1) {
			memset(dst, 0, len + sizeof(msg_t));
			server_recv(sockfd, dst, len);

			msg = (msg_t *)dst;
			if (memcmp(msg->cmd, STOP_MSG, MSG_HDR_LEN) == 0) {
				if (cnt > msg->count) {
					perror("wrong count");
					exit(EXIT_FAILURE);
				} else if (cnt == msg->count)
					break;
			}
			cnt++;
		}

		// msg->count is counted from 0. So stop message is not
		// recorded in msg->count.
		if (cnt == msg->count) {
			get_time_end(&end);
			memcpy(&start, &msg->start, sizeof(start));
			get_time_diff(start, end, &diff);
			// At here, stop message is received.
			// msg->length indicates the length of stop message,
			// not data message.
			// Only calculate data payload size.
			calc_perf(diff, msg->count, len);
		}
#endif
		close(sockfd);
		close(fd[1]);
	}
}

static void start_ssl(client_ssl_t client_send, server_ssl_t server_recv,
		      int file_fd, void *src, void *dst, size_t len)
{
	int fd[2];
	int sockfd;
	pid_t pid;
	struct timespec start, end, diff;
	int cnt = 0;
	msg_t *msg;

	fd[1] = server_socket();
	pid = fork();
	if (pid < 0) {
		perror("fork");
		exit(1);
	}

	if (pid) {
		// parent
		SSL_CTX *ctx;
		SSL *ssl;
		long verify_result;
		int opt = 1;

		SSL_library_init();
		OpenSSL_add_all_algorithms();
		SSL_load_error_strings();

		ctx = SSL_CTX_new(TLSv1_2_client_method());
		if (ctx == NULL) {
			perror("ctx");
			exit(EXIT_FAILURE);
		}
		if (SSL_CTX_load_verify_locations(ctx, CERTIFICATE_FILE, NULL)
		    != 1) {
			perror("CA failed");
			exit(EXIT_FAILURE);
		}
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

		fd[0] = client_socket();	// create client ssl
		if (setsockopt(fd[0], SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
			perror("setsockopt");
			exit(EXIT_FAILURE);
		}

		ssl = SSL_new(ctx);
		SSL_set_fd(ssl, fd[0]);		// bind ssl with sock
		if (ssl_ktls_flag)
			SSL_set_options(ssl, SSL_OP_ENABLE_KTLS);

		if (SSL_connect(ssl) == -1) {
			perror("ssl connect");
			exit(EXIT_FAILURE);
		}

		verify_result = SSL_get_verify_result(ssl);
		if (verify_result != X509_V_OK) {
			perror("SSL failed");
			exit(EXIT_FAILURE);
		}

		printf("ktls send:%ld, ktls recv:%ld\n",
			BIO_get_ktls_send(SSL_get_wbio(ssl)),
			BIO_get_ktls_recv(SSL_get_rbio(ssl)));

		if (start_timer(&start) < 0) {
			close(fd[0]);
			exit(EXIT_FAILURE);
		}

		memset(src, 0, len + sizeof(msg_t));
		set_message_header(src, len, msg_count);
#ifdef ONLY_ONE_MESSAGE
		client_send(ssl, file_fd, src, len);
		msg_count++;
#else
		do {
			client_send(ssl, file_fd, src, len);
			msg_count++;
		} while (stop_flag == 0);
#endif
		stop_ssl_test(ssl, start);

		SSL_shutdown(ssl);
		SSL_free(ssl);
		SSL_CTX_free(ctx);

		close(fd[0]);
		close(fd[1]);
		waitpid(-1, NULL, 0);
	} else {
		// child
		SSL_CTX *ctx;
		SSL *ssl;

		OpenSSL_add_all_algorithms();
		SSL_load_error_strings();

		ctx = SSL_CTX_new(TLSv1_2_server_method());
		if (ctx == NULL) {
			perror("ssl ctx");
			exit(EXIT_FAILURE);
		}

		if (SSL_CTX_use_certificate_file(ctx, CERTIFICATE_FILE,
						 SSL_FILETYPE_PEM) <= 0) {
			perror("ssl cert");
			exit(EXIT_FAILURE);
		}

		if (SSL_CTX_use_PrivateKey_file(ctx, PRIVATE_KEY_FILE,
						SSL_FILETYPE_PEM) <= 0) {
			perror("ssl key");
			exit(EXIT_FAILURE);
		}

		if (!SSL_CTX_check_private_key(ctx)) {
			fprintf(stderr, "Private key does not match the public certificate\n");
			exit(EXIT_FAILURE);
		}

		sockfd = accept(fd[1], NULL, NULL);
		if (sockfd < 0) {
			perror("accept");
			return;
		}

		ssl = SSL_new(ctx);
		SSL_set_fd(ssl, sockfd);

		if (SSL_accept(ssl) <= 0) {
			perror("ssl accept");
			exit(EXIT_FAILURE);
		}

#ifdef ONLY_ONE_MESSAGE
		server_recv(ssl, dst, len);
		printf("dst:\n");
		dump_buffer_hex(dst, len + sizeof(msg_t));

		msg = (msg_t *)dst;
		if (memcmp(msg->cmd, STOP_MSG, MSG_HDR_LEN) == 0) {
			if (cnt > msg->count) {
				perror("wrong count");
				exit(EXIT_FAILURE);
			}
		}
		(void)end;
		(void)diff;
#else
		while (1) {
			memset(dst, 0, len + sizeof(msg_t));
			server_recv(ssl, dst, len);

			msg = (msg_t *)dst;
			if (memcmp(msg->cmd, STOP_MSG, MSG_HDR_LEN) == 0) {
				if (cnt > msg->count) {
					perror("wrong count");
					exit(EXIT_FAILURE);
				} else if (cnt == msg->count)
					break;
			}
			cnt++;
		}

		// msg->count is counted from 0. So stop message is not
		// recorded in msg->count.
		if (cnt == msg->count) {
			get_time_end(&end);
			memcpy(&start, &msg->start, sizeof(start));
			get_time_diff(start, end, &diff);
			// At here, stop message is received.
			// msg->length indicates the length of stop message,
			// not data message.
			// Only calculate data payload size.
			calc_perf(diff, msg->count, len);
		}
#endif
		SSL_shutdown(ssl);
		SSL_free(ssl);
		SSL_CTX_free(ctx);

		close(sockfd);
		close(fd[1]);
		exit(0);
	}
}

int do_sock_send(size_t len)
{
	size_t msg_sz;
	unsigned char *src, *dst;
	int ret;

	msg_sz = len + sizeof(msg_t);
	src = malloc(msg_sz);
	if (src == NULL) {
		perror("no memory for src");
		ret = -ENOMEM;
		goto out;
	}
	dst = malloc(msg_sz);
	if (dst == NULL) {
		perror("no memory for dst");
		ret = -ENOMEM;
		goto out_dst;
	}
	if (RAND_bytes(src, msg_sz) <= 0) {
		perror("rand");
		ret = -EINVAL;
		goto out_rnd;
	}
	memset(dst, 0, msg_sz);
	// fd isn't used at here
	start_sock(client_sock_send, server_sock_recv, -1, src, dst, len);
	free(dst);
	free(src);
	return 0;
out_rnd:
	free(dst);
out_dst:
	free(src);
out:
	return ret;
}

int do_sock_fdata(char *name)
{
	unsigned char *src, *dst;
	size_t msg_sz, len;
	int fd;
	int ret;
	struct stat st;

	fd = open(name, O_RDONLY);
	if (fd < 0) {
		perror("open");
		exit(EXIT_FAILURE);
	}

	if (fstat(fd, &st) < 0) {
		perror("fstat");
		exit(EXIT_FAILURE);
	}
	len = st.st_size;
	printf("Test to send file with %ld size.\n", len);

	msg_sz = sizeof(msg_t) + len;
	src = malloc(msg_sz);
	if (src == NULL) {
		perror("no memory for src");
		ret = -ENOMEM;
		goto out;
	}
	dst = malloc(msg_sz);
	if (dst == NULL) {
		perror("no memory for dst");
		ret = -ENOMEM;
		goto out_dst;
	}
	memset(dst, 0, msg_sz);
	start_sock(client_sock_send_fdata, server_sock_recv, fd, src, dst, len);
	close(fd);
	free(dst);
	free(src);
	return 0;
out_dst:
	free(src);
out:
	return ret;
}

int do_sock_file(char *name)
{
	unsigned char *src, *dst;
	size_t msg_sz, len;
	int fd;
	int ret;
	struct stat st;

	fd = open(name, O_RDONLY);
	if (fd < 0) {
		perror("open");
		exit(EXIT_FAILURE);
	}

	if (fstat(fd, &st) < 0) {
		perror("fstat");
		exit(EXIT_FAILURE);
	}
	len = st.st_size;
	printf("Test to send file with %ld size.\n", len);

	msg_sz = sizeof(msg_t) + len;
	src = malloc(msg_sz);
	if (src == NULL) {
		perror("no memory for src");
		ret = -ENOMEM;
		goto out;
	}
	dst = malloc(msg_sz);
	if (dst == NULL) {
		perror("no memory for dst");
		ret = -ENOMEM;
		goto out_dst;
	}
	memset(dst, 0, msg_sz);
	start_sock(client_sock_send_file, server_sock_recv, fd, src, dst, len);
	close(fd);
	free(dst);
	free(src);
	return 0;
out_dst:
	free(src);
out:
	return ret;
}

int do_ssl_fdata(char *name)
{
	unsigned char *src, *dst;
	size_t msg_sz, len;
	int fd;
	int ret;
	struct stat st;

	fd = open(name, O_RDONLY);
	if (fd < 0) {
		perror("open");
		exit(EXIT_FAILURE);
	}

	if (fstat(fd, &st) < 0) {
		perror("fstat");
		exit(EXIT_FAILURE);
	}
	len = st.st_size;
	printf("Test to send file with %ld size.\n", len);

	msg_sz = sizeof(msg_t) + len;
	src = malloc(msg_sz);
	if (src == NULL) {
		perror("no memory for src");
		ret = -ENOMEM;
		goto out;
	}
	dst = malloc(msg_sz);
	if (dst == NULL) {
		perror("no memory for dst");
		ret = -ENOMEM;
		goto out_dst;
	}
	memset(dst, 0, msg_sz);
	start_ssl(client_ssl_send_fdata, server_ssl_recv, fd, src, dst, len);
	close(fd);
	free(dst);
	free(src);
	return 0;
out_dst:
	free(src);
out:
	return ret;
}

int do_ssl_file(char *name)
{
	unsigned char *src, *dst;
	size_t msg_sz, len;
	int fd;
	int ret;
	struct stat st;

	ssl_ktls_flag = 1;
	fd = open(name, O_RDONLY);
	if (fd < 0) {
		perror("open");
		exit(EXIT_FAILURE);
	}

	if (fstat(fd, &st) < 0) {
		perror("fstat");
		exit(EXIT_FAILURE);
	}
	len = st.st_size;
	printf("Test to send file with %ld size.\n", len);

	msg_sz = sizeof(msg_t) + len;
	src = malloc(msg_sz);
	if (src == NULL) {
		perror("no memory for src");
		ret = -ENOMEM;
		goto out;
	}
	dst = malloc(msg_sz);
	if (dst == NULL) {
		perror("no memory for dst");
		ret = -ENOMEM;
		goto out_dst;
	}
	memset(dst, 0, msg_sz);
	start_ssl(client_ssl_send_file, server_ssl_recv, fd, src, dst, len);
	close(fd);
	free(dst);
	free(src);
	return 0;
out_dst:
	free(src);
out:
	return ret;
}

int main(void)
{
	printf("sock send case:\n");
	do_sock_send(128);
	printf("read file & send over socket:\n");
	do_sock_fdata("data_128.bin");
	printf("sendfile:\n");
	do_sock_file("data_128.bin");
	printf("read file & send over SSL:\n");
	do_ssl_fdata("data_128.bin");
	/*
	printf("sendfile over SSL:\n");
	do_ssl_file("data_128.bin");
	*/
	return 0;
}
