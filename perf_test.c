#include <arpa/inet.h>
#include <errno.h>
#include <openssl/rand.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
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

#define TIMER_INTERVAL	2
//#define TIMER_INTERVAL	180

typedef void (*client_t)(int fd, void *src, size_t len);
typedef void (*server_t)(int fd, void *dst, size_t len);

typedef struct {
	unsigned char cmd[MSG_HDR_LEN];
	int count;				// sequence number
	int length;				// length of the whole message
	struct timespec start;
} msg_t;

static int memcmp_flag = 1;
static int stop_flag = 0;
static int msg_count = 0;

static int stop_test(int sockfd, struct timespec start)
{
	int ret;
	int len;
	msg_t msg;

	memcpy(&msg.cmd[0], STOP_MSG, MSG_HDR_LEN);
	msg.count = msg_count;
	memcpy(&msg.start, &start, sizeof(struct timespec));
	printf("send out stop message with %d count\n", msg_count);
	len = sizeof(msg);
	ret = send(sockfd, &msg, len, 0);
	if (ret < len)
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

static int get_time_end(struct timespec *end)
{
	if (clock_gettime(CLOCK_REALTIME, end) < 0) {
		perror("get time");
		return -errno;
	}
	return 0;
}

static void get_time_diff(struct timespec start, struct timespec end,
			  struct timespec *res)
{
	if (end.tv_nsec > start.tv_nsec) {
		res->tv_nsec = end.tv_nsec - start.tv_nsec;
		res->tv_sec = end.tv_sec - start.tv_sec;
	} else {
		res->tv_nsec = 1000000000 + end.tv_nsec - start.tv_nsec;
		res->tv_sec = end.tv_sec - start.tv_sec - 1;
	}
}

static void set_message_header(void *src, size_t len, int frame_num)
{
	msg_t *msg = (msg_t *)src;

	memcpy(&msg->cmd[0], DATA_MSG, MSG_HDR_LEN);
	msg->count = frame_num;
	msg->length = len;
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
	printf("client sock:%d\n", sockfd);
	return sockfd;
out:
	close(sockfd);
	exit(EXIT_FAILURE);
}

int server_socket(void)
{
	struct sockaddr_in server_addr = { 0 };
	int server_fd = socket(AF_INET, SOCK_STREAM, 0);

	if (server_fd < 0) {
		perror("fail to open server socket");
		exit(EXIT_FAILURE);
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
void client_sock_send(int fd, void *src, size_t len)
{
	int ret;

	ret = send(fd, src, len, 0);
	if ((ret <= 0) || (ret != (int)len)) {
		printf("#%s, ret:%d, len:%d, msg_count:%d\n", __func__, ret, len, msg_count);
		perror("send");
		//exit(EXIT_FAILURE);
	}
}

// receive one message
void server_sock_recv(int fd, void *dst, size_t len)
{
	int ret;
	int new_frame = 1;
	msg_t *msg;
	size_t left = len;

	while (1) {
		ret = read(fd, dst, left);
		if (ret < 0) {
			perror("recv");
			exit(EXIT_FAILURE);
		} else if (ret > left) {
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

static void start(client_t client_send, server_t server_recv, void *src,
		  void *dst, size_t len)
{
	int fd[2];
	int sockfd;
	pid_t pid;
	struct timespec start, end, diff;
	int cnt = 0;
	msg_t *msg;
	int ret;
	int optval;
	socklen_t optlen = sizeof(optval);

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

		set_message_header(src, len, msg_count);
		/*
		printf("src:\n");
		dump_buffer_hex(src, len);
		*/
		do {
			client_send(fd[0], src, len);
			msg_count++;
		} while (stop_flag == 0);
		stop_test(fd[0], start);

		close(fd[0]);
		printf("send %d messages\n", msg_count);
		waitpid(-1, NULL, 0);
	} else {
		// child
		sockfd = accept(fd[1], NULL, NULL);
		if (sockfd < 0) {
			perror("accept");
			return;
		}

		while (1) {
			server_recv(sockfd, dst, len);
			//printf("dst:\n");
			//dump_buffer_hex(dst, len);

			msg = (msg_t *)dst;
			if (memcmp(msg->cmd, STOP_MSG, MSG_HDR_LEN) == 0) {
				if (cnt > msg->count) {
					perror("wrong count");
					exit(EXIT_FAILURE);
#if 1
				} else if (cnt == msg->count)
					break;
#else
				}
#endif
			}
			cnt++;
		}
		printf("cnt:%d, msg->count:%d\n", cnt, msg->count);
		if (cnt == msg->count) {
			get_time_end(&end);
			memcpy(&start, &msg->start, sizeof(start));
			get_time_diff(start, end, &diff);
			printf("recv count %d\n", msg->count);
			printf("interval sec %ld\n", diff.tv_sec);
		}
		close(sockfd);
		close(fd[1]);
		exit(0);
	}
}

int main(void)
{
	size_t len = 128;
	unsigned char *src, *dst;
	int ret;

	src = malloc(len);
	if (src == NULL) {
		perror("no memory for src");
		ret = -ENOMEM;
		goto out;
	}
	dst = malloc(len);
	if (dst == NULL) {
		perror("no memory for dst");
		ret = -ENOMEM;
		goto out_dst;
	}
	if (RAND_bytes(src, len) <= 0) {
		perror("rand");
		ret = -EINVAL;
		goto out_rnd;
	}
	memset(dst, 0, len);
	start(client_sock_send, server_sock_recv, src, dst, len);
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
