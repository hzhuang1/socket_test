#include <assert.h>
#include <fcntl.h>
#include <gnutls/gnutls.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

//#include "cert.h"
#include "common.h"

#define fail(...)                             \
        {                                     \
                fprintf(stderr, __VA_ARGS__); \
                exit(1);                      \
        }

#define success(...)			\
	{				\
		printf(__VA_ARGS__);	\
	}

#define check_wait_status(...)	{ }

static void terminate(void);

/* This program tests whether our pull timeout function is called
 * during handshake.
 */

static void server_log_func(int level, const char *str)
{
	//  fprintf (stderr, "server|<%d>| %s", level, str);
}

static void client_log_func(int level, const char *str)
{
	fprintf(stderr, "client|<%d>| %s", level, str);
}

static unsigned char server_cert_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIICVjCCAcGgAwIBAgIERiYdMTALBgkqhkiG9w0BAQUwGTEXMBUGA1UEAxMOR251\n"
	"VExTIHRlc3QgQ0EwHhcNMDcwNDE4MTMyOTIxWhcNMDgwNDE3MTMyOTIxWjA3MRsw\n"
	"GQYDVQQKExJHbnVUTFMgdGVzdCBzZXJ2ZXIxGDAWBgNVBAMTD3Rlc3QuZ251dGxz\n"
	"Lm9yZzCBnDALBgkqhkiG9w0BAQEDgYwAMIGIAoGA17pcr6MM8C6pJ1aqU46o63+B\n"
	"dUxrmL5K6rce+EvDasTaDQC46kwTHzYWk95y78akXrJutsoKiFV1kJbtple8DDt2\n"
	"DZcevensf9Op7PuFZKBroEjOd35znDET/z3IrqVgbtm2jFqab7a+n2q9p/CgMyf1\n"
	"tx2S5Zacc1LWn9bIjrECAwEAAaOBkzCBkDAMBgNVHRMBAf8EAjAAMBoGA1UdEQQT\n"
	"MBGCD3Rlc3QuZ251dGxzLm9yZzATBgNVHSUEDDAKBggrBgEFBQcDATAPBgNVHQ8B\n"
	"Af8EBQMDB6AAMB0GA1UdDgQWBBTrx0Vu5fglyoyNgw106YbU3VW0dTAfBgNVHSME\n"
	"GDAWgBTpPBz7rZJu5gakViyi4cBTJ8jylTALBgkqhkiG9w0BAQUDgYEAaFEPTt+7\n"
	"bzvBuOf7+QmeQcn29kT6Bsyh1RHJXf8KTk5QRfwp6ogbp94JQWcNQ/S7YDFHglD1\n"
	"AwUNBRXwd3riUsMnsxgeSDxYBfJYbDLeohNBsqaPDJb7XailWbMQKfAbFQ8cnOxg\n"
	"rOKLUQRWJ0K3HyXRMhbqjdLIaQiCvQLuizo=\n"
	"-----END CERTIFICATE-----\n";

const gnutls_datum_t server_cert = { server_cert_pem, sizeof(server_cert_pem) };

static unsigned char server_key_pem[] =
	"-----BEGIN RSA PRIVATE KEY-----\n"
	"MIICXAIBAAKBgQDXulyvowzwLqknVqpTjqjrf4F1TGuYvkrqtx74S8NqxNoNALjq\n"
	"TBMfNhaT3nLvxqResm62ygqIVXWQlu2mV7wMO3YNlx696ex/06ns+4VkoGugSM53\n"
	"fnOcMRP/PciupWBu2baMWppvtr6far2n8KAzJ/W3HZLllpxzUtaf1siOsQIDAQAB\n"
	"AoGAYAFyKkAYC/PYF8e7+X+tsVCHXppp8AoP8TEZuUqOZz/AArVlle/ROrypg5kl\n"
	"8YunrvUdzH9R/KZ7saNZlAPLjZyFG9beL/am6Ai7q7Ma5HMqjGU8kTEGwD7K+lbG\n"
	"iomokKMOl+kkbY/2sI5Czmbm+/PqLXOjtVc5RAsdbgvtmvkCQQDdV5QuU8jap8Hs\n"
	"Eodv/tLJ2z4+SKCV2k/7FXSKWe0vlrq0cl2qZfoTUYRnKRBcWxc9o92DxK44wgPi\n"
	"oMQS+O7fAkEA+YG+K9e60sj1K4NYbMPAbYILbZxORDecvP8lcphvwkOVUqbmxOGh\n"
	"XRmTZUuhBrJhJKKf6u7gf3KWlPl6ShKEbwJASC118cF6nurTjuLf7YKARDjNTEws\n"
	"qZEeQbdWYINAmCMj0RH2P0mvybrsXSOD5UoDAyO7aWuqkHGcCLv6FGG+qwJAOVqq\n"
	"tXdUucl6GjOKKw5geIvRRrQMhb/m5scb+5iw8A4LEEHPgGiBaF5NtJZLALgWfo5n\n"
	"hmC8+G8F0F78znQtPwJBANexu+Tg5KfOnzSILJMo3oXiXhf5PqXIDmbN0BKyCKAQ\n"
	"LfkcEcUbVfmDaHpvzwY9VEaoMOKVLitETXdNSxVpvWM=\n"
	"-----END RSA PRIVATE KEY-----\n";

const gnutls_datum_t server_key = { server_key_pem, sizeof(server_key_pem) };

/* A very basic TLS client, with anonymous authentication.
*/

#define MAX_BUF 2048
static const char *g_msg = "";

int debug = 1;

#define BERKLEY_SOCKET

static ssize_t my_pull(gnutls_transport_ptr_t tr, void *data, size_t len)
{
	return recv((long)tr, data, len, 0);
}

static ssize_t my_push(gnutls_transport_ptr_t tr, const void *data, size_t len)
{
	return send((long)tr, data, len, 0);
}

static int my_pull_timeout(gnutls_transport_ptr_t tr, unsigned ms)
{
	if (ms != 0) {
		fail("pull timeout was called: %s!\n", g_msg);
		exit(1);
	}
	return 1;
}

static void client(int fd, const char *msg, const char *prio, unsigned expl)
{
	int ret;
	gnutls_anon_client_credentials_t anoncred;
	gnutls_certificate_credentials_t x509_cred;
	gnutls_session_t session;
	/* Need to enable anonymous KX specifically. */
	char buffer[MAX_BUF + 1];

	gnutls_global_init();
	g_msg = msg;

	if (debug) {
		gnutls_global_set_log_function(client_log_func);
		gnutls_global_set_log_level(7);
	}

	/* set socket to non-blocking */
	ret = fcntl(fd, F_GETFL, 0);
	fcntl(fd, F_SETFL, ret | O_NONBLOCK);

	gnutls_anon_allocate_client_credentials(&anoncred);
	gnutls_certificate_allocate_credentials(&x509_cred);

	/* Initialize TLS session
	*/
	gnutls_init(&session, GNUTLS_CLIENT | expl);

	/* Use default priorities */
	ret = gnutls_priority_set_direct(session, prio, NULL);
	if (ret < 0) {
		fail("error in setting priority\n");
		exit(1);
	}

	/* put the anonymous credentials to the current session
	*/
	gnutls_credentials_set(session, GNUTLS_CRD_ANON, anoncred);
	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, x509_cred);

	gnutls_transport_set_int(session, fd);
#ifndef BERKLEY_SOCKET
	gnutls_transport_set_push_function(session, my_push);
	gnutls_transport_set_pull_function(session, my_pull);
	gnutls_transport_set_pull_timeout_function(session, my_pull_timeout);
#endif

	/* Perform the TLS handshake
	*/
	do {
		ret = gnutls_handshake(session);
	} while (ret < 0 && gnutls_error_is_fatal(ret) == 0);

	if (ret < 0) {
		fail("client: Handshake failed\n");
		gnutls_perror(ret);
		exit(1);
	} else {
		if (debug)
			success("client: Handshake was completed\n");
	}

	if (debug)
		success("client: TLS version is: %s\n",
				gnutls_protocol_get_name(
					gnutls_protocol_get_version(session)));

#ifdef BERKLEY_SOCKET
	printf("#%s, %d\n", __func__, __LINE__);
	ret = recv(fd, buffer, sizeof(buffer) - 1, 0);
	if (ret < 0) {
		perror("recv");
		goto end;
	}
	printf("recv %d bytes\n", ret);
	dump_buffer_hex(buffer, ret);
end:
#endif
	close(fd);

	gnutls_deinit(session);

	gnutls_anon_free_client_credentials(anoncred);
	gnutls_certificate_free_credentials(x509_cred);

	gnutls_global_deinit();
}

/* These are global */
pid_t child;

static void terminate(void)
{
	assert(child);
	kill(child, SIGTERM);
	exit(1);
}

static void server(int fd, const char *prio, unsigned expl)
{
	int ret;
	char buffer[MAX_BUF + 1];
	gnutls_session_t session;
	gnutls_anon_server_credentials_t anoncred;
	gnutls_certificate_credentials_t x509_cred;

	/* this must be called once in the program
	*/
	gnutls_global_init();
	memset(buffer, 0, sizeof(buffer));

	if (debug) {
		gnutls_global_set_log_function(server_log_func);
		gnutls_global_set_log_level(4711);
	}

	gnutls_certificate_allocate_credentials(&x509_cred);
	gnutls_certificate_set_x509_key_mem(x509_cred, &server_cert,
			&server_key, GNUTLS_X509_FMT_PEM);

	gnutls_anon_allocate_server_credentials(&anoncred);

	if (expl & GNUTLS_DATAGRAM)
		gnutls_init(&session, GNUTLS_SERVER | GNUTLS_DATAGRAM);
	else
		gnutls_init(&session, GNUTLS_SERVER);

	/* avoid calling all the priority functions, since the defaults
	 * are adequate.
	 */
	gnutls_priority_set_direct(session, prio, NULL);

	gnutls_credentials_set(session, GNUTLS_CRD_ANON, anoncred);
	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, x509_cred);

	gnutls_transport_set_int(session, fd);

	do {
		ret = gnutls_handshake(session);
	} while (ret < 0 && gnutls_error_is_fatal(ret) == 0);
	if (ret < 0) {
		close(fd);
		gnutls_deinit(session);
		fail("server: Handshake has failed (%s)\n\n",
				gnutls_strerror(ret));
		terminate();
	}
	if (debug)
		success("server: Handshake was completed\n");

	if (debug)
		success("server: TLS version is: %s\n",
				gnutls_protocol_get_name(
					gnutls_protocol_get_version(session)));

#ifdef BERKLEY_SOCKET
	strcpy(buffer, "hello world");
	ret = send(fd, buffer, strlen("hello world"), 0);
	if (ret < 0)
		fail("error sending hello\n");
	printf("send %d bytes\n", ret);
#endif
	close(fd);
	gnutls_deinit(session);

	gnutls_anon_free_server_credentials(anoncred);
	gnutls_certificate_free_credentials(x509_cred);

	gnutls_global_deinit();

	if (debug)
		success("server: finished\n");
}

static void start(const char *msg, const char *prio, unsigned expl)
{
	int fd[2];
	int ret;

	success("trying %s\n", msg);

	signal(SIGPIPE, SIG_IGN);

	ret = socketpair(AF_INET, SOCK_STREAM, 0, fd);
	if (ret < 0) {
		perror("socketpair");
		exit(1);
	}

	child = fork();
	if (child < 0) {
		perror("fork");
		fail("fork");
		exit(1);
	}

	if (child) {
		/* parent */
		close(fd[1]);
		client(fd[0], msg, prio, expl);
		waitpid(-1, NULL, 0);
		//kill(child, SIGTERM);
	} else {
		close(fd[0]);
		server(fd[1], prio, expl);
		exit(0);
	}
}

static void ch_handler(int sig)
{
	int status = 0;

	waitpid(-1, &status, 0);
	check_wait_status(status);
	return;
}

void doit(void)
{
	signal(SIGCHLD, ch_handler);

	start("TLS1.2-explicit flag", "NORMAL:-VERS-ALL:+VERS-TLS1.2",
			GNUTLS_NONBLOCK);
	//start("TLS1.2-explicit flag", "NORMAL:-VERS-ALL:+VERS-TLS1.3",
	//		GNUTLS_NONBLOCK);
	start("TLS-explicit flag", "NORMAL", GNUTLS_NONBLOCK);
	//start("DTLS1.2-explicit flag", "NORMAL:-VERS-ALL:+VERS-DTLS1.2",
	//		GNUTLS_NONBLOCK | GNUTLS_DATAGRAM);
	//start("DTLS-explicit flag", "NORMAL",
	//		GNUTLS_NONBLOCK | GNUTLS_DATAGRAM);
	start("TLS1.2-no flag", "NORMAL:-VERS-ALL:+VERS-TLS1.2", 0);
	//start("TLS1.3-no flag", "NORMAL:-VERS-ALL:+VERS-TLS1.3", 0);
	//start("TLS-no flag", "NORMAL", 0);
}

int main(void)
{
	doit();
	return 0;
}
