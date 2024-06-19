#include <gnutls/gnutls.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "cert.h"
#include "common.h"

#define BUF_SIZE	2048

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

static unsigned char ssl2_hello[] =
	"\x80\x59\x01\x03\x01\x00\x30\x00\x00\x00\x20\x00\x00\x39\x00\x00"
	"\x38\x00\x00\x35\x00\x00\x16\x00\x00\x13\x00\x00\x0a\x00\x00\x33"
	"\x00\x00\x32\x00\x00\x2f\x00\x00\x07\x00\x00\x05\x00\x00\x04\x00"
	"\x00\x15\x00\x00\x12\x00\x00\x09\x00\x00\xff\xb1\xc9\x95\x1a\x02"
	"\x6c\xd6\x42\x11\x6e\x99\xe2\x84\x97\xc9\x17\x53\xaf\x53\xf7\xfc"
	"\x8d\x1e\x72\x87\x18\x53\xee\xa6\x7d\x18\xc6";

static unsigned char tls_alert[] = "\x15\x03\x01\x00\x02\x02\x5A";

static int debug = 1;

pid_t child;

static void tls_log_func(int level, const char *str)
{
	fprintf(stderr, "%s |<%d>| %s", child ? "server" : "client", level,
			str);
}

static void client(int sd)
{
	char buf[BUF_SIZE];
	int ret;

	/* send an SSL 2.0 hello, and then an alert */

	ret = send(sd, ssl2_hello, sizeof(ssl2_hello) - 1, 0);
	if (ret < 0)
		fail("error sending hello\n");
	printf("send %d bytes\n", ret);

	ret = recv(sd, buf, sizeof(buf), 0);
	if (ret < 0)
		fail("error receiving hello\n");
	printf("recv %d bytes\n", ret);
	dump_buffer_hex(buf, ret);

	ret = send(sd, tls_alert, sizeof(tls_alert) - 1, 0);
	if (ret < 0)
		fail("error sending hello\n");

	close(sd);
}

static void client2(int sd)
{
	char buf[BUF_SIZE];
	int ret;

	/* send an SSL 2.0 hello, and then an alert */
	ret = send(sd, ssl2_hello, sizeof(ssl2_hello) - 1, 0);
	printf("send %d bytes\n", ret);
	if (ret < 0)
		fail("error sending hello\n");
	close(sd);
}

static void server(int sd)
{
	gnutls_certificate_credentials_t x509_cred;
	gnutls_session_t session;
	int ret;

	/* this must be called once in the program
	*/
	gnutls_global_init();

	gnutls_global_set_log_function(tls_log_func);
	if (debug)
		gnutls_global_set_log_level(6);

	gnutls_certificate_allocate_credentials(&x509_cred);
	gnutls_certificate_set_x509_trust_mem(x509_cred, &ca3_cert,
			GNUTLS_X509_FMT_PEM);

	gnutls_certificate_set_x509_key_mem(x509_cred,
			&server_ca3_localhost_cert,
			&server_ca3_key,
			GNUTLS_X509_FMT_PEM);

	if (debug)
		success("Launched, generating DH parameters...\n");

	gnutls_init(&session, GNUTLS_SERVER);

	/* avoid calling all the priority functions, since the defaults
	 * are adequate.
	 */
	gnutls_priority_set_direct(session, "NORMAL", NULL);

	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, x509_cred);

	gnutls_transport_set_int(session, sd);
	ret = gnutls_handshake(session);
	if (ret != GNUTLS_E_FATAL_ALERT_RECEIVED ||
			gnutls_alert_get(session) != GNUTLS_A_USER_CANCELED) {
		fail("server: Handshake failed unexpectedly (%s)\n\n",
				gnutls_strerror(ret));
		return;
	}

	if (debug) {
		success("server: Handshake parsed the SSL2.0 client hello\n");
	}

	close(sd);
	gnutls_deinit(session);

	gnutls_certificate_free_credentials(x509_cred);

	gnutls_global_deinit();

	if (debug)
		success("server: finished\n");
}

static void server2(int sd)
{
	char buf[BUF_SIZE];
	int ret;

	printf("%s, %d\n", __func__, __LINE__);
	/* send an SSL 2.0 hello, and then an alert */

	ret = recv(sd, buf, sizeof(buf), 0);
	if (ret < 0)
		fail("error receiving hello\n");
	printf("recv %d bytes\n", ret);

	ret = send(sd, ssl2_hello, sizeof(ssl2_hello) - 1, 0);
	printf("%s, %d, ret:%d\n", __func__, __LINE__, ret);
	if (ret < 0)
		fail("error sending hello\n");
	printf("send %d bytes\n", ret);
	printf("%s, %d\n", __func__, __LINE__);
	dump_buffer_hex(buf, ret);
}

static void server3(int sd)
{
	gnutls_certificate_credentials_t x509_cred;
	gnutls_session_t session;
	int ret;
	char buf[BUF_SIZE];

	/* this must be called once in the program
	*/
	gnutls_global_init();

	gnutls_global_set_log_function(tls_log_func);
	if (debug)
		gnutls_global_set_log_level(6);

	gnutls_certificate_allocate_credentials(&x509_cred);
	gnutls_certificate_set_x509_trust_mem(x509_cred, &ca3_cert,
			GNUTLS_X509_FMT_PEM);

	gnutls_certificate_set_x509_key_mem(x509_cred,
			&server_ca3_localhost_cert,
			&server_ca3_key,
			GNUTLS_X509_FMT_PEM);

	if (debug)
		success("Launched, generating DH parameters...\n");

	gnutls_init(&session, GNUTLS_SERVER);

	/* avoid calling all the priority functions, since the defaults
	 * are adequate.
	 */
	gnutls_priority_set_direct(session, "NORMAL", NULL);

	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, x509_cred);

	gnutls_transport_set_int(session, sd);
	printf("#%s, %d\n", __func__, __LINE__);
	ret = gnutls_handshake(session);
	printf("#%s, %d, ret:%d\n", __func__, __LINE__, ret);
	if (ret != GNUTLS_E_FATAL_ALERT_RECEIVED ||
			gnutls_alert_get(session) != GNUTLS_A_USER_CANCELED) {
		fail("server: Handshake failed unexpectedly (%s)\n\n",
				gnutls_strerror(ret));
		return;
	}
	printf("#%s, %d\n", __func__, __LINE__);

	if (debug) {
		success("server: Handshake parsed the SSL2.0 client hello\n");
	}

	printf("prepare to receive\n");
	ret = recv(sd, buf, sizeof(buf), 0);
	printf("recv ret:%d\n", ret);
	if (ret < 0)
		fail("error receiving hello\n");
	printf("recv %d bytes\n", ret);
	dump_buffer_hex(buf, ret);

	close(sd);
	gnutls_deinit(session);

	gnutls_certificate_free_credentials(x509_cred);

	gnutls_global_deinit();

	if (debug)
		success("server: finished\n");
}

void doit(void)
{
	int sockets[2];
	int err;

	err = socketpair(AF_UNIX, SOCK_STREAM, 0, sockets);
	if (err == -1) {
		perror("socketpair");
		fail("socketpair failed\n");
		return;
	}

	child = fork();
	if (child < 0) {
		perror("fork");
		fail("fork");
		return;
	}

	if (child) {
		int status;

		close(sockets[1]);
#if 0
		server(sockets[0]);
#else
		server3(sockets[0]);
#endif
		wait(&status);
		check_wait_status(status);
	} else {
		close(sockets[0]);
		client2(sockets[1]);
		exit(0);
	}
}

int main(void)
{
	doit();
	return 0;
}
