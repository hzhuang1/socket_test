#include <errno.h>
#include <linux/tls.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "common.h"
#include "test_vec.h"

void tls_crypto_info_init(uint16_t tls_version, uint16_t cipher_type,
			  struct tls_crypto_info_keys *tls12)
{
	memset(tls12, 0, sizeof(*tls12));

	switch (cipher_type) {
	case TLS_CIPHER_CHACHA20_POLY1305:
		tls12->len = sizeof(struct tls12_crypto_info_chacha20_poly1305);
		tls12->chacha20.info.version = tls_version;
		tls12->chacha20.info.cipher_type = cipher_type;
		break;
	case TLS_CIPHER_AES_GCM_128:
		tls12->len = sizeof(struct tls12_crypto_info_aes_gcm_128);
		tls12->aes128.info.version = tls_version;
		tls12->aes128.info.cipher_type = cipher_type;
		break;
	case TLS_CIPHER_AES_GCM_256:
		tls12->len = sizeof(struct tls12_crypto_info_aes_gcm_256);
		tls12->aes256.info.version = tls_version;
		tls12->aes256.info.cipher_type = cipher_type;
		break;
	default:
		fprintf(stderr, "unmatched version & cipher\n");
		exit(EXIT_FAILURE);
	}
}

void test_vec_init(struct tls_crypto_info_keys *tls12, uint16_t cipher_type)
{
	switch (cipher_type) {
	case TLS_CIPHER_AES_GCM_128:
		memcpy(&tls12->aes128.iv, &aes_gcm_tv[0].iv, 12);
		memcpy(&tls12->aes128.key, &aes_gcm_tv[0].key,
		       aes_gcm_tv[0].klen);
		break;
	default:
		fprintf(stderr, "unmatched cipher type\n");
		exit(EXIT_FAILURE);
	}
}

void dump_buffer_hex(void *buf, size_t len)
{
	size_t i, j;

	for (i = 0; i < len; i += 16) {
		printf("[%04lx] ", i);
		for (j = 0; j < 16 && i + j < len; j++) {
			printf("%02x ", *(unsigned char *)(buf + i + j));
		}
		printf("\n");
	}
}

void memrnd(void *s, size_t n)
{
	int *dword = s;
	char *byte;

	for (; n >= 4; n -= 4)
		*dword++ = rand();
	byte = (void *)dword;
	while (n--)
		*byte++ = rand();
}

#if 0
int ktls_send_ctrl_message(int sockfd, unsigned char record_type,
			   const char *data, size_t length)
{
	struct msghdr msg = { 0 };
	int cmsg_len = sizeof(record_type);
	struct cmsghdr *cmsg;
	char buf[CMSG_SPACE(cmsg_len)];
	struct iovec msg_iov;

	msg.msg_control = buf;
	msg.msg_controllen = sizeof(buf);
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = IPPROTO_TCP;
	cmsg->cmsg_type = CMSG_LEN(cmsg_len);
	*((unsigned char *)CMSG_DATA(cmsg)) = record_type;
	msg.msg_controllen = cmsg->cmsg_len;

	msg_iov.iov_base = (void *)data;
	msg_iov.iov_len = length;
	msg.msg_iov = &msg_iov;
	msg.msg_iovlen = 1;

	return sendmsg(sockfd, &msg, 0);
}

int ktls_read_record(int sockfd, void *data, size_t length)
{
	struct msghdr msg = { 0 };
	int cmsg_len = sizeof(struct tls_get_record);
	struct tls_get_record *tgr;
	struct cmsghdr *cmsg;
	char buf[CMSG_SPACE(cmsg_len)];
	struct iovec msg_iov;
	int ret;
	unsigned char *p = data;
	const size_t prepend_length = SSL3_RT_HEADER_LENGTH;

	if (length <= prepend_length) {
		errno = EINVAL;
		return -1;
	}

	msg.msg_control = buf;
	msg.msg_controllen = sizeof(buf);

	msg_iov.iov_base = p + prepend_length;
	msg_iov.iov_len = length - prepend_length;
	msg.msg_iov = &msg_iov;
	msg.msg_iovlen = 1;

	ret = recvmsg(sockfd, &msg, 0);
	if (ret < 0)
		return ret;

	if ((msg.msg_flags & (MSG_EOR | MSG_CTRUNC)) != MSG_EOR) {
		errno = EMSGSIZE;
		return -1;
	}

	if (msg.msg_controllen == 0) {
		errno = EBADMSG;
		return -1;
	}

	cmsg = CMSG_FIRSTHDR(&msg);
	if (cmsg->cmsg_level != IPPROTO_TCP || cmsg->cmsg_type != TLS_GET_RECORD_TYPE
	    || cmsg->cmsg_len != CMSG_LEN(cmsg_len)) {
		errno = EBADMSG;
		return -1;
	}

	tgr = (struct tls_get_record *)CMSG_DATA(cmsg);
	p[0] = tgr->tls_type;
	p[1] = tgr->tls_vmajor;
	p[2] = tgr->tls_vminor;
	*(uint16_t *)(p + 3) = htons(ret);

	return ret + prepend_length;
}
#endif
