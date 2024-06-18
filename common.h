#ifndef __COMMON_H__
#define __COMMON_H__

#include <stdint.h>
#include <linux/tls.h>

#define SSL3_RT_HEADER_LENGTH	5

#define EVP_GCM_TLS_TAG_LEN	16

struct tls_crypto_info_keys {
	union {
		struct tls_crypto_info crypto_info;
		struct tls12_crypto_info_aes_gcm_128 aes128;
		struct tls12_crypto_info_aes_gcm_256 aes256;
		struct tls12_crypto_info_chacha20_poly1305 chacha20;
	};
	size_t len;
};

extern void tls_crypto_info_init(uint16_t tls_version, uint16_t cipher_type,
				 struct tls_crypto_info_keys *tls2);
extern void test_vec_init(struct tls_crypto_info_keys *tls,
			  uint16_t cipher_type);
extern void dump_buffer_hex(void *buf, size_t len);
extern void memrnd(void *s, size_t n);

#endif /* __COMMON_H__ */
