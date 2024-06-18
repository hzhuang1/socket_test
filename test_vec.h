#ifndef __TEST_VEC_H__
#define __TEST_VEC_H__

struct aead_testvec {
	const char *key;
	const char *iv;
	const char *ptext;
	const char *assoc;
	const char *ctext;
	unsigned char novrfy;
	unsigned char wk;
	unsigned char klen;
	unsigned int plen;
	unsigned int clen;
	unsigned int alen;
	int setkey_error;
	int setauthsize_error;
	int crypt_error;
};

struct aead_testvec aes_gcm_tv[] = {
        {
                .key    = "\xfe\xff\xe9\x92\x86\x65\x73\x1c"
                          "\x6d\x6a\x8f\x94\x67\x30\x83\x08",
                .klen   = 16,
                .iv     = "\xca\xfe\xba\xbe\xfa\xce\xdb\xad"
                          "\xde\xca\xf8\x88",
                .ptext  = "\xd9\x31\x32\x25\xf8\x84\x06\xe5"
                          "\xa5\x59\x09\xc5\xaf\xf5\x26\x9a"
                          "\x86\xa7\xa9\x53\x15\x34\xf7\xda"
                          "\x2e\x4c\x30\x3d\x8a\x31\x8a\x72"
                          "\x1c\x3c\x0c\x95\x95\x68\x09\x53"
                          "\x2f\xcf\x0e\x24\x49\xa6\xb5\x25"
                          "\xb1\x6a\xed\xf5\xaa\x0d\xe6\x57"
                          "\xba\x63\x7b\x39\x1a\xaf\xd2\x55",
                .plen   = 64,
                .ctext  = "\x42\x83\x1e\xc2\x21\x77\x74\x24"
                          "\x4b\x72\x21\xb7\x84\xd0\xd4\x9c"
                          "\xe3\xaa\x21\x2f\x2c\x02\xa4\xe0"
                          "\x35\xc1\x7e\x23\x29\xac\xa1\x2e"
                          "\x21\xd5\x14\xb2\x54\x66\x93\x1c"
                          "\x7d\x8f\x6a\x5a\xac\x84\xaa\x05"
                          "\x1b\xa3\x0b\x39\x6a\x0a\xac\x97"
                          "\x3d\x58\xe0\x91\x47\x3f\x59\x85"
                          "\x4d\x5c\x2a\xf3\x27\xcd\x64\xa6"
                          "\x2c\xf3\x5a\xbd\x2b\xa6\xfa\xb4",
                .clen   = 80,
        }
};

#endif	/* __TEST_VEC_H__ */
