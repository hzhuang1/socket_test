#ifndef __CERT_H__
#define __CERT_H__

#include <gnutls/gnutls.h>

#define PRIO_STRING	"NORMAL:-VERS-ALL:+VERS-TLS1.2:-CIPHER-ALL:+AES-256-GCM"

/* A server cert/key pair with CA */
static unsigned char server_cert_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIDIzCCAgugAwIBAgIMUz8PCR2sdRK56V6OMA0GCSqGSIb3DQEBCwUAMA8xDTAL\n"
	"BgNVBAMTBENBLTEwIhgPMjAxNDA0MDQxOTU5MDVaGA85OTk5MTIzMTIzNTk1OVow\n"
	"EzERMA8GA1UEAxMIc2VydmVyLTIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\n"
	"AoIBAQDZ3dCzh9gOTOiOb2dtrPu91fYYgC/ey0ACYjQxaru7FZwnuXPhQK9KHsIV\n"
	"YRIyo49wjKZddkHet2sbpFAAeETZh8UUWLRb/mupyaSJMycaYCNjLZCUJTztvXxJ\n"
	"CCNfbtgvKC+Vu1mu94KBPatslgvnsamH7AiL5wmwRRqdH/Z93XaEvuRG6Zk0Sh9q\n"
	"ZMdCboGfjtmGEJ1V+z5CR+IyH4sckzd8WJW6wBSEwgliGaXnc75xKtFWBZV2njNr\n"
	"8V1TOYOdLEbiF4wduVExL5TKq2ywNkRpUfK2I1BcWS5D9Te/QT7aSdE08rL6ztmZ\n"
	"IhILSrMOfoLnJ4lzXspz3XLlEuhnAgMBAAGjdzB1MAwGA1UdEwEB/wQCMAAwFAYD\n"
	"VR0RBA0wC4IJbG9jYWxob3N0MA8GA1UdDwEB/wQFAwMHoAAwHQYDVR0OBBYEFJXR\n"
	"raRS5MVhEqaRE42A3S2BIj7UMB8GA1UdIwQYMBaAFP6S7AyMRO2RfkANgo8YsCl8\n"
	"JfJkMA0GCSqGSIb3DQEBCwUAA4IBAQCQ62+skMVZYrGbpab8RI9IG6xH8kEndvFj\n"
	"J7wBBZCOlcjOj+HQ7a2buF5zGKRwAOSznKcmvZ7l5DPdsd0t5/VT9LKSbQ6+CfGr\n"
	"Xs5qPaDJnRhZkOILCvXJ9qyO+79WNMsg9pWnxkTK7aWR5OYE+1Qw1jG681HMkWTm\n"
	"nt7et9bdiNNpvA+L55569XKbdtJLs3hn5gEQFgS7EaEj59aC4vzSTFcidowCoa43\n"
	"7JmfSfC9YaAIFH2vriyU0QNf2y7cG5Hpkge+U7uMzQrsT77Q3SDB9WkyPAFNSB4Q\n"
	"B/r+OtZXOnQhLlMV7h4XGlWruFEaOBVjFHSdMGUh+DtaLvd1bVXI\n"
	"-----END CERTIFICATE-----\n"
	"-----BEGIN CERTIFICATE-----\n"
	"MIIDATCCAemgAwIBAgIBATANBgkqhkiG9w0BAQsFADAPMQ0wCwYDVQQDEwRDQS0w\n"
	"MCIYDzIwMTQwNDA0MTk1OTA1WhgPOTk5OTEyMzEyMzU5NTlaMA8xDTALBgNVBAMT\n"
	"BENBLTEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDvhyQfsUm3T0xK\n"
	"jiBXO3H6Y27b7lmCRYZQCmXCl2sUsGDL7V9biavTt3+sorWtH542/cTGDh5n8591\n"
	"7rVxAB/VASmN55O3fjZyFGrjusjhXBla0Yxe5rZ/7/Pjrq84T7gc/IXiX9Sums/c\n"
	"o9AeoykfhsjV2ubhh4h+8uPsHDTcAFTxq3mQaoldwnW2nmjDFzaKLtQdnyFf41o6\n"
	"nsJCK/J9PtpdCID5Zb+eQfu5Yhk1iUHe8a9TOstCHtgBq61YzufDHUQk3zsT+VZM\n"
	"20lDvSBnHdWLjxoea587JbkvtH8xRR8ThwABSb98qPnhJ8+A7mpO89QO1wxZM85A\n"
	"xEweQlMHAgMBAAGjZDBiMA8GA1UdEwEB/wQFMAMBAf8wDwYDVR0PAQH/BAUDAwcE\n"
	"ADAdBgNVHQ4EFgQU/pLsDIxE7ZF+QA2CjxiwKXwl8mQwHwYDVR0jBBgwFoAUGD0R\n"
	"Yr2H7kfjQUcBMxSTCDQnhu0wDQYJKoZIhvcNAQELBQADggEBANEXLUV+Z1PGTn7M\n"
	"3rPT/m/EamcrZJ3vFWrnfN91ws5llyRUKNhx6222HECh3xRSxH9YJONsbv2zY6sd\n"
	"ztY7lvckL4xOgWAjoCVTx3hqbZjDxpLRsvraw1PlqBHlRQVWLKlEQ55+tId2zgMX\n"
	"Z+wxM7FlU/6yWVPODIxrqYQd2KqaEp4aLIklw6Hi4HD6DnQJikjsJ6Noe0qyX1Tx\n"
	"uZ8mgP/G47Fe2d2H29kJ1iJ6hp1XOqyWrVIh/jONcnTvWS8aMqS3MU0EJH2Pb1Qa\n"
	"KGIvbd/3H9LykFTP/b7Imdv2fZxXIK8jC+jbF1w6rdBCVNA0p30X/jonoC3vynEK\n"
	"5cK0cgs=\n"
	"-----END CERTIFICATE-----\n";

const gnutls_datum_t server_cert = { server_cert_pem,
				     sizeof(server_cert_pem) - 1 };

static unsigned char server_key_pem[] =
	"-----BEGIN RSA PRIVATE KEY-----\n"
	"MIIEpQIBAAKCAQEA2d3Qs4fYDkzojm9nbaz7vdX2GIAv3stAAmI0MWq7uxWcJ7lz\n"
	"4UCvSh7CFWESMqOPcIymXXZB3rdrG6RQAHhE2YfFFFi0W/5rqcmkiTMnGmAjYy2Q\n"
	"lCU87b18SQgjX27YLygvlbtZrveCgT2rbJYL57Gph+wIi+cJsEUanR/2fd12hL7k\n"
	"RumZNEofamTHQm6Bn47ZhhCdVfs+QkfiMh+LHJM3fFiVusAUhMIJYhml53O+cSrR\n"
	"VgWVdp4za/FdUzmDnSxG4heMHblRMS+UyqtssDZEaVHytiNQXFkuQ/U3v0E+2knR\n"
	"NPKy+s7ZmSISC0qzDn6C5yeJc17Kc91y5RLoZwIDAQABAoIBAQCRXAu5HPOsZufq\n"
	"0K2DYZz9BdqSckR+M8HbVUZZiksDAeIUJwoHyi6qF2eK+B86JiK4Bz+gsBw2ys3t\n"
	"vW2bQqM9N/boIl8D2fZfbCgZWkXGtUonC+mgzk+el4Rq/cEMFVqr6/YDwuKNeJpc\n"
	"PJc5dcsvpTvlcjgpj9bJAvJEz2SYiIUpvtG4WNMGGapVZZPDvWn4/isY+75T5oDf\n"
	"1X5jG0lN9uoUjcuGuThN7gxjwlRkcvEOPHjXc6rxfrWIDdiz/91V46PwpqVDpRrg\n"
	"ig6U7+ckS0Oy2v32x0DaDhwAfDJ2RNc9az6Z+11lmY3LPkjG/p8Klcmgvt4/lwkD\n"
	"OYRC5QGRAoGBAPFdud6nmVt9h1DL0o4R6snm6P3K81Ds765VWVmpzJkK3+bwe4PQ\n"
	"GQQ0I0zN4hXkDMwHETS+EVWllqkK/d4dsE3volYtyTti8zthIATlgSEJ81x/ChAQ\n"
	"vvXxgx+zPUnb1mUwy+X+6urTHe4bxN2ypg6ROIUmT+Hx1ITG40LRRiPTAoGBAOcT\n"
	"WR8DTrj42xbxAUpz9vxJ15ZMwuIpk3ShE6+CWqvaXHF22Ju4WFwRNlW2zVLH6UMt\n"
	"nNfOzyDoryoiu0+0mg0wSmgdJbtCSHoI2GeiAnjGn5i8flQlPQ8bdwwmU6g6I/EU\n"
	"QRbGK/2XLmlrGN52gVy9UX0NsAA5fEOsAJiFj1CdAoGBAN9i3nbq6O2bNVSa/8mL\n"
	"XaD1vGe/oQgh8gaIaYSpuXlfbjCAG+C4BZ81XgJkfj3CbfGbDNqimsqI0fKsAJ/F\n"
	"HHpVMgrOn3L+Np2bW5YMj0Fzwy+1SCvsQ8C+gJwjOLMV6syGp/+6udMSB55rRv3k\n"
	"rPnIf+YDumUke4tTw9wAcgkPAoGASHMkiji7QfuklbjSsslRMyDj21gN8mMevH6U\n"
	"cX7pduBsA5dDqu9NpPAwnQdHsSDE3i868d8BykuqQAfLut3hPylY6vPYlLHfj4Oe\n"
	"dj+xjrSX7YeMBE34qvfth32s1R4FjtzO25keyc/Q2XSew4FcZftlxVO5Txi3AXC4\n"
	"bxnRKXECgYEAva+og7/rK+ZjboJVNxhFrwHp9bXhz4tzrUaWNvJD2vKJ5ZcThHcX\n"
	"zCig8W7eXHLPLDhi9aWZ3kUZ1RLhrFc/6dujtVtU9z2w1tmn1I+4Zi6D6L4DzKdg\n"
	"nMRLFoXufs/qoaJTqa8sQvKa+ceJAF04+gGtw617cuaZdZ3SYRLR2dk=\n"
	"-----END RSA PRIVATE KEY-----\n";

const gnutls_datum_t server_key = { server_key_pem,
				    sizeof(server_key_pem) - 1 };

static char ca3_cert_pem[] =
        "-----BEGIN CERTIFICATE-----\n"
        "MIID+jCCAmKgAwIBAgIIVzGgXgSsTYwwDQYJKoZIhvcNAQELBQAwDzENMAsGA1UE\n"
        "AxMEQ0EtMzAgFw0xNjA1MTAwODQ4MzBaGA85OTk5MTIzMTIzNTk1OVowDzENMAsG\n"
        "A1UEAxMEQ0EtMzCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBALbdxniG\n"
        "+2wP/ONeZfvR7AJakVo5deFKIHVTiiBWwhg+HSjd4nfDa+vyTt/wIdldP1PriD1R\n"
        "igc8z68+RxPpGfAc197pKlKpO08I0L1RDKnjBWr4fGdCzE6uZ/ZsKVifoIZpdC8M\n"
        "2IYpAIMajEtnH53XZ1hTEviXTsneuiCTtap73OeSkL71SrIMkgBmAX17gfX3SxFj\n"
        "QUzOs6QMMOa3+8GW7RI+E/SyS1QkOO860dj9XYgOnTL20ibGcWF2XmTiQASI+KmH\n"
        "vYJCNJF/8pvmyJRyBHGZO830aBY0+DcS2bLKcyMiWfOJw7WnpaO7zSEC5WFgo4jd\n"
        "qroUBQdjQNCSSdrt1yYrAl1Sj2PMxYFX4H545Pr2sMpwC9AnPk9+uucT1Inj9615\n"
        "qbuXgFwhkgpK5pnPjzKaHp7ESlJj4/dIPTmhlt5BV+CLh7tSLzVLrddGU+os8Jin\n"
        "T42radJ5V51Hn0C1CHIaFAuBCd5XRHXtrKb7WcnwCOxlcvux9h5/847F4wIDAQAB\n"
        "o1gwVjAPBgNVHRMBAf8EBTADAQH/MBMGA1UdJQQMMAoGCCsGAQUFBwMJMA8GA1Ud\n"
        "DwEB/wQFAwMHBgAwHQYDVR0OBBYEFPmohhljtqQUE2B2DwGaNTbv8bSvMA0GCSqG\n"
        "SIb3DQEBCwUAA4IBgQBhBi8dXQMtXH2oqcuHuEj9JkxraAsaJvc1WAoxbiqVcJKc\n"
        "VSC0gvoCY3q+NQvuePzw5dzd5JBfkoIsP5U6ATWAUPPqCP+/jRnFqDQlH626mhDG\n"
        "VS8W7Ee8z1KWqnKWGv5nkrZ6r3y9bVaNUmY7rytzuct1bI9YkX1kM66vgnU2xeMI\n"
        "jDe36/wTtBRVFPSPpE3KL9hxCg3KgPSeSmmIhmQxJ1M6xe00314/GX3lTDt55UdM\n"
        "gmldl2LHV+0i1NPCgnuOEFVOiz2nHAnw2LNmvHEDDpPauz2Meeh9aaDeefIh2u/w\n"
        "g39WRPhU1mYvmxvYZqA/jwSctiEhuKEBBZSOHxeTjplH1THlIziVnYyVW4sPMiGU\n"
        "ajXhTi47H219hx87+bldruOtirbDIslL9RGWqWAkMeGP+hUl1R2zvDukaqIKqIN8\n"
        "1/A/EeMoI6/IHb1BpgY2rGs/I/QTb3VTKqQUYv09Hi+itPCdKqamSm8dZMKKaPA0\n"
        "fD9yskUMFPBhfj8BvXg=\n"
        "-----END CERTIFICATE-----\n";

static char ca3_key_pem[] =
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "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\n"
        "-----END RSA PRIVATE KEY-----\n";

const gnutls_datum_t ca3_key = { (unsigned char *)ca3_key_pem,
                                 sizeof(ca3_key_pem) - 1 };

const gnutls_datum_t ca3_cert = { (unsigned char *)ca3_cert_pem,
                                  sizeof(ca3_cert_pem) - 1 };

static char subca3_cert_pem[] =
        "-----BEGIN CERTIFICATE-----\n"
        "MIIEDTCCAnWgAwIBAgIMV6MdMjWzT9C59ec8MA0GCSqGSIb3DQEBCwUAMA8xDTAL\n"
        "BgNVBAMTBENBLTMwIBcNMTYwNTEwMDg0ODMwWhgPOTk5OTEyMzEyMzU5NTlaMBIx\n"
        "EDAOBgNVBAMTB3N1YkNBLTMwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIB\n"
        "gQCgOcNXzStOnRFoi05aMRLeMB45X4a2srSBul3ULxDSGjIP0EEl//X2WLiope/x\n"
        "NL8bPCRpI1sSVXl8Hb1cK3qWNGazVmC7xW07NxL26I86e3/BVRnq8ioVtvPQwEpv\n"
        "uI8F97x1vL/n+cfcdkN77NScr5C9jHMVioRvC+qKz9bUBx5DSySV66PR5+wGsJDv\n"
        "kfsmjVOgqiTlSWQS5G3nMMq0Rixsc5dP5Wygkbdh9+45UCtObcnHABJrP+GtLiG0\n"
        "AOUx6oPzPteZL13erWXg7zYusTarj9rTcdsgR/Im1mIzmD2i7GhJo4Gj0Sk3Rq93\n"
        "JyeA+Ay5UPmqcm+dqX00b49MTTv4GtO53kLQSCXYFJ96jcMiXMzBFJD1ROsdk4WU\n"
        "ed/tJMHffttDz9j3WcuX9M2nzTT2xlauokjbEAhRDRw5fxCFZh7TbmaH4vysDO9U\n"
        "ZXVEXSLKonQ2Lmyso48s/G30VmlSjtPtJqRsv/oPpCO/c0D6BrkHV55B48xfmyIF\n"
        "jgECAwEAAaNkMGIwDwYDVR0TAQH/BAUwAwEB/zAPBgNVHQ8BAf8EBQMDBwYAMB0G\n"
        "A1UdDgQWBBQtMwQbJ3+UBHzH4zVP6SWklOG3oTAfBgNVHSMEGDAWgBT5qIYZY7ak\n"
        "FBNgdg8BmjU27/G0rzANBgkqhkiG9w0BAQsFAAOCAYEAMii5Gx3/d/58oDRy5a0o\n"
        "PvQhkU0dKa61NfjjOz9uqxNSilLJE7jGJPaG2tKtC/XU1Ybql2tqQY68kogjKs31\n"
        "QC6RFkoZAFouTJt11kzbgVWKewCk3/OrA0/ZkRrAfE0Pma/NITRwTHmTsQOdv/bz\n"
        "R+xIPhjKxKrKyJFMG5xb+Q0OKSbd8kDpgYWKob5x2jsNYgEDp8nYSRT45SGw7c7F\n"
        "cumkXz2nA6r5NwbnhELvNFK8fzsY+QJKHaAlJ9CclliP1PiiAcl2LQo2gaygWNiD\n"
        "+ggnqzy7nqam9rieOOMHls1kKFAFrWy2g/cBhTfS+/7Shpex7NK2GAiujgUV0TZH\n"
        "EyEZt6um4gLS9vwUKs/R4XS9VL/bBlfAy2hAVTeUejiRBGeTJkqBu7+c4FdrCByV\n"
        "haeQASMYu/lga8eaGL1zJbJe2BQWI754KDYDT9qKNqGlgysr4AVje7z1Y1MQ72Sn\n"
        "frzYSQw6BB85CurB6iou3Q+eM4o4g/+xGEuDo0Ne/8ir\n"
        "-----END CERTIFICATE-----\n";

static char subca3_key_pem[] =
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "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\n"
        "-----END RSA PRIVATE KEY-----\n";

const gnutls_datum_t subca3_key = { (unsigned char *)subca3_key_pem,
                                    sizeof(subca3_key_pem) - 1 };

const gnutls_datum_t subca3_cert = { (unsigned char *)subca3_cert_pem,
                                     sizeof(subca3_cert_pem) - 1 };

static char server_ca3_key_pem[] =
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "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\n"
        "-----END RSA PRIVATE KEY-----\n";

const gnutls_datum_t server_ca3_key = { (unsigned char *)server_ca3_key_pem,
                                        sizeof(server_ca3_key_pem) - 1 };

static char server_ca3_rsa_pss_key_pem[] =
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEAvxOfMAZbqIuVqkPt5s5fyNeuYD09r80oDEN54MS7/tMy+2yk\n"
        "rwsX3a1zGLqn47Q59E0QAlheFP5ZXcQgFXVdQwWCn00YtYyGn5uGrzT80PlIAnaG\n"
        "yVpjLGci7mU13IpHlLKqQbBaCdiDU1qV/fyy03t0KVdlyzTi3RJoKDU3XTG/eJmy\n"
        "bPHuBGzBjtXn4IJkbbe9FL090YJbgu0EqgcVhaon9JOs5cVNGsHZ4zdRo1d9/5zK\n"
        "tqaAVCPYECL/OYwTBS0O8kTrkoHwXo08bR0sUhb7enfI827mOOiIyokkzUu1YVyP\n"
        "6GMnggmoUa8LaSeO3bsWU9rx1ngWBUQ5hBG5JQIDAQABAoIBAAkoYpfFpjz0u66W\n"
        "ZN+MApE4rRXVuZAkcAfub/fy1ePHsYjVUytEh9dLCdokkAlcyO5JhzvlilTNP/E7\n"
        "hiIhJuAgcns6EbYZzxX1OUZKbteBKw9bKOibmWc2Zjkwxp0UT4vz6C8PybDxHJIx\n"
        "JEExDE0QfKfClZFgroLT8AQFUOr5cy8dY2edh17+rMMeBvJ5Yit3L6hlHjO+5eJA\n"
        "E0WzxPrZWIFfAJl484HbZL/kBT8UXqYDTR7MB+qOq8mdKQSLcHwyjvItgvgklEPu\n"
        "0Rl626K+R6841FmrXjUEBVtfkS8Osw/+CJDYw6YZwB7W8oLRRhcB7PjMWU5RHAIW\n"
        "nZKFWn0CgYEA0qsP7FUemy7kG7cA8qMErt7oWV/DYIMpKaCJC+17vk37OmJbUpbo\n"
        "UkfEIY9iT8hcPjP1jAnQf2d0A37zn9B7DTYPhbjbRtNrOSkdrE/u5FeWd4tr9uc7\n"
        "JdYhRc6dkPKbVbFFyo7bdHwU0ZLtfhJYKpTYJ3oNvjsiLqBjIHaj2v8CgYEA6DFV\n"
        "FKlQL9OnzTnQtu5oDvqHFiaHD1wdPTN9MeNWEFdcf/kd3eVvcRmpenGZaud7jn72\n"
        "nhtXXyzc9GlVoKL6R+/1GVexwu477dr2Ci5MwPYGtyh2tJWjgHTad0bT0Jq4Bneu\n"
        "ZuXZ0EszfxTmHkUkPlzvUrbPjoJxgb57P0Qfn9sCgYEAnYrTg5c8Jizw5VD74nfK\n"
        "nsOP2pZk054CgGDPXB4i9fP3Nngrdx3navDEWZySlrttUA8nR6xnQX+qIJslsZQF\n"
        "EaImBYhyYwrkGoEG8b9tFVHy8j9PY/sUHn19sGiNKMJlK7ZATPR8ZSYNo5RPCoLJ\n"
        "cD6TTyJVeLdcHqZOuw4+Bx0CgYAvP5qokauXj+JdiJ5IG0thgOlsQHrLTVtF0Oxw\n"
        "8mnY+W4BPJgvRzjeMvKhz+wALQqffIaCtd2ZqG9t7OFXxtJXQSUG+ylZGVFonV3j\n"
        "xHgp6+aB7uH47VpQEXdDPk5r7I/2APSkS7F/CU55Va9eCYPOjOrGUhz6SuD+HdzG\n"
        "iv5EcQKBgDyt221UUieb1sWhCHaKaQ3z8/aJlzs+ge6kSLqoVjcfr5uOKM1O5O72\n"
        "bfy00r7B8ky77qXNTtzv2xt9Km/hRptqnCHsgly5OXW8pMcFnf7Kdh3Q+c5UzVlc\n"
        "ODwZlaKK2fjp9xr2dNpYjRqyEb1gkC9FJMaxab9OAf+AoQifxncv\n"
        "-----END RSA PRIVATE KEY-----\n";

const gnutls_datum_t server_ca3_rsa_pss_key = {
        (unsigned char *)server_ca3_rsa_pss_key_pem,
        sizeof(server_ca3_rsa_pss_key_pem) - 1
};

static char server_ca3_rsa_pss_cert_pem[] =
        "-----BEGIN CERTIFICATE-----\n"
        "MIIEAjCCAjqgAwIBAgIMWSa+iBMb7BVvI0GIMD0GCSqGSIb3DQEBCjAwoA0wCwYJ\n"
        "YIZIAWUDBAIBoRowGAYJKoZIhvcNAQEIMAsGCWCGSAFlAwQCAaIDAgEgMA8xDTAL\n"
        "BgNVBAMTBENBLTMwHhcNMTkwNDE1MDkyMjIwWhcNNDkxMjMxMDkyMjIwWjANMQsw\n"
        "CQYDVQQGEwJHUjCCAVIwPQYJKoZIhvcNAQEKMDCgDTALBglghkgBZQMEAgGhGjAY\n"
        "BgkqhkiG9w0BAQgwCwYJYIZIAWUDBAIBogMCASADggEPADCCAQoCggEBAL8TnzAG\n"
        "W6iLlapD7ebOX8jXrmA9Pa/NKAxDeeDEu/7TMvtspK8LF92tcxi6p+O0OfRNEAJY\n"
        "XhT+WV3EIBV1XUMFgp9NGLWMhp+bhq80/ND5SAJ2hslaYyxnIu5lNdyKR5SyqkGw\n"
        "WgnYg1Nalf38stN7dClXZcs04t0SaCg1N10xv3iZsmzx7gRswY7V5+CCZG23vRS9\n"
        "PdGCW4LtBKoHFYWqJ/STrOXFTRrB2eM3UaNXff+cyramgFQj2BAi/zmMEwUtDvJE\n"
        "65KB8F6NPG0dLFIW+3p3yPNu5jjoiMqJJM1LtWFcj+hjJ4IJqFGvC2knjt27FlPa\n"
        "8dZ4FgVEOYQRuSUCAwEAAaNQME4wDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUjFqe\n"
        "vO9heHT9V24WV1ovs7pvUvMwHwYDVR0jBBgwFoAU+aiGGWO2pBQTYHYPAZo1Nu/x\n"
        "tK8wPQYJKoZIhvcNAQEKMDCgDTALBglghkgBZQMEAgGhGjAYBgkqhkiG9w0BAQgw\n"
        "CwYJYIZIAWUDBAIBogMCASADggGBAAgVZdGqSwhaa8c/KuqsnELoK5QlzdSUNZ0O\n"
        "J31nVQyOmIJtqR14nMndU0y1iowAoj0osZFYjxjN6e2AqUF7R22uhtxmG6rr0YEi\n"
        "XS+rNpbs7+gY/3hK30vo376QL85+U4v4HuTCd+yX8bY9VPqwZBMYO5rcDyXG82xC\n"
        "ZKXT/Tr7XD80iMFjyR2cvRAjoZQeXbWzNE4AEm0jNz2F5Qnl6uSgtpDkHYKgr9xq\n"
        "yUhm/WNKG86pzBxfcFju4prqBLiwUZh068b6znBAS0wMflrF/lznu01QqDhK6mz3\n"
        "cSn5LlzoKjuouAWdZRieqokr1mNiWggmX5n2qKM9FJtDQctsvntCf/freAfy+Xmu\n"
        "Tm055R9UzX76mL89eXY92U++HR8Y5IO5lqY1f13rzWK5rJB9qjz/Mamj9xR6Egoa\n"
        "hh1ysRItcTCFJI5xKb/i3hHv94U12EH1IfFHofptr1pyCtAeOhJytWPndCiB2m1q\n"
        "M2k3tl6cHvlUz7DpgnxNniuQ/dQ4MA==\n"
        "-----END CERTIFICATE-----\n";

const gnutls_datum_t server_ca3_rsa_pss_cert = {
        (unsigned char *)server_ca3_rsa_pss_cert_pem,
        sizeof(server_ca3_rsa_pss_cert_pem) - 1
};

static char server_localhost_ca3_cert_pem[] =
        "-----BEGIN CERTIFICATE-----\n"
        "MIIEKDCCApCgAwIBAgIMV6MdMjbIDKHKsL32MA0GCSqGSIb3DQEBCwUAMBIxEDAO\n"
        "BgNVBAMTB3N1YkNBLTMwIBcNMTYwNTEwMDg1MTE4WhgPOTk5OTEyMzEyMzU5NTla\n"
        "MAAwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQDZPXiZqiz3wLuz+B4Z\n"
        "nJuCphLEX7k15NcpamL3+9ea4gXyfeFSHbSaihPauBUcDMVbL/wfkhxYiJRCX7wq\n"
        "HIkJK4En5aEzSDDa6pI/CI5lSbiXdNDGbFLh5b8Guvhfzyy8lDjFNNy3abkfU270\n"
        "tnzFY5mkYwYgjuN/RgPqh0b8McT+xUeN9x4PuSXXmMC1r3v7y4JuMxE8ZzGDhW2a\n"
        "QK5Is6QYv0WELS5hVvB8GdP5XQwTJw4HH5i/YES7TENV2RByzRY8hFQ9SbK5YHHG\n"
        "oszVJIlIuxm5v8N2Ig1cW6t7t3HnuZbDYRDCERMiEigBz8vEZZyFsMLg5Z7JiNKS\n"
        "G/f+ER9CzDJXHgxBctV9EEc2KmRT1P9JeI/xZUOl9lKljc+t8m0Um3Asx5duWm4t\n"
        "cZm7FecnaJiTXD/tEG64qTKWtDuoI7+X9MjHe5lvf2gIJT3CoKW24Rn6O1fc9oCC\n"
        "nVAi0V6FLM4XaG50X9NC666RVEFkXih8THA1gC9m9NJMrD0CAwEAAaOBjTCBijAM\n"
        "BgNVHRMBAf8EAjAAMBQGA1UdEQQNMAuCCWxvY2FsaG9zdDATBgNVHSUEDDAKBggr\n"
        "BgEFBQcDATAPBgNVHQ8BAf8EBQMDB6AAMB0GA1UdDgQWBBQzneEn04vV/OsF/LXH\n"
        "gWlPXjvZ1jAfBgNVHSMEGDAWgBQtMwQbJ3+UBHzH4zVP6SWklOG3oTANBgkqhkiG\n"
        "9w0BAQsFAAOCAYEASbEdRkK44GUb0Y+80JdYGFV1YuHUAq4QYSwCdrT0hwJrFYI2\n"
        "s8+9/ncyzeyY00ryg6tPlKyE5B7ss29l8zcj0WJYsUk5kjV6uCWuo9/rqqPHK6Lc\n"
        "Qx1cONR4Vt+gD5TX0nRNuKaHVbBJARZ3YOl2F3nApcR/8boq+WNKGhGkzFMaKV+i\n"
        "IDpB0ziBUcb+q257lQGKrBuXl5nCd+PZswB//pZCsIkTF5jFdjeXvOvGDjYAr8rG\n"
        "KpoMTskNcBqgi59sJc8djWMbNt+15qH4mSvTUW1caukeJAr4mwHfrSK5k9ezSSp1\n"
        "EpbQ2Rp3xpbCgklhtsKHSJZ43sghZvCOxk8G3bRZ1/lW6sXvIPmLkvoeetTLvqYq\n"
        "t/+gfv4NJuyZhzuJHbxrxBJ3C9QjqTbpiUumeRQHXLa+vZJUKX7ak1KVubKiOC+x\n"
        "wyfgmq6quk5jPgOgMJWLwpA2Rm30wqX4OehXov3stSXFb+qASNOHlEtQdgKzIEX/\n"
        "6TXY44pCGHMFO6Kr\n"
        "-----END CERTIFICATE-----\n";

const gnutls_datum_t server_ca3_localhost_cert = {
        (unsigned char *)server_localhost_ca3_cert_pem,
        sizeof(server_localhost_ca3_cert_pem) - 1
};

#endif	/* __CERT_H__ */
