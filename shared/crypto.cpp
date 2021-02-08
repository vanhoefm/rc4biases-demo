#include <Python.h>
#include <string.h>
#include <assert.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/aes.h>
#include <openssl/rc4.h>
#include <openssl/sha.h>

#include <stdexcept>

#include "crypto.h"
#include "util.h"

//
// TLS/SSL functions
//

#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined (LIBRESSL_VERSION_NUMBER)
HMAC_CTX *HMAC_CTX_new(void)
{
	HMAC_CTX *ctx = (HMAC_CTX*)OPENSSL_malloc(sizeof(*ctx));
	if (ctx != NULL)
		HMAC_CTX_init(ctx);
	return ctx;
}

void HMAC_CTX_free(HMAC_CTX *ctx)
{
	if (ctx != NULL) {
		HMAC_CTX_cleanup(ctx);
		OPENSSL_free(ctx);
	}
}

EVP_CIPHER_CTX * EVP_CIPHER_CTX_new(void)
{
	EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX*)OPENSSL_malloc(sizeof(*ctx));
	if (ctx != NULL)
		EVP_CIPHER_CTX_init(ctx);
	return ctx;
}

void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx)
{
	if (ctx != NULL) {
		EVP_CIPHER_CTX_cleanup(ctx);
		OPENSSL_free(ctx);
	}
}
#endif

/**
 * @param hashtype	Is return value of EVP_sha256, EVP_sha1, EVP_md5, ...
 */
void hmac_vector(const EVP_MD *hashtype, const uint8_t *key, size_t key_len, size_t num_elem,
		 const uint8_t *addr[], const size_t *len, uint8_t *mac)
{
	HMAC_CTX *ctx;
	unsigned int resultlen = 0;

	ctx = HMAC_CTX_new();

	for (size_t i = 0; i < num_elem; i++)
		HMAC_Update(ctx, addr[i], len[i]);

	HMAC_Final(ctx, mac, &resultlen);
	HMAC_CTX_free(ctx);
}


/**
 * @param hashtype	Is return value of EVP_sha256, EVP_sha1, EVP_md5, ...
 *
 * RFC 5246, Chapter 5. Note that in this case seed' == label + seed.
 * 
 * A() is defined as:
 *	A(0) = seed'
 *	A(i) = HMAC(secret, A(i-1))
 *
 * P_<hash>(secret, seed') = HMAC(secret, A(1) + seed') +
 *                           HMAC(secret, A(2) + seed') +
 *                           HMAC(secret, A(3) + seed') + ...
 *
 * PRF(secret, label, seed) = P_<hash>(secret, label + seed)
 */
void P_hash(const EVP_MD *hashtype, const uint8_t *secret, size_t secret_len, const char *label,
	    const uint8_t *seed, size_t seed_len, uint8_t *out, size_t outlen)
{
	size_t digestlen = EVP_MD_size(hashtype);
	uint8_t A[digestlen];
	uint8_t P[digestlen];
	const uint8_t *addr[3] = {A, (const uint8_t*)label, seed};
	size_t len[3] = {digestlen, strlen(label), seed_len};
	unsigned int resultlen;

	// A(1) = HMAC(secret, label + seed)
	hmac_vector(hashtype, secret, secret_len, 2, &addr[1], &len[1], A);

	size_t pos = 0;
	while (pos < outlen) {
		// P = HMAC(secret, A(i) + label + seed)
		hmac_vector(hashtype, secret, secret_len, 3, addr, len, P);
		// A(i+1) = HMAC(secret, A(i))
		HMAC(hashtype, secret, secret_len, A, digestlen, A, &resultlen);

		// Copy over P to output
		size_t copylen = digestlen;
		if (copylen > outlen - pos) copylen = outlen - pos;
		memcpy(out + pos, P, copylen);

		pos += copylen;
	}
}


/**
 * RFC 4346, Chapter 5
 *
 * PRF(secret, label, seed) = P_MD5(S1, label + seed) XOR
 *                            P_SHA-1(S2, label + seed);
 *
 * Where secret == S1||S2 and len(S1) == len(S2). If secret_len is odd, then
 * S1 and S2 share one byte (last byte of S1, first byte of S2).
 */
void tls1v01_prf(const uint8_t *secret, size_t secret_len, const char *label,
		 const uint8_t *seed, size_t seed_len, uint8_t *out, size_t outlen)
{
	size_t splitlen = (secret_len / 2) + (secret_len % 2);
	const uint8_t *secret1 = secret;
	const uint8_t *secret2 = secret + (secret_len - splitlen);
	uint8_t temp[outlen];

	P_hash(EVP_md5() , secret1, splitlen, label, seed, seed_len, out , outlen);
	P_hash(EVP_sha1(), secret2, splitlen, label, seed, seed_len, temp, outlen);

	for (size_t i = 0; i < outlen; ++i)
		out[i] ^= temp[i];
}


/**
 * RFC 5246, Chapter 5: It uses P_<sha256>.
 */
void tls1v2_prf(const uint8_t *secret, size_t secret_len, const char *label,
		const uint8_t *seed, size_t seed_len, uint8_t *out, size_t outlen)
{
	P_hash(EVP_sha256(), secret, secret_len, label, seed, seed_len, out, outlen);
}


void ssl_tls_prf(uint8_t vermajor, uint8_t verminor, const uint8_t *secret, size_t secret_len,
		 const char *label, const uint8_t *seed, size_t seed_len, uint8_t *out, size_t outlen)
{
	if (vermajor < 3 || (vermajor == 3 && verminor < 3))
		tls1v01_prf(secret, secret_len, label, seed, seed_len, out, outlen);
	else
		tls1v2_prf(secret, secret_len, label, seed, seed_len, out, outlen);
}


/**
 * See mail "TLS1.2 PRF test vectors" sent to tls@ietf.org
 * Link: https://www.ietf.org/mail-archive/web/tls/current/msg03416.html
 */
void tls1v2_prf_test()
{
	uint8_t secret[] = {0x9b, 0xbe, 0x43, 0x6b, 0xa9, 0x40, 0xf0, 0x17,
			    0xb1, 0x76, 0x52, 0x84, 0x9a, 0x71, 0xdb, 0x35};
	uint8_t seed[]   = {0xa0, 0xba, 0x9f, 0x93, 0x6c, 0xda, 0x31, 0x18,
			    0x27, 0xa6, 0xf7, 0x96, 0xff, 0xd5, 0x19, 0x8c};
	const char *label = "test label";
	uint8_t verify[] = {0xE3, 0xF2, 0x29, 0xBA, 0x72, 0x7B, 0xE1, 0x7B, 0x8D, 0x12, 0x26, 0x20, 0x55, 0x7C, 0xD4, 0x53,
			    0xC2, 0xAA, 0xB2, 0x1D, 0x07, 0xC3, 0xD4, 0x95, 0x32, 0x9B, 0x52, 0xD4, 0xE6, 0x1E, 0xDB, 0x5A,
			    0x6B, 0x30, 0x17, 0x91, 0xE9, 0x0D, 0x35, 0xC9, 0xC9, 0xA4, 0x6B, 0x4E, 0x14, 0xBA, 0xF9, 0xAF,
			    0x0F, 0xA0, 0x22, 0xF7, 0x07, 0x7D, 0xEF, 0x17, 0xAB, 0xFD, 0x37, 0x97, 0xC0, 0x56, 0x4B, 0xAB,
			    0x4F, 0xBC, 0x91, 0x66, 0x6E, 0x9D, 0xEF, 0x9B, 0x97, 0xFC, 0xE3, 0x4F, 0x79, 0x67, 0x89, 0xBA,
			    0xA4, 0x80, 0x82, 0xD1, 0x22, 0xEE, 0x42, 0xC5, 0xA7, 0x2E, 0x5A, 0x51, 0x10, 0xFF, 0xF7, 0x01,
			    0x87, 0x34, 0x7B, 0x66};
	uint8_t out[sizeof(verify)] = {0};

	tls1v2_prf(secret, sizeof(secret), label, seed, sizeof(seed), out, sizeof(out));
	
	if (memcmp(verify, out, sizeof(verify)) != 0) {
		PySys_WriteStderr("%s: self-test failed!\n", __FUNCTION__);
		exit(1);
	}

	PySys_WriteStdout("%s: passed\n", __FUNCTION__);
}


/**
 * See mail "PRF Testvector for the standard" sent to "IETF Transport Layer Security WG".
 * Search for http://www.imc.org/ietf-tls/mail-archive/msg01589.html on internet archive.
 */
void tls1v01_prf_test()
{
	/**
	 * The following parameters are passed to PRF:
	 * - secret: 48 Byte 0xab
	 *   Length of pre_master_secret
	 * - label : 14 Byte "PRF Testvector"
	 * - seed  : 64 Byte 0xcd
	 *   Length of client_random + server_random
	 *
	 * out[104]       = PRF(secret, label, seed)
	 * PRF Testvector = MD5(out[104])
	 * 	          = CD 7C A2 CB 9A 6A 3C 6F 34 5C 46 65 A8 B6 81 6B
	 */
	uint8_t secret[48];
	uint8_t seed[64];
	const char *label = "PRF Testvector";
	uint8_t verify[] = {0xD3, 0xD4, 0xD1, 0xE3, 0x49, 0xB5, 0xD5, 0x15, 0x04, 0x46, 0x66, 0xD5, 0x1D, 0xE3, 0x2B, 0xAB,
			    0x25, 0x8C, 0xB5, 0x21, 0xB6, 0xB0, 0x53, 0x46, 0x3E, 0x35, 0x48, 0x32, 0xFD, 0x97, 0x67, 0x54,
			    0x44, 0x3B, 0xCF, 0x9A, 0x29, 0x65, 0x19, 0xBC, 0x28, 0x9A, 0xBC, 0xBC, 0x11, 0x87, 0xE4, 0xEB,
			    0xD3, 0x1E, 0x60, 0x23, 0x53, 0x77, 0x6C, 0x40, 0x8A, 0xAF, 0xB7, 0x4C, 0xBC, 0x85, 0xEF, 0xF6,
			    0x92, 0x55, 0xF9, 0x78, 0x8F, 0xAA, 0x18, 0x4C, 0xBB, 0x95, 0x7A, 0x98, 0x19, 0xD8, 0x4A, 0x5D,
			    0x7E, 0xB0, 0x06, 0xEB, 0x45, 0x9D, 0x3A, 0xE8, 0xDE, 0x98, 0x10, 0x45, 0x4B, 0x8B, 0x2D, 0x8F,
			    0x1A, 0xFB, 0xC6, 0x55, 0xA8, 0xC9, 0xA0, 0x13};
	uint8_t out[sizeof(verify)] = {0};

	memset(secret, 0xab, sizeof(secret));
	memset(seed  , 0xcd, sizeof(seed  ));

	tls1v01_prf(secret, sizeof(secret), label, seed, sizeof(seed), out, sizeof(out));
	
	if (memcmp(verify, out, sizeof(verify)) != 0) {
		PySys_WriteStderr("%s: self-test failed!\n", __FUNCTION__);
		exit(1);
	}

	PySys_WriteStdout("%s: passed\n", __FUNCTION__);
}

