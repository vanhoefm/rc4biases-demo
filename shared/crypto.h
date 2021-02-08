#ifndef biases_crypto_h_
#define biases_crypto_h_

#include <stdint.h>
#include <openssl/evp.h>

enum EncType {
	EncType_Unknown,
	EncType_TKIP,
	EncType_CCMP
};

//
// SSL/TLS functions
//

#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined (LIBRESSL_VERSION_NUMBER)
HMAC_CTX *HMAC_CTX_new(void);
void HMAC_CTX_free(HMAC_CTX *ctx);
EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void);
void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx);
#endif

void hmac_vector(const EVP_MD *hashtype, const uint8_t *key, size_t key_len, size_t num_elem,
		      const uint8_t *addr[], const size_t *len, uint8_t *mac);

void tls1v01_prf(const uint8_t *secret, size_t secret_len, const char *label,
		 const uint8_t *seed, size_t seed_len, uint8_t *out, size_t outlen);
void tls1v2_prf(const uint8_t *secret, size_t secret_len, const char *label,
		const uint8_t *seed, size_t seed_len, uint8_t *out, size_t outlen);

/** Auto-select correct RPF based on SSL/TLS version */
void ssl_tls_prf(uint8_t vermajor, uint8_t verminor, const uint8_t *secret, size_t secret_len,
		 const char *label, const uint8_t *seed, size_t seed_len, uint8_t *out, size_t outlen);

void tls1v01_prf_test();
void tls1v2_prf_test();

#endif // biases_crypto_h_
