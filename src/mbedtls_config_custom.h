#include "mbedtls/mbedtls_config.h"
// /*
#define MBEDTLS_DEPRECATED_REMOVED

#undef MBEDTLS_ERROR_C
#undef MBEDTLS_NET_C
#undef MBEDTLS_PEM_PARSE_C
#undef MBEDTLS_PEM_WRITE_C

#undef MBEDTLS_BASE64_C
#undef MBEDTLS_CAMELLIA_C
#undef MBEDTLS_ARIA_C
#undef MBEDTLS_CCM_C
#undef MBEDTLS_CHACHA20_C
#undef MBEDTLS_CHACHAPOLY_C
#undef MBEDTLS_CMAC_C
#undef MBEDTLS_DES_C
#undef MBEDTLS_DHM_C
#undef MBEDTLS_ECJPAKE_C
#undef MBEDTLS_HKDF_C
#undef MBEDTLS_LMS_C
#undef MBEDTLS_NIST_KW_C
#undef MBEDTLS_MD5_C
#undef MBEDTLS_POLY1305_C
#undef MBEDTLS_PSA_CRYPTO_C
#undef MBEDTLS_PSA_CRYPTO_STORAGE_C
#undef MBEDTLS_PSA_ITS_FILE_C
#undef MBEDTLS_SHA1_C
#undef MBEDTLS_SHA224_C
// #undef MBEDTLS_SHA256_C // Only keep this, for TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384
#undef MBEDTLS_SHA384_C
#undef MBEDTLS_SHA512_C

#undef MBEDTLS_CIPHER_MODE_CBC
#undef MBEDTLS_CIPHER_MODE_CFB
#undef MBEDTLS_CIPHER_MODE_CTR
#undef MBEDTLS_CIPHER_MODE_OFB
#undef MBEDTLS_CIPHER_MODE_XTS

#undef MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED

#undef MBEDTLS_SSL_PROTO_DTLS
#undef MBEDTLS_SSL_DTLS_HELLO_VERIFY
#undef MBEDTLS_SSL_DTLS_ANTI_REPLAY
#undef MBEDTLS_SSL_DTLS_CONNECTION_ID
#undef MBEDTLS_SSL_DTLS_CLIENT_PORT_REUSE
#undef MBEDTLS_SSL_DTLS_CONNECTION_ID_COMPAT
#undef MBEDTLS_SSL_DTLS_CLIENT_PORT_REUSE
#undef MBEDTLS_SSL_DTLS_CONNECTION_ID_COMPAT
#undef MBEDTLS_SSL_DTLS_CLIENT_PORT_REUSE

// #undef MBEDTLS_SSL_PROTO_TLS1_2
// #undef MBEDTLS_SSL_ENCRYPT_THEN_MAC
// #undef MBEDTLS_SSL_EXTENDED_MASTER_SECRET
// #undef MBEDTLS_SSL_RENEGOTIATION
// #undef MBEDTLS_SSL_TLS_AES

// #undef MBEDTLS_SSL_PROTO_TLS1_3
// #undef MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
// #undef MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED
// #undef MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED
// #undef MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED

// #undef MBEDTLS_PKCS1_V15 // cause error
#undef MBEDTLS_PKCS1_V21
#undef MBEDTLS_PKCS5_C
#undef MBEDTLS_PKCS7_C
#undef MBEDTLS_PKCS12_C
#undef MBEDTLS_X509_RSASSA_PSS_SUPPORT

#undef MBEDTLS_PK_RSA_ALT_SUPPORT
#undef MBEDTLS_SELF_TEST

#undef MBEDTLS_SSL_ENCRYPT_THEN_MAC
#undef MBEDTLS_SSL_EXTENDED_MASTER_SECRET
#undef MBEDTLS_SSL_RENEGOTIATION
#undef MBEDTLS_SSL_MAX_FRAGMENT_LENGTH
// #undef MBEDTLS_SSL_KEEP_PEER_CERTIFICATE // even bigger

// https://github.com/Mbed-TLS/mbedtls/tree/development/configs
// */

// #define MBEDTLS_SSL_PROTO_TLS1_3
