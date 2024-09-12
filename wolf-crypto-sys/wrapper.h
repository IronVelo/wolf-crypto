#ifndef WOLFCRYPT_WRAPPER_H
#define WOLFCRYPT_WRAPPER_H

// Core headers
#include "wolfcrypt/include/wolfssl/wolfcrypt/types.h"
#include "wolfcrypt/include/wolfssl/wolfcrypt/settings.h"
#include "wolfcrypt/include/wolfssl/wolfcrypt/error-crypt.h"
#include "wolfcrypt/include/wolfssl/wolfcrypt/logging.h"
#include "wolfcrypt/include/wolfssl/wolfcrypt/memory.h"
#include "wolfcrypt/include/wolfssl/wolfcrypt/misc.h"
#include "wolfcrypt/include/wolfssl/wolfcrypt/random.h"

// Hash functions
#include "wolfcrypt/include/wolfssl/wolfcrypt/hash.h"
#include "wolfcrypt/include/wolfssl/wolfcrypt/md2.h"
#include "wolfcrypt/include/wolfssl/wolfcrypt/md4.h"
#include "wolfcrypt/include/wolfssl/wolfcrypt/md5.h"
#include "wolfcrypt/include/wolfssl/wolfcrypt/sha.h"
#include "wolfcrypt/include/wolfssl/wolfcrypt/sha256.h"
#include "wolfcrypt/include/wolfssl/wolfcrypt/sha512.h"
#include "wolfcrypt/include/wolfssl/wolfcrypt/sha3.h"
#include "wolfcrypt/include/wolfssl/wolfcrypt/blake2.h"
#include "wolfcrypt/include/wolfssl/wolfcrypt/ripemd.h"

// Symmetric ciphers
#include "wolfcrypt/include/wolfssl/wolfcrypt/aes.h"
#include "wolfcrypt/include/wolfssl/wolfcrypt/des3.h"
#include "wolfcrypt/include/wolfssl/wolfcrypt/arc4.h"
#include "wolfcrypt/include/wolfssl/wolfcrypt/camellia.h"
#include "wolfcrypt/include/wolfssl/wolfcrypt/chacha.h"
#include "wolfcrypt/include/wolfssl/wolfcrypt/chacha20_poly1305.h"
#include "wolfcrypt/include/wolfssl/wolfcrypt/cmac.h"
#include "wolfcrypt/include/wolfssl/wolfcrypt/rc2.h"

// Asymmetric cryptography
#include "wolfcrypt/include/wolfssl/wolfcrypt/rsa.h"
#include "wolfcrypt/include/wolfssl/wolfcrypt/ecc.h"
#include "wolfcrypt/include/wolfssl/wolfcrypt/dh.h"
#include "wolfcrypt/include/wolfssl/wolfcrypt/dsa.h"
#include "wolfcrypt/include/wolfssl/wolfcrypt/curve25519.h"
#include "wolfcrypt/include/wolfssl/wolfcrypt/ed25519.h"
#include "wolfcrypt/include/wolfssl/wolfcrypt/curve448.h"
#include "wolfcrypt/include/wolfssl/wolfcrypt/ed448.h"

// Post-quantum cryptography
#include "wolfcrypt/include/wolfssl/wolfcrypt/kyber.h"
#include "wolfcrypt/include/wolfssl/wolfcrypt/dilithium.h"
#include "wolfcrypt/include/wolfssl/wolfcrypt/sphincs.h"
#include "wolfcrypt/include/wolfssl/wolfcrypt/falcon.h"

// Key derivation and password-based cryptography
#include "wolfcrypt/include/wolfssl/wolfcrypt/pwdbased.h"
#include "wolfcrypt/include/wolfssl/wolfcrypt/pkcs12.h"
#include "wolfcrypt/include/wolfssl/wolfcrypt/tfm.h"
#include "wolfcrypt/include/wolfssl/wolfcrypt/integer.h"
#include "wolfcrypt/include/wolfssl/wolfcrypt/srp.h"

// Additional cryptographic primitives
#include "wolfcrypt/include/wolfssl/wolfcrypt/hmac.h"
#include "wolfcrypt/include/wolfssl/wolfcrypt/poly1305.h"
#include "wolfcrypt/include/wolfssl/wolfcrypt/siphash.h"
#include "wolfcrypt/include/wolfssl/wolfcrypt/hpke.h"

// Encoding and formatting
#include "wolfcrypt/include/wolfssl/wolfcrypt/coding.h"
#include "wolfcrypt/include/wolfssl/wolfcrypt/asn.h"
#include "wolfcrypt/include/wolfssl/wolfcrypt/asn_public.h"
#include "wolfcrypt/include/wolfssl/wolfcrypt/pkcs7.h"
#include "wolfcrypt/include/wolfssl/wolfcrypt/signature.h"

// Platform-specific optimizations
#include "wolfcrypt/include/wolfssl/wolfcrypt/cpuid.h"
#include "wolfcrypt/include/wolfssl/wolfcrypt/cryptocb.h"
#include "wolfcrypt/include/wolfssl/wolfcrypt/wc_encrypt.h"
#include "wolfcrypt/include/wolfssl/wolfcrypt/wc_port.h"
#include "wolfcrypt/include/wolfssl/wolfcrypt/wolfevent.h"
#include "wolfcrypt/include/wolfssl/wolfcrypt/wolfmath.h"

// #include "wolfcrypt/include/wolfssl/wolfcrypt/fe_operations.h"
// #include "wolfcrypt/include/wolfssl/wolfcrypt/ge_operations.h"
// #include "wolfcrypt/include/wolfssl/wolfcrypt/sp_int.h"

#endif // WOLFCRYPT_WRAPPER_H
