#include <openssl/evp.h>
#include <openssl/sha.h>

#define PBKDF2_PRF_ALGORITHM  EVP_sha256()
#define PBKDF2_DIGEST_LENGTH  SHA512_DIGEST_LENGTH
#define PBKDF2_SALT_LENGTH    32
#define PBKDF2_RESULT_LENGTH  PBKDF2_SALT_LENGTH + (2 * PBKDF2_DIGEST_LENGTH) + 1
#define SEPARATOR             ':'

/* Increase the iteration count to mitigate the brute force attack effectivity. */
#define PBKDF2_ITERATIONS     64000

/*
 * Generates a random ASCII string with num charactes that can be used as a salt.
 * Character SEPARATOR is not used in the string.
 *
 * Returns zero on success, otherwise a non-zero value.
 */
int generate_salt(char** salt);

/*
 * Creates a SHA256 digest from a password and a salt using PBKDF2-HMAC.
 * See RFC2898 or https://en.wikipedia.org/wiki/PBKDF2 for more information.
 *
 * The result will contain following information:
 *   [salt] + SEPARATOR + [digest]
 * where [digest] is pbkdf2-sha256([salt], [password], iter=PBKDF2_ITERATIONS).
 */
void hash_password(const char* password, const unsigned char* salt, char* result);
