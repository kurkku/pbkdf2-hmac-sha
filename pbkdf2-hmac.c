
#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#include "pbkdf2-hmac.h"

int generate_salt(char** salt) {
  int i = 0;
  int c = 0;
  // The array mustn't contain SEPARATOR
  char valid_chars[] = "abcdefghijklmnopqrstuvwxyz"
                       "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                       "0123456789"
                       "!@#$%^&*()-_=+|[]{};,.<>?/~";
  int valid_chars_len = strlen(valid_chars);
  unsigned char rand_bytes[PBKDF2_SALT_LENGTH];

  *salt = malloc(PBKDF2_SALT_LENGTH);
  if (!salt) {
    return 1;
  }

  // Generate enough randon bytes
  if (RAND_bytes(rand_bytes, PBKDF2_SALT_LENGTH) != 1) {
    return 1;
  }

  // Convert random bytes to ASCII characters
  for (i = 0; i < PBKDF2_SALT_LENGTH; i++) {
    c = rand_bytes[i] % valid_chars_len;
    (*salt)[i] = valid_chars[c];
  }

  return 0;
}

void hash_password(const char* password, const unsigned char* salt, char* result) {
  int i = 0;
  static unsigned char digest[PBKDF2_DIGEST_LENGTH];

  memset(result, 0, PBKDF2_RESULT_LENGTH);

  // Add salt and the separator in the beginning of the result.
  memcpy(result, salt, PBKDF2_SALT_LENGTH);
  result[PBKDF2_SALT_LENGTH] = SEPARATOR;

  // Generate the digest
  PKCS5_PBKDF2_HMAC(password, strlen(password), salt, PBKDF2_SALT_LENGTH,
                    PBKDF2_ITERATIONS, PBKDF2_PRF_ALGORITHM,
                    PBKDF2_DIGEST_LENGTH, digest);

  // Convert the hash to ASCII and add it to the result.
  for (i = 0; i < sizeof(digest); i++) {
    sprintf(result + PBKDF2_SALT_LENGTH + 1 + (i * 2), "%02x", 255 & digest[i]);
  }
}
