#include <stdio.h>
#include <string.h>

#include "pbkdf2-hmac.h"

int main() {

  // Generate unique salt string
  char* salt = 0;
  if (generate_salt(&salt) != 0) {
    printf("generate_salt");
    return 1;
  }

  const char* pw = "mr shine, him diamond!";

  // Generate a hash from the password and the salt.
  char result[PBKDF2_RESULT_LENGTH];
  hash_password(pw, salt, result);

  printf("Result: %s\n", result);

  // Verification
  puts("Validating...");
  strncpy(salt, result, PBKDF2_SALT_LENGTH);
  char* userpass = "mr shine, him diamond!";

  char r1[PBKDF2_RESULT_LENGTH];
  hash_password(userpass, salt, r1);
  printf("Result: %s\n", r1);

  // Compare the strings
  int ret = strncmp(result, r1, PBKDF2_RESULT_LENGTH);

  printf("Validation: %s\n", ((ret == 0) ? "Passed" : "Failed"));

  free(salt);
  return 0;
}
