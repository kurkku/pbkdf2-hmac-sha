PBKDF2 HMAC SHA256 module in C

## Background
The C module contains a wrapper for OpenSSL's PBKDF2 implementation, and a simple salt generator.

PBKDF2 (Password-Based Key Derivation Function #2), defined in PKCS #5, is an algorithm for deriving a random value from a password.

The algorithms applies a pseudo-random function -- SHA256 HMAC in this case -- to the password along with a salt string and repeats the process multiple times to create a derived key (i.e., a hash). The derived key can be stored -- along with the plain-text salt string -- to, for example, a password file or database table.

Using a salt along with the password reduces the ability to use rainbow tables to crack the hash. Increasing the number of iterations makes it harder to crack the password using brute force methods but it slows down the key derivation too.

More information:
* (RCF2898)[https://tools.ietf.org/html/rfc2898]
* (Wikipedia)[https://en.wikipedia.org/wiki/PBKDF2]

## Usage
See `test.c` for a sample program.

Basically, function `hash_password` returns a digest string that can be stored to persistent storage. The string has the format of
```
[salt] + SEPARATOR + [digest]
```
where `[digest]` is `pbkdf2-sha256([salt], [password], iter=PBKDF2_ITERATIONS)`.
