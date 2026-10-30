# Keccak SHA-3 / SHAKE Implementation in Java

A Java implementation of the SHA-3 and SHAKE cryptographic primitives specified by FIPS 202. This project implements the Keccak sponge construction and Keccak-f[1600] permutation, supporting SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE-128, and SHAKE-256.

## Features

- SHA3-224
- SHA3-256
- SHA3-384
- SHA3-512
- SHAKE-128
- SHAKE-256
- Keccak-f[1600] permutation
- Sponge absorb and squeeze operations
- Validation using official NIST SHA-3 and SHAKE test vectors

## Building

Compile the project:

```bash
javac Main.java SHA3SHAKE.java
```

Run the application:

```bash
java Main [mode] [arguments]
```

## Attribution

The Keccak-f[1600] implementation was inspired by Markku-Juhani Saarinen's tiny_sha3 reference implementation, as permitted by the project specification.

## Validation

The implementation has been tested against official NIST SHA-3 and SHAKE validation vectors, including SHA3-256, SHA3-512, SHAKE128, and SHAKE256 test cases.
