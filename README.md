# ecc.nim

A Nim wrapper around the [micro-ecc](https://github.com/kmackay/micro-ecc) C library, providing [Elliptic Curve Cryptography](https://cryptobook.nakov.com/asymmetric-key-ciphers/elliptic-curve-cryptography-ecc) (ECC) primitives including ECDSA signing/verification and ECDH shared secret generation.

## Features

- **Key generation** — generate EC key pairs or derive a public key from a private key
- **ECDSA** — sign and verify message hashes (with optional built-in SHA-2 hashing)
- **ECDH** — compute shared secrets between two parties, with optional nonce-salted hashing
- **Key import/export** — serialize and deserialize keys in raw or [SEC1 v2](https://www.secg.org/sec1-v2.pdf) format (compressed and uncompressed)
- **Multiple curves** — supports secp160r1, secp192r1, secp224r1, secp256r1, and secp256k1

## Dependencies

- [micro-ecc](https://github.com/kmackay/micro-ecc) — included as a git submodule (`micro-ecc/`)
- [checksums](https://github.com/nim-lang/checksums) — included as a git submodule (`checksums/`) for SHA-2 hashing

Clone with submodules:

```sh
git clone --recurse-submodules https://github.com/czietz/ecc-nim.git
```

## Usage

### Choosing a Curve

```nim
let curve = newCurve(Curve_secp256r1)
```

Supported curve types: `Curve_secp160r1`, `Curve_secp192r1`, `Curve_secp224r1`, `Curve_secp256r1`, `Curve_secp256k1`.

### Key Generation

```nim
let keyPair = curve.makeKeyPair()
let pubKey  = keyPair.public
let privKey = keyPair.private

# Derive public key from an existing private key
let derived = privKey.getPublicKey()
```

### Key Export and Import

```nim
# Export
let rawPub        = pubKey.toBytes()                  # raw uncompressed
let compressedPub = pubKey.toBytes(compressed = true) # SEC1 compressed
let sec1Pub       = pubKey.toBytesSec1()              # SEC1 uncompressed (0x04 prefix)
let rawPriv       = privKey.toBytes()

# Import
let loadedPub  = curve.loadPublicKey(rawPub)
let loadedPub2 = curve.loadPublicKey(compressedPub, compressed = true)
let loadedPriv = curve.loadPrivateKey(rawPriv)
```

`loadPublicKey` validates the key and raises `ECCError` on invalid input, making it safe to use with untrusted data.

### ECDSA Signing and Verification

```nim
let message   = "Hello, world!"
let signature = privKey.ecDsaHashAndSign(message)          # hashes with SHA-256, then signs
let valid     = pubKey.ecDsaHashAndVerify(message, signature) # true if valid

# Or provide your own hash
let hash = myHash(message)
let sig2  = privKey.ecDsaSign(hash)
let ok    = pubKey.ecDsaVerify(hash, sig2)
```

### ECDH Shared Secret

```nim
let aliceKeys = curve.makeKeyPair()
let bobKeys   = curve.makeKeyPair()

# Both sides compute the same secret
let secretA = ecHashedSharedSecret(bobKeys.public, aliceKeys.private, nonce = "session-id")
let secretB = ecHashedSharedSecret(aliceKeys.public, bobKeys.private, nonce = "session-id")

assert secretA == secretB  # true
```

The raw (unhashed) version is also available via `ecSharedSecret`. It is recommended to hash the result before using it as a symmetric key.

## Running the Built-in Tests

```sh
nim c -r ecc.nim
```

This compiles and runs the self-tests at the bottom of the file, exercising key generation, import/export, ECDSA, and ECDH.

## Security Notes

- By default, micro-ecc uses the **system's cryptographically secure RNG**. This is the recommended mode of operation.
- A `useWeakInternalRNG` proc is available for testing purposes only. It is marked `deprecated` and **must not be used in production**, as the Nim PRNG it uses is not cryptographically secure.
- Always hash ECDH shared secrets before use as symmetric keys.
- The destructor for private key objects explicitly zeroes the key data. For plain sequences, such as exported private keys or ECDH shared secrets, no custom destructor is possible. If you worry about leaking secret data in memory, a helper function `zeroSequence` is provided. (You might also use the `defer:` statement to make sure `zeroSequence` is run at the end of the current block.)

```nim
# Clear exported private key from memory
zeroSequence(rawPriv)
```

## OpenSSH compatibility

A supplementary package `sshcompat` is provided that adds support for OpenSSH-compatible public and private keys and signatures in `ecdsa-sha2-nistp256` format. See the documentation inside the file for a description of functions and limitations.

Note: The OpenSSH format adds overhead. If you care about performance and not about OpenSSH compatibility, you should use the functions from ecc.nim instead – as described above.

## License

Copyright (c) 2026 Christian Zietz <czietz@gmx.net>

This wrapper is licensed under the **MIT License**. The underlying [micro-ecc](https://github.com/kmackay/micro-ecc) library is licensed under BSD 2-Clause. See its repository for details.
