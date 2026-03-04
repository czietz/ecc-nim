# SPDX-License-Identifier: MIT

## A Nim wrapper around the micro-ecc C library, providing Elliptic Curve Cryptography (ECC)
## primitives including ECDSA signing/verification and ECDH shared secret generation.
##
## Copyright (c) 2026 Christian Zietz <czietz@gmx.net>
##
## Licensed under the MIT license.

import std/random
import std/typetraits
import std/sequtils
# included as git submodule, to avoid system-wide installation
import checksums/src/checksums/sha2

# micro-ecc library from https://github.com/kmackay/micro-ecc.git
{.compile: "micro-ecc/uECC.c".}

type
    ECCError* = object of CatchableError    ## Exception raised by this library

#-# CURVES #-#

type
    uECC_Curve {.importc: "uECC_Curve", header: "micro-ecc/uECC.h".} = object
        discard

type CurveType* = enum
    ## Supported curves
    Curve_secp160r1,
    Curve_secp192r1,
    Curve_secp224r1,
    Curve_secp256r1,
    Curve_secp256k1,

type Curve* = object
    ## Represents a curve and must be instantiated by newCurve_
    ctype: CurveType
    curveSize: int
    privateKeySize: int
    publicKeySize: int
    getCurve: uECC_Curve

proc uECC_curve_public_key_size(curve: uECC_Curve): cint {.importc, header: "micro-ecc/uECC.h".}    
proc uECC_curve_private_key_size(curve: uECC_Curve): cint {.importc, header: "micro-ecc/uECC.h".}

proc uECC_secp160r1(): uECC_Curve {.importc, header: "micro-ecc/uECC.h".}
proc uECC_secp192r1(): uECC_Curve {.importc, header: "micro-ecc/uECC.h".}
proc uECC_secp224r1(): uECC_Curve {.importc, header: "micro-ecc/uECC.h".}
proc uECC_secp256r1(): uECC_Curve {.importc, header: "micro-ecc/uECC.h".}
proc uECC_secp256k1(): uECC_Curve {.importc, header: "micro-ecc/uECC.h".}

proc newCurve*(T: CurveType): Curve =
    ## Instantiates a curve of given CurveType_
    result.ctype = T
    case T:
        of Curve_secp160r1:
            result.getCurve = uECC_secp160r1()
        of Curve_secp192r1:
            result.getCurve = uECC_secp192r1()
        of Curve_secp224r1:
            result.getCurve = uECC_secp224r1()
        of Curve_secp256r1:
            result.getCurve = uECC_secp256r1()
        of Curve_secp256k1:
            result.getCurve = uECC_secp256k1()
    result.publicKeySize = uECC_curve_public_key_size(result.getCurve)
    result.privateKeySize = uECC_curve_private_key_size(result.getCurve)
    result.curveSize = result.publicKeySize div 2

proc getPublicKeySize*(C: Curve, compressed = false): int =
    ## Returns the length in bytes of the public key (uncompressed or compressed)
    if compressed:
        return C.curveSize + 1
    else:
        return C.publicKeySize

proc getCurveSize*(C: Curve): int = C.curveSize             ## Returns the curve order / 8 ("length" of the curve in *bytes*)

proc getPrivateKeySize*(C: Curve): int = C.privateKeySize   ## Returns the length in bytes of the private key

proc getSignatureSize*(C: Curve): int = 2 * C.curveSize     ## Returns the length in bytes of a ECDSA signature

proc getSharedSecretSize*(C: Curve): int = C.curveSize      ## Returns the length in bytes of a ECDH shared secret

proc getCurveType*(C: Curve): CurveType = C.ctype           ## Returns the CurveType_

#-# KEYS, SIGNATURES, AND SHARED SECRETS #-#

type ECPrivateKey* = object
    ## Represents a private key
    curve: Curve
    key: seq[char]

type ECPublicKey* = object
    ## Represents a public key
    curve: Curve
    key: seq[char]

type ECKeyPair* = tuple
    ## Represents a key pair
    public: ECPublicKey
    private: ECPrivateKey

type ECDSASignature* = seq[char]    ## Represents a ECDSA signature

type ECDHSharedSecret* = seq[char]  ## Represents a ECDH shared secret

proc getCurve*(P: ECPrivateKey): Curve = P.curve    ## Returns the Curve_ the key is on

proc getCurve*(P: ECPublicKey): Curve = P.curve     ## Returns the Curve_ the key is on


#-# HELPERS FOR PRIVATE KEY DESTRUCTION #-#

proc zeroSequence*[T](s: seq[T]) =
    ## Zeroes the contents of a sequence
    when supportsCopyMem(T):
        if s.len > 0:
            zeroMem(addr s[0], s.len * sizeof(T))
    else:
        {.error: "T must be a plain data type (no managed fields)".}

proc zeroSequence*(s: string) =
    ## Zeroes the contents of a string
    if s.len > 0:
        zeroMem(addr s[0], s.len)

proc `=destroy`*(P: var ECPrivateKey) =
    # clear private key data so it's removed from memory
    zeroSequence(P.key)
    `=destroy`(P.curve)
    `=destroy`(P.key)


#-# RANDOM NUMBERS #-#

type rngFunction* = proc (dest: ptr UncheckedArray[char], size: cuint): cuint {.cdecl.}
proc uECC_get_rng: pointer {.importc, header: "micro-ecc/uECC.h", used.} 
proc uECC_set_rng(rng: rngFunction) {.importc, header: "micro-ecc/uECC.h", used.}

# NON(!!!)-cryptographically secure RNG based on Nim's PRNG
var randstate: Rand
proc weakPRNG(dest: ptr UncheckedArray[char], size: cuint): cuint {.cdecl, used.} =
    for i in 0 ..< int(size):
        dest[i] = randstate.rand(char)
    return 1

proc useCustomRNG*(RNG_func: rngFunction) =
    ## Use custom random number generator (RNG)
    ##
    ## By default, micro-ecc uses the system's secure random generator. This is
    ## the recommended mode of operation. However, on systems where micro-ecc fails
    ## to find a secure random generator, you can provide your own RNG. This RNG
    ## must be cryptographically secure, otherwise keys and signatures will be weak!
    ##
    ## The function signature of the RNG is:
    ##
    ## `proc (dest: ptr UncheckedArray[char], size: cuint): cuint {.cdecl.}`
    ##
    ## The RNG must fill in `size` chars into the array `dest` and return 1. It
    ## can also return 0 to signal that the random generation failed.
    uECC_set_rng(RNG_func)

proc useWeakInternalRNG*(seed: int64) {.deprecated: "this RNG is not cryptographically secure".} =
    ## Use Nim's internal random number generator (RNG)
    ##
    ## This **not cryptographically secure** and should only be used for testing!
    ## In particular, keys and signatures generated while using this RNG are weak.
    ##
    ## Note: By default, micro-ecc uses the system's secure random generator. This is
    ## the recommended mode of operation.
    randstate = initRand(seed)
    useCustomRNG(weakPRNG)


#-# KEY GENERATION #-#

proc uECC_make_key(public: ptr[char], private: ptr[char], curve: uECC_Curve): cint {.importc, header: "micro-ecc/uECC.h".}

proc makeKeyPair*(C: Curve): ECKeyPair =
    ## Generates a pair of public and private key
    var priv = ECPrivateKey(curve: C, key: newSeq[char](C.privateKeySize))
    var pub = ECPublicKey(curve: C, key: newSeq[char](C.publicKeySize))
    let ret = uECC_make_key(addr pub.key[0], addr priv.key[0], C.getCurve)
    if ret == 0: raise newException(ECCError, "key generation failed")
    return (public: pub, private: priv)

proc uECC_compute_public_key(private: ptr[char], public: ptr[char], curve: uECC_Curve): cint {.importc, header: "micro-ecc/uECC.h".}

proc getPublicKey*(P: ECPrivateKey): ECPublicKey =
    ## Computes the public key for a given private key
    result = ECPublicKey(curve: P.curve, key: newSeq[char](P.curve.publicKeySize))
    let ret = uECC_compute_public_key(addr P.key[0], addr result.key[0], P.curve.getCurve)
    if ret == 0: raise newException(ECCError, "could not compute public key")


#-# PUBLIC KEY EXPORT AND IMPORT #-#

proc uECC_compress(public: ptr[char], compressed: ptr[char], curve: uECC_Curve) {.importc, header: "micro-ecc/uECC.h".}

proc toBytes*(P: ECPublicKey, compressed = false): seq[char] =
    ## Exports a public key for storage, optionally in `compressed` format
    ##
    ## Compressed keys are represented in SEC1 v2 format, whereas uncompressed
    ## keys are just the point coordinates. (See toBytesSec1_ for export in SEC1 v2
    ## compliant uncompressed format.)
    if compressed:
        var compressed = newSeq[char](P.curve.curveSize + 1)
        uECC_compress(addr P.key[0], addr compressed[0], P.curve.getCurve)
        return compressed
    else:
        return P.key

proc toBytesSec1*(P: ECPublicKey): seq[char] =
    ## Exports a public key for storage, in SEC1-v2-compliant *uncompressed* format
    return chr(4) & P.toBytes(false)

proc uECC_valid_public_key(public: ptr[char], curve: uECC_Curve): cint {.importc, header: "micro-ecc/uECC.h".}

proc validPublicKey(P: ECPublicKey): bool =
    return (uECC_valid_public_key(addr P.key[0], P.curve.getCurve) == 1)

proc uECC_decompress(compressed: ptr[char], public: ptr[char], curve: uECC_Curve) {.importc, header: "micro-ecc/uECC.h".}

proc loadPublicKey*(C: Curve, bytes: openArray[char], compressed = false): ECPublicKey =
    ## Imports a public key
    ##
    ## When `compressed` is set, compressed SEC1 v2 format is expected.
    ## Otherwise guess the key format based on the input length:
    ## * Compressed SEC1 v2 format (as returned by toBytes_)
    ## * Uncompressed raw format (as returned by toBytes_)
    ## * Uncompressed SEC1 v2 format (as returned by toBytesSec1_)
    ##
    ## If the key is invalid (wrong length, not on the curve), an ECCError_ is
    ## raised. Thus, this function may be used with untrusted input.
    if compressed or bytes.len < C.publicKeySize:
        if bytes.len != C.curveSize + 1: raise newException(ECCError, "invalid public key size")
        if bytes[0] notin {'\x02', '\x03'}: raise newException(ECCError, "invalid compressed public key")
        result = ECPublicKey(curve: C, key: newSeq[char](C.publicKeySize))
        uECC_decompress(addr bytes[0], addr result.key[0], result.curve.getCurve)
    else:
        # support uncompressed key in SEC 1 format (0x04 || key)
        if (bytes.len == C.publicKeySize + 1) and (bytes[0] == '\x04'):
            result = ECPublicKey(curve: C, key: @bytes[1..^1])
        elif bytes.len == C.publicKeySize:
            result = ECPublicKey(curve: C, key: @bytes)
        else:
            raise newException(ECCError, "invalid public key size")
    let ret = validPublicKey(result)
    if not ret: raise newException(ECCError, "invalid public key")


#-# PRIVATE KEY EXPORT AND IMPORT #-#

proc toBytes*(P: ECPrivateKey): seq[char] =
    ## Exports a private key for storage
    return P.key

proc allZeros(bytes: openArray[char]): bool {.inline.} =
    allIt(bytes, it == '\0')

proc loadPrivateKey*(C: Curve, bytes: openArray[char]): ECPrivateKey =
    ## Imports a private key
    if bytes.len != C.privateKeySize: raise newException(ECCError, "invalid private key size")
    if allZeros(bytes): raise newException(ECCError, "invalid private key")
    return ECPrivateKey(curve: C, key: @bytes)


#-# ECDSA SIGNATURES #-#

proc uECC_sign(private: ptr[char],
               message_hash: ptr[char], 
               hash_size: cuint,
               signature: ptr[char],
               curve: uECC_Curve): cint {.importc, header: "micro-ecc/uECC.h".}

proc ecDsaSign*(P: ECPrivateKey, messageHash: openArray[char]): ECDSASignature =
    ## Signs a message hash with the given private key, returning the signature.
    ##
    ## Note: According to the standard, the hash is truncated if it is longer
    ## than the curve length.
    result = newSeq[char](P.curve.getSignatureSize)
    let ret = uECC_sign(addr P.key[0], addr messageHash[0], cuint(messageHash.len), addr result[0], P.curve.getCurve)
    if ret == 0: raise newException(ECCError, "signature generation failed")

proc ecDsaHashAndSign*(P: ECPrivateKey, message: openArray[char], hasher = Sha_256): ECDSASignature =
    ## Hashes a message with the given `hasher`, then signs the hash with the given private key,
    ## returning the signature.
    let hash = hasher.secureHash(message)
    return ecDsaSign(P, hash)

proc uECC_verify(public: ptr[char],
                message_hash: ptr[char],
                hash_size: cuint,
                signature: ptr[char],
                curve: uECC_Curve): cint {.importc, header: "micro-ecc/uECC.h".}

proc ecDsaVerify*(P: ECPublicKey, messageHash: openArray[char], signature: ECDSASignature): bool =
    ## Verifies a message hash and signature versus the given public key
    ##
    ## Returns `true` if the signature is valid.
    if signature.len != P.curve.getSignatureSize: raise newException(ECCError, "invalid signature size")
    let ret = uECC_verify(addr P.key[0], addr messageHash[0], cuint(messageHash.len), addr signature[0], P.curve.getCurve)
    return (ret == 1)

proc ecDsaHashAndVerify*(P: ECPublicKey, message: openArray[char], signature: ECDSASignature, hasher = Sha_256): bool =
    ## Hashes a message with the given `hasher`, then verifies the hash and signature versus the given public key.
    ##
    ## Returns `true` if the signature is valid.
    let hash = hasher.secureHash(message)
    return ecDsaVerify(P, cast[seq[char]](hash), signature)

#-# ECDH SHARED SECRET #-#

proc uECC_shared_secret(public: ptr[char],
                        private: ptr[char],
                        secret: ptr[char],
                        curve: uECC_Curve): cint {.importc, header: "micro-ecc/uECC.h".}

proc ecSharedSecret*(P: ECPublicKey, Q: ECPrivateKey): ECDHSharedSecret =
    ## Generates a shared secret with someone else's public key and a private key
    ##
    ## It is recommended that you hash the result before using it for symmetric encryption
    var secret = newSeq[char](Q.curve.getSharedSecretSize)
    if P.curve != Q.curve: raise newException(ECCError, "keys are not on the same curve")
    let ret = uECC_shared_secret(addr P.key[0], addr Q.key[0], addr secret[0], Q.curve.getCurve)
    if ret == 0: raise newException(ECCError, "shared secret generation failed")
    return secret

proc hmacSha256(key: openArray[char], message: openArray[char]): ShaDigest_256 =
    # A HMAC SHA-256 implementation
    const
        BlockSize = 64
        IPad = 0x36'u8
        OPad = 0x5C'u8

    # normalize key to block size
    # remaining bytes are already zero (array is zero-initialized)
    var normKey: array[BlockSize, byte]
    if key.len > BlockSize:
        let hashed = Sha_256.secureHash(key)
        copyMem(addr normKey[0], addr hashed[0], hashed.len)
    else:
        copyMem(addr normKey[0], addr key[0], key.len)

    # create inner and outer padded keys
    var innerKey: array[BlockSize, char]
    var outerKey: array[BlockSize, char]
    for i in 0 ..< BlockSize:
        innerKey[i] = chr(normKey[i] xor IPad)
        outerKey[i] = chr(normKey[i] xor OPad)

    # inner hash
    var innerCtx = initSha256()
    innerCtx.update(innerKey)
    innerCtx.update(message)
    let innerHash = innerCtx.digest()

    # outer hash
    var outerCtx = initSha256()
    outerCtx.update(outerKey)
    outerCtx.update(innerHash)
    result = outerCtx.digest()

proc ecHMACSharedSecret*(P: ECPublicKey, Q: ECPrivateKey, nonce: openArray[char] = []): ShaDigest_256 =
    ## Generates a shared secret with someone else's public key and a private key
    ##
    ## Then performs a HMAC SHA256 with the shared secret as key and the optional `nonce`,
    ## which must be shared by both parties. Returns the HMAC, which can be used,
    ## e.g., as session-specific secret.
    let secret = ecSharedSecret(P, Q)
    defer: zeroSequence(secret)
    result = hmacSha256(secret, nonce)

proc ecHashedSharedSecret*(P: ECPublicKey, Q: ECPrivateKey, nonce: openArray[char] = [], hasher = Sha_256): seq[char] =
    ## Generates a shared secret with someone else's public key and a private key
    ##
    ## Then hashes the secret and and optional `nonce`, which must be shared by
    ## both parties, with the given `hasher`. Returns the hash, which can be used,
    ## e.g., as session-specific secret.
    ##
    ## Note: Is susceptible to a "Length Extension Attack" when an attacker can
    ## control the nonce. In that situation, use ecHMACSharedSecret instead.
    let secret = ecSharedSecret(P, Q)
    defer: zeroSequence(secret)
    var ctx = initSha(hasher)
    result = newSeqOfCap[char](hasher.digestLength())
    result.setLen(hasher.digestLength())
    ctx.update(secret)
    ctx.update(nonce)
    discard ctx.digest(result)


when isMainModule:

    # run some tests

    # generate a key-pair
    let u = newCurve(Curve_secp160r1)
    var x = u.makeKeyPair()

    # different forms of key export
    let a = x.public.toBytes()
    let a2 = x.public.toBytesSec1()
    let b = x.public.toBytes(compressed = true)
    let c = x.private.toBytes()

    # different forms of key import
    let d = u.loadPublicKey(a)
    let d2 = u.loadPublicKey(a2)
    let e = u.loadPublicKey(b)
    let f = x.private.getPublicKey()

    # test invalid public key
    let a3 = newSeq[char](u.getPublicKeySize)
    try:
        discard u.loadPublicKey(a3)
        doAssert(false, "Failed to recognize invalid public key")
    except ECCError:
        discard

    # test that imported keys match
    doAssert(d == x.public)
    doAssert(d2 == x.public)
    doAssert(e == x.public)
    doAssert(f == x.public)

    let g = u.loadPrivateKey(c)
    doAssert(g == x.private)

    # scrub 'c' from memory
    zeroSequence(c)
    doAssert(allZeros(c))

    # test that loading scrubbed key fails
    try:
        discard u.loadPrivateKey(c)
        doAssert(false, "Failed to recognize invalid private key")
    except ECCError:
        discard

    # test signature and verification
    let m = "Hello"
    let h = x.private.ecDsaHashAndSign(m)
    let j = x.public.ecDsaHashAndVerify(m, h)
    doAssert(j)
    let m2 = "Bye!"
    let j2 = x.public.ecDsaHashAndVerify(m2, h)
    doAssert(not j2)

    # test shared secret generation with a second key pair
    let y = u.makeKeyPair()

    let k = ecHashedSharedSecret(x.public, y.private, "nonce")
    let l = ecHashedSharedSecret(y.public, x.private, "nonce")
    let l2 = ecHashedSharedSecret(y.public, x.private, "ecnon")
    doAssert(k == l)
    doAssert(k != l2)

    # test HMAC SHA256 with RFC4231 test vector
    let o = hmacSha256('\x0b'.repeat(20), "Hi There")
    doAssert($o == "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")

    # test shared secret generation with HMAC SHA256
    let p = ecHMACSharedSecret(x.public, y.private, "nonce")
    let q = ecHMACSharedSecret(y.public, x.private, "nonce")
    let q2 = ecHMACSharedSecret(y.public, x.private, "ecnon")
    doAssert(p == q)
    doAssert(p != q2)

    echo "All tests passed"