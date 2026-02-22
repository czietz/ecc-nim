# SPDX-License-Identifier: MIT

## A Nim wrapper around the micro-ecc C library, providing Elliptic Curve Cryptography (ECC)
## primitives including ECDSA signing/verification and ECDH shared secret generation.
##
## Copyright (c) 2026 Christian Zietz <czietz@gmx.net>
##
## Licensed under the MIT license.

import std/random
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

type Curve* = object
    ## Represents a curve and must be instantiated by newCurve_
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

type CurveType* = enum
    ## Supported curves
    Curve_secp160r1,
    Curve_secp192r1,
    Curve_secp224r1,
    Curve_secp256r1,
    Curve_secp256k1,

proc newCurve*(T: CurveType): Curve =
    ## Instantiates a curve of given CurveType_
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


#-# RANDOM NUMBERS #-#

type rngFunction = proc (dest: ptr UncheckedArray[char], size: cuint): cuint {.cdecl.}
proc uECC_get_rng: pointer {.importc, header: "micro-ecc/uECC.h", used.} 
proc uECC_set_rng(rng: rngFunction) {.importc, header: "micro-ecc/uECC.h", used.}

# NON(!!!)-cryptographically secure RNG based on Nim's PRNG
var randstate: Rand
proc weakPRNG(dest: ptr UncheckedArray[char], size: cuint): cuint {.cdecl, used.} =
    for i in 0 ..< int(size):
        dest[i] = randstate.rand(char)
    return 1

proc useWeakInternalRNG*(seed: int64) {.deprecated: "this RNG is not cryptographically secure".} =
    ## Use Nim's internal random number generator (RNG)
    ##
    ## This **not cryptographically secure** and should only be used for testing!
    ## In particular, keys and signatures generated while using this RNG are weak.
    ##
    ## Note: By default, micro-ecc uses the system's secure random generator. This is
    ## the recommended mode of operation.
    randstate = initRand(seed)
    uECC_set_rng(weakPRNG)


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

proc toBytesSec1*(P: ECPublicKey, compressed = false): seq[char] =
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
        result = ECPublicKey(curve: C, key: newSeq[char](C.publicKeySize))
        uECC_decompress(addr bytes[0], addr result.key[0], result.curve.getCurve)
    else:
        # support uncompressed key in SEC 1 format (0x04 || key)
        if (bytes.len == C.publicKeySize + 1) and (bytes[0] == chr(4)):
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

proc loadPrivateKey*(C: Curve, bytes: openArray[char]): ECPrivateKey =
    ## Imports a private key
    if bytes.len != C.privateKeySize: raise newException(ECCError, "invalid private key size")
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
    ## It is recommended that you hash the result before using it for symmetric encryption or HMAC.
    var secret = newSeq[char](Q.curve.getSharedSecretSize)
    if P.curve != Q.curve: raise newException(ECCError, "keys are not on the same curve")
    let ret = uECC_shared_secret(addr P.key[0], addr Q.key[0], addr secret[0], Q.curve.getCurve)
    if ret == 0: raise newException(ECCError, "shared secret generation failed")
    return secret

proc ecHashedSharedSecret*(P: ECPublicKey, Q: ECPrivateKey, nonce: openArray[char] = [], hasher = Sha_256): seq[char] =
    ## Generates a shared secret with someone else's public key and a private key
    ##
    ## Then hashes the secret and and optional `nonce`, which must be shared by
    ## both parties, with the given `hasher`. Returns the hash, which can be used,
    ## e.g., as session-specific secret.
    let secret = ecSharedSecret(P, Q)
    var ctx = initSha(hasher)
    result = newSeqOfCap[char](hasher.digestLength())
    result.setLen(hasher.digestLength())
    ctx.update(nonce)
    ctx.update(secret)
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
        doAssert(false, "Failed to recognize invalid key")
    except ECCError:
        discard

    # test that imported keys match
    doAssert(d == x.public)
    doAssert(d2 == x.public)
    doAssert(e == x.public)
    doAssert(f == x.public)

    let g = u.loadPrivateKey(c)

    doAssert(g == x.private)

    # test signature and verification
    let m = "Hello"
    let h = x.private.ecDsaHashAndSign(m)
    let j = x.public.ecDsaHashAndVerify(m, h)
    doAssert(j)

    # test shared secret generation with a second key pair
    let y = u.makeKeyPair()

    let k = ecHashedSharedSecret(x.public, y.private, "nonce")
    let l = ecHashedSharedSecret(y.public, x.private, "nonce")
    doAssert(k == l)

    echo "All tests passed"