# SPDX-License-Identifier: MIT

## A supplement to ecc.nim, for importing and exporting OpenSSH
## compatible keys and signatures.
##
## It follows the formats described in OpenSSH's ``PROTOCOL``,
## ``PROTOCOL.key`` and ``PROTOCOL.sshsig`` with the following limitations:
##
## - Only the ``ecdsa-sha2`` format on the ``nistp256`` curve is supported.
## - Only *unencrypted* private keys are supported.
## - Only the ``sha512`` algorithm (default in OpenSSH) is supported
##   for hashing messages.
##
##
## Copyright (c) 2026 Christian Zietz <czietz@gmx.net>
##
## Licensed under the MIT license.

import std/endians
import std/base64
import std/strutils
import std/sequtils
import ecc
import checksums/src/checksums/sha2

const longname = "ecdsa-sha2-nistp256"
const shortname = "nistp256"

const openssh_magic = "openssh-key-v1\0"
const none = "none"
const keystart = "-----BEGIN OPENSSH PRIVATE KEY-----"
const keyend = "-----END OPENSSH PRIVATE KEY-----"

const sshsig_magic = "SSHSIG"
const sshsig1_magic = "SSHSIG\0\0\0\1"
const sha512 = "sha512"
const sigstart = "-----BEGIN SSH SIGNATURE-----"
const sigend = "-----END SSH SIGNATURE-----"

const linelen = 70

proc bigEndianUint32(x: uint32): seq[char] =
    # encode a uint32 into big-endian format
    result = newSeq[char](sizeof(uint32))
    bigEndian32(addr result[0], addr x)

proc toSshString(x: seq[char]): seq[char] =
    # return a "ssh string", i.e., big-endian length + string
    result = bigEndianUint32(uint32(x.len))
    result = result & x

proc popBigEndianUint32(x: var seq[char]): uint32 =
    # pop uint32 from sequence
    bigEndian32(addr result, addr x[0])
    x = x[sizeof(uint32) .. ^1]

proc popSshString(x: var seq[char]): seq[char] =
    # pop "ssh string" from sequence
    let strlen = popBigEndianUint32(x)
    if strlen > 0:
        result = x[0 .. strlen-1]
    else:
        result = @""
    # pop string
    x = x[strlen .. ^1]


proc encodeSshPublicKey(P: ECPublicKey): seq[char] =
    # encode a public key into an SSH "public key blob"
    if P.getCurve().getCurveType() != Curve_secp256r1:
        raise newException(ECCError, "only nistp256 curve is supported")
    let keydata = P.toBytesSec1()
    return toSshString(@longname) & toSshString(@shortname) & toSshString(keydata)

proc toSshKey*(P: ECPublicKey, comment = ""): string =
    ## Encodes an EC public key as an OpenSSH public key string.
    ##
    ## The result is a single-line string of the form:
    ## ``ecdsa-sha2-nistp256 <base64-encoded-key> <comment>``
    ## which can be written directly to an ``authorized_keys`` file or a ``.pub`` file.
    ##
    ## Only the ``nistp256`` (secp256r1) curve is supported; an ``ECCError`` is raised
    ## for any other curve.
    ##
    ## Parameters:
    ## - P       - the EC public key to encode
    ## - comment - optional comment appended to the key line (default: empty string)
    ##
    ## Returns the OpenSSH public key string.
    let encodedkey = encodeSshPublicKey(P)
    let b64key = encode(encodedkey)
    return longname & " " & b64key & " " & comment

proc decodeSshPublicKey(decodedkey: var seq[char]): ECPublicKey =
    # decode a public key from an SSH "public key blob"
    var keydata: seq[char]
    try:
        let n1 = popSshString(decodedkey)
        let n2 = popSshString(decodedkey)
        keydata = popSshString(decodedkey)
        if n1 != longname or n2 != shortname: raise newException(ECCError, "only ecdsa-sha2-nistp256 is supported")
    except IndexDefect:
        raise newException(ECCError, "illegal SSH public key")

    return loadPublicKey(newCurve(Curve_secp256r1), keydata)

proc loadSshPublicKey*(K: string): ECPublicKey =
    ## Parses an OpenSSH public key string and returns the corresponding EC public key.
    ##
    ## The input ``K`` must be a single-line OpenSSH public key of the form:
    ## ``ecdsa-sha2-nistp256 <base64-encoded-key> [comment]``
    ##
    ## Raises ``ECCError`` if:
    ## - the string is malformed or cannot be base64-decoded
    ## - the key type is not ``ecdsa-sha2-nistp256``
    ## - the encoded key data is invalid
    ##
    ## Parameters:
    ## - K - the OpenSSH public key string to parse
    ##
    ## Returns the decoded ``ECPublicKey``.
    let parts = K.split(' ')
    if parts.len < 2: raise newException(ECCError, "illegal SSH public key")
    if parts[0] != longname: raise newException(ECCError, "only ecdsa-sha2-nistp256 is supported")

    var decodedkey: seq[char]
    try:
        decodedkey = @(decode(parts[1]))
    except ValueError:
        raise newException(ECCError, "illegal SSH public key")

    return decodeSshPublicKey(decodedkey)

proc sshFingerPrint*(P: ECPublicKey): string =
    ## Computes the OpenSSH SHA-256 fingerprint of an EC public key.
    ##
    ## The fingerprint is calculated by hashing the SSH wire-format encoding of the
    ## public key with SHA-256, then base64-encoding the digest (without padding).
    ## The result has the form ``SHA256:<base64>`` and matches the output of
    ## ``ssh-keygen -l -E sha256``.
    ##
    ## Parameters:
    ## - P - the EC public key to fingerprint
    ##
    ## Returns the fingerprint string, e.g. ``SHA256:abc123...``.
    let encodedkey = encodeSshPublicKey(P)
    let fingerprint = Sha_256.secureHash(encodedkey)
    result = "SHA256:" & encode(fingerprint).strip(leading=false, trailing=true, chars={'='})

proc toSshKey*(Q: ECPrivateKey, comment = ""): string =
    ## Encodes an EC private key as an OpenSSH private key PEM block.
    ##
    ## The result is a multi-line string delimited by
    ## ``-----BEGIN OPENSSH PRIVATE KEY-----`` and ``-----END OPENSSH PRIVATE KEY-----``,
    ## using the ``openssh-key-v1`` format. The key is stored unencrypted (cipher
    ## ``none``); encryption is not supported.
    ##
    ## Only the ``nistp256`` (secp256r1) curve is supported; an ``ECCError`` is raised
    ## for any other curve.
    ##
    ## Parameters:
    ## - Q       - the EC private key to encode
    ## - comment - optional comment embedded in the key file (default: empty string)
    ##
    ## Returns the PEM-encoded OpenSSH private key string.
    var temp, temp2: seq[char]

    if Q.getCurve().getCurveType() != Curve_secp256r1:
        raise newException(ECCError, "only nistp256 curve is supported")

    let P = Q.getPublicKey()
    let encodedpublickey = encodeSshPublicKey(P)
    let encodedprivatekey = '\0' & Q.toBytes()
    # magic, and no encryption supported
    temp = @openssh_magic & toSshString(@none) & toSshString(@none) & toSshString(@"")
    # one key
    temp = temp & bigEndianUint32(1'u32)
    # public key
    temp = temp & toSshString(encodedpublickey)

    # private key (this would be encrypted if we supported encryption)
    # but since we don't encrypt anyway, we don't have to make the checkints random
    temp2 = bigEndianUint32(0x55aa55aa'u32) & bigEndianUint32(0x55aa55aa'u32) & encodedpublickey &
            toSshString(encodedprivatekey) & toSshString(@comment)

    # pad to a multiple of 8 bytes (not strictly required since we don't encrypt)
    var padbyte = '\x01'
    while temp2.len mod 8 != 0:
        temp2 = temp2 & padbyte
        inc padbyte

    temp = temp & toSshString(temp2)
    let b64key = encode(temp)

    result = keystart
    for i in countup(0, b64key.len, linelen):
        result = result & "\n" & b64key[i ..< min(i + linelen, b64key.len)]
    result = result & "\n" & keyend & "\n"


proc loadSshKeyPair*(K: string): ECKeyPair =
    ## Parses an OpenSSH private key PEM block and returns the EC key pair.
    ##
    ## The input ``K`` must contain a PEM-encoded ``openssh-key-v1`` private key,
    ## delimited by ``-----BEGIN OPENSSH PRIVATE KEY-----`` / ``-----END OPENSSH PRIVATE KEY-----``.
    ## Only unencrypted keys (cipher ``none``) and the ``ecdsa-sha2-nistp256`` key
    ## type are supported. If the file contains multiple keys only the first is loaded.
    ##
    ## The parsed public and private keys are cross-validated; an ``ECCError`` is
    ## raised if they do not correspond to the same key pair.
    ##
    ## Raises ``ECCError`` if:
    ## - the PEM structure or base64 encoding is invalid
    ## - the key is encrypted
    ## - the key type is not ``ecdsa-sha2-nistp256``
    ## - internal consistency checks fail
    ##
    ## Parameters:
    ## - K - the PEM string containing the OpenSSH private key
    ##
    ## Returns an ``ECKeyPair`` with ``public`` and ``private`` fields.
    # split into lines, discarding empty lines
    let lines = filterit(K.splitLines(), it.strip() != "")
    if lines.len < 3: raise newException(ECCError, "illegal SSH private key")
    if lines[0].strip() != keystart or lines[^1].strip() != keyend: raise newException(ECCError, "illegal SSH private key")

    var b64key: string
    var decodedkey: seq[char]
    for k in 1 .. lines.len-2:
        b64key = b64key & lines[k].strip()
    try:
        decodedkey = @(decode(b64key))
    except ValueError:
        raise newException(ECCError, "illegal SSH private key")

    try:
        if decodedkey[0..openssh_magic.len-1] != openssh_magic:
            raise newException(ECCError, "illegal SSH private key")
        decodedkey = decodedkey[openssh_magic.len..^1]

        let e1 = popSshString(decodedkey)
        let e2 = popSshString(decodedkey)
        discard popSshString(decodedkey) # options
        if e1 != none or e2 != none: raise newException(ECCError, "only unencrypted keys are supported")

        let num = popBigEndianUint32(decodedkey)
        # we only import the first key, but don't fail if there are more
        if num < 1: raise newException(ECCError, "illegal SSH private key")

        var pubkeydata1 = popSshString(decodedkey)
        var container = popSshString(decodedkey)

        let checkint1 = popBigEndianUint32(container)
        let checkint2 = popBigEndianUint32(container)
        if checkint1 != checkint2: raise newException(ECCError, "illegal SSH private key")

        # check that public keys match (would be more relevant if data was encrypted)
        let pubkeydata2 = container[0..pubkeydata1.len-1]
        if pubkeydata1 != pubkeydata2: raise newException(ECCError, "illegal SSH private key")
        container = container[pubkeydata1.len..^1]

        # create public key (also checks curve)
        let pub = decodeSshPublicKey(pubkeydata1)

        # create private key
        var privkeydata = popSshString(container)
        # sometimes SSH pads the k value with a zero byte, remove it
        let psize = pub.getCurve.getPrivateKeySize
        if privkeydata.len == psize+1 and privkeydata[0] == '\0':
            privkeydata = privkeydata[1..^1]
        let priv = loadPrivateKey(newCurve(Curve_secp256r1), privkeydata)

        # check that keys match
        if priv.getPublicKey != pub: raise newException(ECCError, "illegal SSH private key")

        return (public: pub, private: priv)

    except ECCError:
        raise # re-raise
    except IndexDefect:
        raise newException(ECCError, "illegal SSH private key")


proc ecDsaSshSign*(Q: ECPrivateKey, messagehash: ShaDigest_512, namespace: string): string =
    ## Creates an SSH signature (sshsig format) over a pre-computed SHA-512 message hash.
    ##
    ## The signature follows the ``SSHSIG`` protocol and is returned as a PEM block
    ## delimited by ``-----BEGIN SSH SIGNATURE-----`` / ``-----END SSH SIGNATURE-----``.
    ## The hash algorithm recorded in the signature is ``sha512``; the signing algorithm
    ## is ``ecdsa-sha2-nistp256``.
    ##
    ## Only the ``nistp256`` (secp256r1) curve is supported; an ``ECCError`` is raised
    ## for any other curve.
    ##
    ## Parameters:
    ## - Q           - the EC private key to sign with
    ## - messagehash - the SHA-512 digest of the message to be signed
    ## - namespace   - the sshsig namespace string (e.g. ``"file"``, ``"git"``)
    ##
    ## Returns the PEM-encoded SSH signature string.
    if Q.getCurve().getCurveType() != Curve_secp256r1:
        raise newException(ECCError, "only nistp256 curve is supported")

    let P = Q.getPublicKey()
    let encodedpublickey = encodeSshPublicKey(P)

    # header
    var temp = @sshsig1_magic & toSshString(encodedpublickey) & toSshString(@namespace) & toSshString(@"") & toSshString(@sha512)

    # construct object to be signed and sign it
    let signaturedata =  @sshsig_magic & toSshString(@namespace) & toSshString(@"") & toSshString(@sha512) & toSshString(@messagehash)
    let signature = Q.ecDsaHashAndSign(signaturedata)
    let rssize = signature.len div 2
    # ssh encode signature
    let temp2 = toSshString('\0' & signature[0..rssize-1]) & toSshString('\0' & signature[rssize..^1])
    let temp3 = toSshString(@longname) & toSshString(temp2)

    temp = temp & toSshString(temp3)
    let b64sig = encode(temp)

    result = sigstart
    for i in countup(0, b64sig.len, linelen):
        result = result & "\n" & b64sig[i ..< min(i + linelen, b64sig.len)]
    result = result & "\n" & sigend & "\n"

proc ecDsaHashAndSshSign*(Q: ECPrivateKey, message: openArray[char], namespace: string): string =
    ## Hashes a message with SHA-512 and creates an SSH signature (sshsig format).
    ##
    ## This is a convenience wrapper around ``ecDsaSshSign`` that hashes ``message``
    ## with SHA-512 before signing. See ``ecDsaSshSign`` for full details on the
    ## output format.
    ##
    ## Parameters:
    ## - Q         - the EC private key to sign with
    ## - message   - the raw message to hash and sign
    ## - namespace - the sshsig namespace string (e.g. ``"file"``, ``"git"``)
    ##
    ## Returns the PEM-encoded SSH signature string.
    let messagehash = Sha_512.secureHash(message)
    return ecDsaSshSign(Q, messagehash, namespace)

proc loadSshSignature(S: string): tuple[public: ECPublicKey, signature: ECDSASignature, namespace: string] =
    # parse "armored" SSH signature and return public key, the signature, and the namespace
    # split into lines, discarding empty lines
    let lines = filterit(S.splitLines(), it.strip() != "")
    if lines.len < 3: raise newException(ECCError, "illegal SSH signature")
    if lines[0].strip() != sigstart or lines[^1].strip() != sigend: raise newException(ECCError, "illegal SSH signature")

    var b64sig: string
    var decodedsig: seq[char]
    for k in 1 .. lines.len-2:
        b64sig = b64sig & lines[k].strip()
    try:
        decodedsig = @(decode(b64sig))
    except ValueError:
        raise newException(ECCError, "illegal SSH signature")

    try:
        if decodedsig[0..sshsig1_magic.len-1] != sshsig1_magic:
            raise newException(ECCError, "illegal SSH signature")
        decodedsig = decodedsig[sshsig1_magic.len..^1]

        var pubkeydata = popSshString(decodedsig)
        result.public = decodeSshPublicKey(pubkeydata)
        result.namespace = cast[string](popSshString(decodedsig))

        discard popSshString(decodedsig) # reserved field

        let hashalgo = popSshString(decodedsig)
        if hashalgo != sha512: raise newException(ECCError, "only sha512 is supported as message hashing algorithm")

        var temp = popSshString(decodedsig)
        let n1 = popSshString(temp)
        if n1 != longname: raise newException(ECCError, "only ecdsa-sha2-nistp256 is supported")
        # signature consists of r and s, encoded separately
        var temp2 = popSshString(temp)
        var rsig = popSshString(temp2)
        var ssig = popSshString(temp2)

        # sometimes SSH pads the r/s values a zero byte each, remove them
        let rssize = result.public.getCurve.getSignatureSize div 2
        if rsig.len == rssize+1 and rsig[0] == '\0':
            rsig = rsig[1..^1]
        if ssig.len == rssize+1 and ssig[0] == '\0':
            ssig = ssig[1..^1]

        result.signature = rsig & ssig
        if result.signature.len != result.public.getCurve.getSignatureSize:
            raise newException(ECCError, "illegal SSH signature")

    except ECCError:
        raise # re-raise
    except IndexDefect:
        raise newException(ECCError, "illegal SSH signature")


proc ecDsaSshVerify*(S: string, messagehash: ShaDigest_512, P: var ECPublicKey, namespace: var string): bool =
    ## Verifies an SSH signature (sshsig format) against a pre-computed SHA-512 hash.
    ##
    ## The signature ``S`` must be a PEM-encoded sshsig block. The public key and
    ## namespace embedded in the signature are extracted and written to ``P`` and
    ## ``namespace`` respectively, so the caller can inspect them after the call.
    ##
    ## If ``namespace`` is non-empty on entry it is used as an expected value;
    ## ``false`` is then returned when the signature's namespace does not match.
    ##
    ## Typically, only specific trusted public keys are allowed to make signatures.
    ## The caller must then verify the returned public key `P` against the list
    ## of allowed signers.
    ##
    ## Parameters:
    ## - S           - the PEM-encoded SSH signature to verify
    ## - messagehash - the SHA-512 digest of the original message
    ## - P           - output: the public key extracted from the signature
    ## - namespace   - in/out: expected namespace (empty = accept any); set to the
    ##                 actual namespace found in the signature on return
    ##
    ## Returns ``true`` if the signature is cryptographically valid, ``false`` otherwise.

    let sig = loadSshSignature(S)
    if (namespace != "") and (sig.namespace != namespace): 
        return false

    P = sig.public
    namespace = sig.namespace

    # construct object to be signed and sign it
    let signaturedata =  @sshsig_magic & toSshString(@namespace) & toSshString(@"") & toSshString(@sha512) & toSshString(@messagehash)
    return ecDsaHashAndVerify(sig.public, signaturedata, sig.signature)

proc ecDsaHashAndSshVerify*(S: string, message: openArray[char], P: var ECPublicKey, namespace: var string): bool =
    ## Hashes a message with SHA-512 and verifies an SSH signature (sshsig format).
    ##
    ## This is a convenience wrapper around ``ecDsaSshVerify`` that hashes ``message``
    ## with SHA-512 before verification. See ``ecDsaSshVerify`` for full details on
    ## parameters and behaviour.
    ##
    ## Parameters:
    ## - S         - the PEM-encoded SSH signature to verify
    ## - message   - the raw message to hash and verify against
    ## - P         - output: the public key extracted from the signature
    ## - namespace - in/out: expected namespace (empty = accept any); set to the
    ##               actual namespace found in the signature on return
    ##
    ## Returns ``true`` if the signature is cryptographically valid, ``false`` otherwise.
    let messagehash = Sha_512.secureHash(message)
    return ecDsaSshVerify(S, messagehash, P, namespace)

when isMainModule:

    var namespace = "testing"

    # test key generation and parsing with self-generated keys
    block:

        let curve = newCurve(Curve_secp256r1)
        let (pubkey, privkey) = makeKeyPair(curve)

        let sshkey1 = pubkey.toSshKey("testing")
        let check1  = loadSshPublicKey(sshkey1)
        doAssert(check1 == pubkey)

        let sshkey2 = privkey.toSshKey("testing")
        let check2  = loadSshKeyPair(sshkey2)
        doAssert(check2.private == privkey)
        doAssert(check2.public == pubkey)

        # test signature generation and parsing
        var check3: ECPublicKey
        let sig1 = ecDsaHashAndSshSign(privkey, "Hallo", namespace)
        let check4 = ecDsaHashAndSshVerify(sig1, "Hallo", check3, namespace)
        doAssert(check2.public == check3)
        doAssert(check4)

    # test with data generated by OpenSSH
    block:

        let sshpub = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLWB+Z3DaiJFs+UhlCQjE9Zrsos/B+gKrm2HMyWtGmMaBUmB0otfS1NxF1actepFbBE78DxXpWYtaORp46vlGEw= testing"

        let sshpriv = """
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQS1gfmdw2oiRbPlIZQkIxPWa7KLPwfo
Cq5thzMlrRpjGgVJgdKLX0tTcRdWnLXqRWwRO/A8V6VmLWjkaeOr5RhMAAAAoPY6trX2Or
a1AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLWB+Z3DaiJFs+Uh
lCQjE9Zrsos/B+gKrm2HMyWtGmMaBUmB0otfS1NxF1actepFbBE78DxXpWYtaORp46vlGE
wAAAAgB6Bsf45YJK/gEWf7UEN94dgjZZ2MH1/Lr533qmaEohYAAAAHdGVzdGluZwE=
-----END OPENSSH PRIVATE KEY-----"""

        let check1 = loadSshPublicKey(sshpub)
        let check2 = loadSshKeyPair(sshpriv)
        doAssert(check2.public == check1)

        let sshsig = """
-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAAGgAAAATZWNkc2Etc2hhMi1uaXN0cDI1NgAAAAhuaXN0cDI1NgAAAE
EEtYH5ncNqIkWz5SGUJCMT1muyiz8H6AqubYczJa0aYxoFSYHSi19LU3EXVpy16kVsETvw
PFelZi1o5Gnjq+UYTAAAAAd0ZXN0aW5nAAAAAAAAAAZzaGE1MTIAAABlAAAAE2VjZHNhLX
NoYTItbmlzdHAyNTYAAABKAAAAIQCOjytucPCN8w7TfD+1MhgAwKpBD5VViod+j7HrCP7O
0AAAACEAlH4nUcMip4zBEGujecNRqJYxcKi0fyBWTwdaiOxVNUU=
-----END SSH SIGNATURE-----"""

        var check3: ECPublicKey
        let check4 = ecDsaHashAndSshVerify(sshsig, "Hallo", check3, namespace)
        doAssert(check2.public == check3)
        doAssert(check4)

    echo "All tests passed"