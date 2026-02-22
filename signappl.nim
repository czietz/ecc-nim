# SPDX-License-Identifier: MIT

## A simple program using ecc.nim for key and signatures generation
## and signature verification.
##
## Copyright (c) 2026 Christian Zietz <czietz@gmx.net>
##
## Licensed under the MIT license.

import std/strformat
import std/parseopt
import ecc

# included as git submodule, to avoid system-wide installation
import checksums/src/checksums/sha2

let curve = newCurve(Curve_secp256r1)


proc writeHelp =
    echo """
Usage: signappl command --arg:val

Elliptic curve cryptography on secp256r1 curve.

Commands:

  keygen: Generates a key pair
    --pub file   File to write public key to
    --priv file  File to write private key to

  sign:   Signs a file
    --priv file  File containing private key
    --file file  File to sign
    --sig file   File to write signature to

  verify: Verifies a signature
    --pub file   File containing public key
    --sig file   File containing signature
    --file file  File that has been signed
"""
    quit(0)


proc do_keygen(pubkey: string, privkey: string) =

    if pubkey == "" or privkey == "":
        echo "Key generation needs '--pub' and '--priv' options"
        quit(1)

    let keys = curve.makeKeyPair()
    try:
        writeFile(privkey, cast[seq[byte]](keys.private.toBytes))
    except IOError:
        echo fmt"Could not write private key file '{privkey}'"
        quit(1)

    try:
        writeFile(pubkey, cast[seq[byte]](keys.public.toBytes(compressed=true)))
    except IOError:
        echo fmt"Could not write public key file '{pubkey}'"
        quit(1)

    echo fmt"Keys have been written to '{pubkey}' and '{privkey}'"


proc do_hash(datafile: string): ShaDigest_256 =
    var ctx = initSha_256()
    var buffer = newSeqUninit[char](4096)

    try:
        var f: File = open(datafile, fmRead)
        while true:
            let l = f.readChars(buffer)
            if l == 0:
                break
            ctx.update(buffer[0..(l-1)])
        result = ctx.digest()
    except IOError:
        echo fmt"Could not read data file '{datafile}'"
        quit(1)


proc do_sign(privkey: string, datafile: string, signfile: string) =

    if privkey == "" or datafile == "" or signfile == "":
        echo "Signature generation needs '--priv', '--file' and '--sig' options"
        quit(1)

    var privbytes: string
    try:
        privbytes = readFile(privkey)
    except IOError:
        echo fmt"Could not read private key file '{privkey}'"
        quit(1)

    if privbytes.len != curve.getPrivateKeySize:
        echo fmt"Invalid private key size. Expected {curve.getPrivateKeySize} bytes"
        quit(1)

    let privkey = curve.loadPrivateKey(privbytes)
    let hash = do_hash(datafile)
    let sign = privkey.ecDsaSign(hash)

    try:
        writeFile(signfile, cast[seq[byte]](sign))
    except IOError:
        echo fmt"Could not write signature file '{signfile}'"
        quit(1)

    echo fmt"Signature has been written to '{signfile}'"

proc do_verify(pubkey: string, datafile: string, signfile: string) =

    if pubkey == "" or datafile == "" or signfile == "":
        echo "Signature verification needs '--pub', '--file' and '--sig' options"
        quit(1)

    var pubbytes: string
    try:
        pubbytes = readFile(pubkey)
    except IOError:
        echo fmt"Could not read public key file '{pubkey}'"
        quit(1)

    var sigbytes: string
    try:
        sigbytes = readFile(signfile)
    except IOError:
        echo fmt"Could not read signature file '{signfile}'"
        quit(1)

    var pub: ECPublicKey
    try:
        pub = curve.loadPublicKey(pubbytes)
    except ECCError:
        echo fmt"Invalid public key '{pubkey}'"
        quit(1)

    let hash = do_hash(datafile)
    let okay = pub.ecDsaVerify(hash, @sigbytes)

    let res = if okay: "valid" else: "INVALID!"

    echo fmt"Signature '{signfile}' of '{datafile}' with key '{pubkey}' is {res}"

    if not okay:
        quit(1)


var command = ""
var pubkey = ""
var privkey = ""
var datafile = ""
var signfile = ""

for kind, key, val in getopt(shortNoVal = {'h'}, longNoVal = @["help"]):
    case kind
    of cmdArgument:
        command = key
    of cmdLongOption, cmdShortOption:
        case key
        of "pub": pubkey = val
        of "priv": privkey = val
        of "file": datafile = val
        of "sig": signfile = val
        of "help","h": writeHelp()
    of cmdEnd: discard # cannot happen

case command
of "keygen": do_keygen(pubkey, privkey)
of "sign":   do_sign(privkey, datafile, signfile)
of "verify": do_verify(pubkey, datafile, signfile)
else: writeHelp()
