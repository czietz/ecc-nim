# SPDX-License-Identifier: MIT

## A simple program using ecc.nim for key and signatures generation
## and signature verification. Keys and signatures are compatible
## to OpenSSH's ``ssh-keygen`` command.
##
## Copyright (c) 2026 Christian Zietz <czietz@gmx.net>
##
## Licensed under the MIT license.

import std/strformat
import std/parseopt
import ecc
import sshcompat

# included as git submodule, to avoid system-wide installation
import checksums/src/checksums/sha2

let curve = newCurve(Curve_secp256r1)


proc writeHelp =
    echo """
Usage: signappl command --arg:val

Elliptic curve cryptography on secp256r1 curve
with OpenSSH compatible keys and signatures.

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
        writeFile(privkey, keys.private.toSshKey)
    except IOError:
        echo fmt"Could not write private key file '{privkey}'"
        quit(1)

    try:
        writeFile(pubkey, keys.public.toSshKey & "\n")
    except IOError:
        echo fmt"Could not write public key file '{pubkey}'"
        quit(1)

    echo fmt"Keys have been written to '{pubkey}' and '{privkey}'"


proc do_hash(datafile: string): ShaDigest_512 =
    var ctx = initSha_512()
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

const namespace = "ecc.nim"

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

    var keys: ECKeyPair
    try:
        keys = loadSshKeyPair(privbytes)
    except ECCError:
        echo fmt"Invalid private key file '{privkey}'"
        quit(1)

    let hash = do_hash(datafile)
    let sign = keys.private.ecDsaSshSign(hash, namespace)

    try:
        writeFile(signfile, sign)
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

    var pub, pub2: ECPublicKey
    try:
        pub = loadSshPublicKey(pubbytes)
    except ECCError:
        echo fmt"Invalid public key file '{pubkey}'"
        quit(1)

    echo "Using ECDSA key " & sshFingerPrint(pub)

    let hash = do_hash(datafile)
    var expected_namespace = namespace
    var okay = ecDsaSshVerify(sigbytes, hash, pub2, expected_namespace)

    # user specified a permitted public key, check that it has been used for the signature
    let samekey = (pub == pub2)
    var res: string
    if okay and samekey:
        res = "valid."
    elif okay:
        echo "Signature was made with " & sshFingerPrint(pub2)
        res = "INVALID (made with different public key)!"
    else:
        res = "INVALID!"
    echo fmt"Signature '{signfile}' of '{datafile}' with key '{pubkey}' is {res}"

    if (not okay) or (not samekey):
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
