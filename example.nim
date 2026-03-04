# SPDX-License-Identifier: MIT

# Examples from the README

# Copyright (c) 2026 Christian Zietz <czietz@gmx.net>

import ecc

let curve = newCurve(Curve_secp256r1)

let keyPair = curve.makeKeyPair()
let pubKey  = keyPair.public
let privKey = keyPair.private

# Derive public key from an existing private key
let derived = privKey.getPublicKey()

# Export
let rawPub        = pubKey.toBytes()                  # raw uncompressed
let compressedPub = pubKey.toBytes(compressed = true) # SEC1 compressed
let sec1Pub       = pubKey.toBytesSec1()              # SEC1 uncompressed (0x04 prefix)
let rawPriv       = privKey.toBytes()

# Import
let loadedPub  = curve.loadPublicKey(rawPub)
let loadedPub2 = curve.loadPublicKey(compressedPub, compressed = true)
let loadedPriv = curve.loadPrivateKey(rawPriv)

let message   = "Hello, world!"
let signature = privKey.ecDsaHashAndSign(message)          # hashes with SHA-256, then signs
let valid     = pubKey.ecDsaHashAndVerify(message, signature) # true if valid

# Or provide your own hash
let hash  = newSeq[char](32)
let sig2  = privKey.ecDsaSign(hash)
let ok    = pubKey.ecDsaVerify(hash, sig2)

let aliceKeys = curve.makeKeyPair()
let bobKeys   = curve.makeKeyPair()

# Both sides compute the same secret
let secretA = ecHMACSharedSecret(bobKeys.public, aliceKeys.private, nonce = "session-id")
let secretB = ecHMACSharedSecret(aliceKeys.public, bobKeys.private, nonce = "session-id")

assert secretA == secretB  # true

# Clear exported private key from memory
zeroSequence(rawPriv)
