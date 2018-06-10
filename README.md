# Crypto

[![Build Status](https://travis-ci.com/tbidne/crypto.svg?branch=master)](https://travis-ci.com/tbidne/crypto)

This is for educational purposes only, NOT intended for actual use.

Build with `stack build --ghc-options="-O2"`

Test with `stack test :spec`, `stack test :inttest`, or just `stack test`, to run the specs, int tests, or everything, respectively. Only the specs are run on travis since the latter can't handle the 4096 bit rsa tests, apparently.

AES can use 128, 192, or 256 bit keys. Only block cipher mode right now is ECB :-(

RSA can use 1024, 2048, or 4096 bit keys. RSA uses AES 256 to encrypt the file, then the AES key is encrypted with the public key then prepended to the ciphertext.

Sample usage:
```
stack exec crypto-exe keygen aes 128 key.aes
stack exec crypto-exe encrypt aes key.aes message ciphertext
stack exec crypto-exe decrypt aes key.aes ciphertext decrypted

stack exec crypto-exe keygen rsa 1024 rsa.pub rsa.prv
stack exec crypto-exe encrypt rsa rsa.pub message ciphertext
stack exec crypto-exe decrypt rsa rsa.prv ciphertext decrypted
```