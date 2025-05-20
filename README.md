# CryptoHelper
Wrapper module to use the wonderful [`cryptography`](https://pypi.org/project/cryptography/) package in an easier way.

## Warning
Using the primitive functions of `cryptography` is dangerous. By using `CryptoHelper`... it's still dangerous!

## Features
- Key creation, saving and loading
- Signing and verifying data
- Create X509 certificates

## Example usages (WIP)
- PKI maintenance
- Creating VPN keys and certificates.

## Project motivation
I've started this project to learn crypto functions in Python. It's still big fun learning that for me.

## Why CryptoHelper?

### More logical object orientated structure
Every private key represents a public key (and its functions) for instance.  
So by creating a `PrivateKey` you create a PublicKey too implicitely.
And now there's only one type of PrivateKey and accordingly the PublicKey since all asymmetric algorithms have similar methods and properties.

## Status
Haven't look into this project for a while. Some type issues have to be solved.  
Publishing it now because I need it on a server.
