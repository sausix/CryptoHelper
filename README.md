# CryptoHelper
Wrapper module to use the wonderful [`cryptography`](https://pypi.org/project/cryptography/) package in an easier way including some implementations and examples.

> [!WARNING]
> Using the primitive functions of `cryptography` is dangerous. By using `CryptoHelper`... it's still dangerous!  
> A lot can go wrong. Be careful.

## Features
- Key creation, saving and loading
- Signing and verifying data
- Create X509 certificates
- Certificate signing requests (CSR)
- Certification revocaion lists (CRL)

## Example usages (WIP)
- PKI maintenance
- Creating keys and certificates for VPNs

## Project motivation
I've started this project to learn crypto functions in Python. It's still big fun learning that for me.

## Why CryptoHelper?

### More logical object orientated structure
Every private key also represents a public key (and its functions) for instance.  
So by creating a `PrivateKey` you create a PublicKey too implicitely.
And now there's only one type of PrivateKey and accordingly the PublicKey since all asymmetric algorithms have similar methods and properties.

## Status
Big rework going on. Not tested, missing tests.  
Publishing it now because I need it on a server.


<p align="center">
  <img src="gangsterdolphin.png" alt="Trustworthy dolphin" title="I won't steal your crypto wallet.Trust me... im a dolphin.png.exe" />
</p>
