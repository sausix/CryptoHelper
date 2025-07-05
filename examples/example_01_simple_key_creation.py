#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pathlib import Path

from crypto_helper import PrivateKey, PublicKey, Ed25519Crypto


workdir = Path("/tmp")
# workdir = Path(r"C:\users\me")

private_key_file = workdir / "private.key"
public_key_file = workdir / "public.pub"

# Create a private key.
priv = PrivateKey()
# priv = PrivateKey(Ed25519Crypto)
print(priv)  # Little information


# Never give a private key away. Save it in a secure folder in PEM format.
priv.private_key_to_file(private_key_file)
print("Private key saved to:", private_key_file)

# Save the corresponding public key to file too.
priv.public_key_to_file(public_key_file)
print("Public key saved to:", public_key_file)

# You have created and saved a private and public key pair!


# Another party may read the public key and do some crypto stuff.
pubkey = PublicKey(public_key_file)
print(pubkey)  # Little information
