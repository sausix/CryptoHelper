#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pathlib import Path

from crypto_helper import PrivateKey, PublicKey


workdir = Path("/tmp")
# workdir = Path(r"C:\users\me")

private_key_file = workdir / "private.key"
public_key_file = workdir / "public.pub"
file = workdir / "file_to_sign.txt"
sig_file = workdir / "file_to_sign.txt.sig"


# Create a private key for signing data
priv = PrivateKey()
print(priv)  # Little information

# Never give a private key away. Save it in a secure folder in PEM format.
priv.private_key_to_file(private_key_file)

# Save the corresponding public key to file too.
priv.public_key_to_file(public_key_file)


# Create a sample file instantly
file.write_text("This is a sample file which will be signed by a person owning a private key.")

# Get the signature bytes
signature_bytes = priv.sign_file(file)

# Or save the signature to a file directly.
priv.sign_file_to_file(file, sig_file)


# Another individual just needs your public key, your file specific signature and the file.

# Open the public key
pubkey = PublicKey(public_key_file)
print(pubkey)  # Little information

# Verify the file based on public key and signature
pubkey.verify_file(sig_file, file)
# No exception: verification succeeded.
print("Verification went fine!")

# Now let's modify the file a little bit to simulate corruption or an attack.
with file.open("a") as f:
    f.write(" ")  # Just add a little space an the end. What can go wrong?

# Rerun verification
pubkey.verify_file(sig_file, file)
# Exception -> cryptography.exceptions.InvalidSignature
