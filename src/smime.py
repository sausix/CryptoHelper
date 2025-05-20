# -*- coding: utf-8 -*-

from pathlib import Path

from cryptography.hazmat.primitives.serialization.pkcs7 import load_pem_pkcs7_certificates, load_der_pkcs7_certificates
from CryptoHelper import Cert


p7s_file = Path("smime.p7s")

for c in load_der_pkcs7_certificates(p7s_file.read_bytes()):
    cert = Cert(c)
    print(cert)

# openssl pkcs7 -in smime.p7s -inform DER
