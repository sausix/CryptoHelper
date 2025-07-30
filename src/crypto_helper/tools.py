# -*- coding: utf-8 -*-

"""
Some extra tools on top of this package.
"""

import re
from pathlib import Path
from typing import Optional, Tuple, Type, Generator

from crypto_helper import PrivateKey, PublicKey
from crypto_helper.certs import CertSigningRequest, Cert, Crl


# Mapping PEM title labels to the corresponding class
pem_label_to_class = {
    b"CERTIFICATE": Cert,
    b"X509 CRL": Crl,
    b"CERTIFICATE REQUEST": CertSigningRequest,
    b"PRIVATE KEY": PrivateKey,
    b"ENCRYPTED PRIVATE KEY": PrivateKey,
    b"PUBLIC KEY": PublicKey,
}


def cert_info(p: Path) -> str:
    out = f"=== {p} ===\n"
    cert = Cert(p)
    out = out + str(cert) + "\n"
    for e in cert.extensions:
        out = out + str(e)
    return out


def print_csr(p: Path):
    out = f"=== {p} ===\n"
    cert = CertSigningRequest(p)
    out = out + str(cert) + "\n"
    for e in cert.extensions:
        out = out + str(e)
    return out


# Groups: 1: label, 2: base64 data
_RE_PEM_BODY = re.compile(rb"-----BEGIN (?P<label>[A-Z ]*)-----(?P<base64>.*?)-----END (?P=label)-----",
                          re.DOTALL)


def split_pem_chain(chained_data: bytes) -> Generator[Tuple[slice, Optional[Type], bytes], None, None]:
    """
    Finds all PEM formatted elements in the bytes blob.

    Generates a sequence of tuples of:
     - the slice region
     - coresponding class which may load the bytes in the range if supported or None
     - PEM label name

    :param chained_data: Data as bytes which may contain multiple segments of PEM conform items.
    :return: Generator for tuple(slice, class name or None, PEM item label)
    """
    # "-----BEGIN " + LABEL + "-----" + DATA + "-----END " + LABEL + "-----".

    for match in _RE_PEM_BODY.finditer(chained_data):
        label = match.group("label")
        yield slice(match.start(), match.end()), pem_label_to_class.get(label), label
