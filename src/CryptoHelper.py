# -*- coding: utf-8 -*-

"""
CryptoHelper
Adrian Sausenthaler

Version: 0.1
"""

import re
import struct
from abc import ABCMeta, abstractmethod
from functools import partial
from typing import Union, Optional, List, Tuple, get_args, Type, Generator, Iterable
from dataclasses import dataclass
from pathlib import Path
from datetime import datetime, timedelta, timezone
from contextlib import suppress
from inspect import isclass
from enum import Enum
from base64 import standard_b64decode

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding, utils, ed25519, ed448

from cryptography.x509.oid import NameOID, ObjectIdentifier
from cryptography.x509 import NameAttribute, CertificateBuilder, Name as x509Name, random_serial_number, Certificate, \
    Extension, ExtensionType, load_pem_x509_certificate, CertificateSigningRequest, load_pem_x509_csr, Version, \
    CertificateSigningRequestBuilder, CertificateRevocationList, CertificateRevocationListBuilder, load_pem_x509_crl, \
    RevokedCertificate, RevokedCertificateBuilder, load_der_x509_crl, load_der_x509_csr, load_der_x509_certificate, \
    BasicConstraints, SubjectKeyIdentifier, GeneralName, AuthorityKeyIdentifier, KeyUsage, ExtendedKeyUsage, \
    SubjectAlternativeName, CRLReason, CRLDistributionPoints, DistributionPoint, ReasonFlags as _ReasonFlags


__all__ = (
    "PublicKey", "PrivateKey", "NameAttributeList", "Cert", "CertSigningRequest", "CertificateSigningRequest", "Crl",
    "CertBuilder", "CsrBuilder", "ObjectIdentifier", "ExtensionType", "Certificate", "x509Name", "RevokedCert",
    "split_pem_chain", "CrlBuilder", "DuplicateCertException", "hashes", "ECCrypto", "RSACrypto", "ec", "Ed25519Crypto",
    "Ed448Crypto", "ExtensionBuilder", "CommonName", "FullOrganization", "convert_timeinfo", "CRLReasonFlags"
)

__VERSION__ = re.search("Version: (.*)",  __doc__).group(1)

_DAY = timedelta(days=1)
_RANDOM = object()
_EARLIEST_UTC_TIME = datetime(1950, 1, 1, tzinfo=timezone.utc)

# Supported key types
PublicKeyTypes = Union[ec.EllipticCurvePublicKey, rsa.RSAPublicKey, ed25519.Ed25519PublicKey, ed448.Ed448PublicKey]
PrivateKeyTypes = Union[ec.EllipticCurvePrivateKey, rsa.RSAPrivateKey, ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey]

_RE_PEM_ENTRY = re.compile(rb"-----BEGIN (?P<label>[A-Z ]*)-----(?P<base64>.*?)-----END (?P=label)-----", re.DOTALL)
_RE_SSH_LINE = re.compile(rb"([A-Za-z0-9\-]*) (.*?) (.*)$")

DuplicateCertException = type("DuplicateCertException", (Exception, ), {})


class CRLReasonFlags(Enum):
    unspecified = 0
    keyCompromise = 1
    cACompromise = 2
    affiliationChanged = 3
    superseded = 4
    cessationOfOperation = 5
    certificateHold = 6
    removeFromCRL = 8
    privilegeWithdrawn = 9
    aACompromise = 10


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

    for match in _RE_PEM_ENTRY.finditer(chained_data):
        label = match.group("label")
        yield slice(match.start(), match.end()), _pem_label_to_class.get(label), label


class _CryptoType(metaclass=ABCMeta):
    """
    Common base class for various crypto methods
    """
    HASH_METHOD = None

    @staticmethod
    @abstractmethod
    def PUBLIC_KEY_TYPE() -> Type[PublicKeyTypes]:
        """Class of the public key"""

    @staticmethod
    @abstractmethod
    def PRIVATE_KEY_TYPE() -> Type[PrivateKeyTypes]:
        """Class of the private key"""

    @classmethod
    @abstractmethod
    def from_openssh(cls, decoded_b64: bytes) -> "PublicKey":
        """Creates a public key of supported types based on OpenSSH key data which is usually stored in base64."""

    @abstractmethod
    def create_private_key(self) -> PrivateKeyTypes:
        """Create and return a new private key instance"""

    @abstractmethod
    def sign(self, privatekey: PrivateKeyTypes, data: bytes) -> bytes:
        """Sign some bytes with a private key instance.
        Returns bytes as signature."""

    @abstractmethod
    def sign_prehashed(self, privatekey: PrivateKeyTypes, data: bytes) -> bytes:
        """Sign prehashed data with a private key instance.
        Files should be prehashed instead of loading them into memory completely.
        Returns bytes as signature."""

    @abstractmethod
    def verify(self, publickey: PublicKeyTypes, sig: bytes, data: bytes):
        """Verifies data with the signature and a public key.
        Raises cryptography.exceptions.InvalidSignature on mismatch"""

    @abstractmethod
    def verify_prehashed(self, publickey: PublicKeyTypes, sig: bytes, data: bytes):
        """Verifies prehashed data with the signature and a public key.
        Raises cryptography.exceptions.InvalidSignature on mismatch"""

    @abstractmethod
    def apply_cryptoconfig(self, publickey: PublicKeyTypes):
        """Applies crypto parameters from a public key into a _CryptoType instance."""

    @abstractmethod
    def apply_hash(self, certhash: hashes.HashAlgorithm):
        """Applies hash algorithms ans parameters into a _CryptoType instance."""


def openssh_read_string(data: bytes) -> Tuple[bytes, bytes]:
    """
    Reads the next string from a OpenSSH field.
    :param data: Bytes which should start with the field length.
    :return: Tuple of the string and the remaining bytes which can be processed further.
    """
    length = struct.unpack(">I", data[:4])[0]
    return data[4:4 + length], data[4 + length:]


def openssh_read_mpint(data: bytes) -> Tuple[int, bytes]:
    """
    Reads the next OpenSSH field as integer.
    :param data: Bytes which should start with the field length.
    :return: Tuple of the integer and the remaining bytes which can be processed further.
    """
    length = struct.unpack(">I", data[:4])[0]
    int_bytes = data[4:4+length]
    int_value = int.from_bytes(int_bytes, byteorder="big", signed=False)
    return int_value, data[4 + length:]


def openssh_keybytes(data: Union[bytes, str, Path]) -> bytes:
    """
    Reads a file or parses the content of a file and returns the raw OpenSSH public key data.
    The file or a single line has to match for example this format:
    "ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEA7U8... comment"
    :param data: Bytes of the file, the line or the path to the file containing a single line.
    :return: Decoded base64 as bytes ready to be parsed individually by _CryptoType subclasses.
    """
    if isinstance(data, bytes):
        content = data

    elif isinstance(data, (str, Path)):
        keyfile = _check_file(data, must_exist=True, argname="data")
        content = keyfile.read_bytes()

    else:
        raise ValueError("Unsupported type of data: " + repr(data))

    m = _RE_SSH_LINE.match(content)
    if not m:
        raise ValueError("Could not detect an openssh file structure.")

    return standard_b64decode(m.group(2))


class ECCrypto(_CryptoType):
    """Interface class for elliptic curves"""
    HASH_METHOD = hashes.SHA256()

    ALGORITHM = ec.ECDSA(HASH_METHOD)
    ALGORITHM_PREHASHED = ec.ECDSA(utils.Prehashed(HASH_METHOD))
    CURVE_TYPE = ec.SECP521R1()

    PRIVATE_KEY_TYPE = ec.EllipticCurvePrivateKey
    PUBLIC_KEY_TYPE = ec.EllipticCurvePublicKey

    @classmethod
    def from_openssh(cls, decoded_b64: bytes):
        ECDSA_CURVES = {
            b"nistp256": ec.SECP256R1(),
            b"nistp384": ec.SECP384R1(),
            b"nistp521": ec.SECP521R1(),
        }

        key_type, remain = openssh_read_string(decoded_b64)
        if not key_type.startswith(b"ecdsa-sha2-"):
            raise ValueError("No ecdsa-sha2-* key data.")

        curve_name, remain = openssh_read_string(remain)
        pubkey_blob, remain = openssh_read_string(remain)

        curve = ECDSA_CURVES.get(curve_name)
        if curve is None:
            raise ValueError(f"Unknown or unsupported curve: {curve_name.decode()}")

        if pubkey_blob[0] != 0x04:
            raise ValueError("Only uncompressed points are supported.")

        field_len = (curve.key_size + 7) // 8
        x = int.from_bytes(pubkey_blob[1:1 + field_len], "big")
        y = int.from_bytes(pubkey_blob[1 + field_len:], "big")

        pub_numbers = ec.EllipticCurvePublicNumbers(x, y, curve)
        return PublicKey(pub_numbers.public_key())

    def __init__(self, hash_method: hashes.HashAlgorithm = None, curve_type: ec.EllipticCurve = None):
        if isinstance(hash_method, hashes.HashAlgorithm):
            self.HASH_METHOD = hash_method
            self.ALGORITHM = ec.ECDSA(self.HASH_METHOD)
            self.ALGORITHM_PREHASHED = ec.ECDSA(utils.Prehashed(self.HASH_METHOD))
        elif hash_method is not None:
            raise TypeError("hash_method must be an instance of a class derived from hashes.HashAlgorithm or None")

        if isinstance(curve_type, ec.EllipticCurve):
            self.CURVE_TYPE = curve_type
        elif curve_type is not None:
            raise TypeError("curve_type must be an instance of a class derived from ec.EllipticCurve or None")

    def create_private_key(self) -> ec.EllipticCurvePrivateKey:
        return ec.generate_private_key(self.CURVE_TYPE)

    def sign(self, privatekey: ec.EllipticCurvePrivateKey, data: bytes) -> bytes:
        return privatekey.sign(data, self.ALGORITHM)

    def sign_prehashed(self, privatekey: ec.EllipticCurvePrivateKey, data: bytes) -> bytes:
        return privatekey.sign(data, self.ALGORITHM_PREHASHED)

    def verify(self, publickey: ec.EllipticCurvePublicKey, sig: bytes, data: bytes):
        publickey.verify(sig, data, self.ALGORITHM)

    def verify_prehashed(self, publickey: ec.EllipticCurvePublicKey, sig: bytes, data: bytes):
        publickey.verify(sig, data, self.ALGORITHM_PREHASHED)

    def apply_cryptoconfig(self, publickey: ec.EllipticCurvePublicKey):
        self.CURVE_TYPE = publickey.curve

    def apply_hash(self, certhash: hashes.HashAlgorithm):
        self.HASH_METHOD = certhash
        self.ALGORITHM = ec.ECDSA(self.HASH_METHOD)
        self.ALGORITHM_PREHASHED = ec.ECDSA(utils.Prehashed(self.HASH_METHOD))

    def __repr__(self):
        return f"<{self.__class__.__name__}, Curve={self.CURVE_TYPE.name} Size={self.CURVE_TYPE.key_size}>"


class Ed25519Crypto(_CryptoType):
    """Interface class for Ed25519"""
    HASH_METHOD = None  # SHA512 but only used in backend internally.

    PRIVATE_KEY_TYPE = ed25519.Ed25519PrivateKey
    PUBLIC_KEY_TYPE = ed25519.Ed25519PublicKey

    # No settings, no __init__ needed

    @classmethod
    def from_openssh(cls, decoded_b64: bytes):
        # begin parsing
        key_type, remain = openssh_read_string(decoded_b64)
        if key_type != b"ssh-ed25519":
            raise ValueError("No Ed25519 key data.")

        pubkey_bytes, _ = openssh_read_string(remain)

        if len(pubkey_bytes) != 32:
            raise ValueError("Invalid length for an Ed25519 key.")

        pubkey = ed25519.Ed25519PublicKey.from_public_bytes(pubkey_bytes)
        return PublicKey(pubkey)

    def create_private_key(self) -> ed25519.Ed25519PrivateKey:
        return ed25519.Ed25519PrivateKey.generate()

    @classmethod
    def sign(cls, privatekey: ed25519.Ed25519PrivateKey, data: bytes) -> bytes:
        return privatekey.sign(data)

    def sign_prehashed(self, privatekey: ed25519.Ed25519PrivateKey, data: bytes) -> bytes:
        raise NotImplementedError("Ed25519 does not allow alternative hash algorithms and prehashed data.")

    def verify(self, publickey: ed25519.Ed25519PublicKey, sig: bytes, data: bytes):
        publickey.verify(sig, data)

    def verify_prehashed(self, publickey: ed25519.Ed25519PublicKey, sig: bytes, data: bytes):
        raise NotImplementedError("Ed25519 does not allow alternative hash algorithms and prehashed data.")

    def apply_cryptoconfig(self, publickey: ed25519.Ed25519PublicKey):
        """Fix config defined by Ed25519Crypto"""

    def apply_hash(self, certhash: hashes.HashAlgorithm):
        """Fix hash defined by Ed25519Crypto"""

    def __repr__(self):
        return f"<{self.__class__.__name__}>"


class Ed448Crypto(_CryptoType):
    """Interface class for Ed448"""
    HASH_METHOD = None  # SHAKE265 but only used in backend internally.

    PRIVATE_KEY_TYPE = ed448.Ed448PrivateKey
    PUBLIC_KEY_TYPE = ed448.Ed448PublicKey

    # No settings, no __init__ needed

    def create_private_key(self) -> ed448.Ed448PrivateKey:
        return ed448.Ed448PrivateKey.generate()

    @classmethod
    def sign(cls, privatekey: ed448.Ed448PrivateKey, data: bytes) -> bytes:
        return privatekey.sign(data)

    def sign_prehashed(self, privatekey: ed448.Ed448PrivateKey, data: bytes) -> bytes:
        raise NotImplementedError("Ed448 does not allow alternative hash algorithms and prehashed data.")

    def verify(self, publickey: ed448.Ed448PublicKey, sig: bytes, data: bytes):
        publickey.verify(sig, data)

    def verify_prehashed(self, publickey: ed448.Ed448PublicKey, sig: bytes, data: bytes):
        raise NotImplementedError("Ed448 does not allow alternative hash algorithms and prehashed data.")

    def apply_cryptoconfig(self, publickey: ed448.Ed448PublicKey):
        """Fix config defined by Ed448"""

    def apply_hash(self, certhash: hashes.HashAlgorithm):
        """Fix hash defined by Ed448"""

    def __repr__(self):
        return f"<{self.__class__.__name__}>"


class RSACrypto(_CryptoType):
    """Interface class for RSA"""
    HASH_METHOD = hashes.SHA256()
    PREHASHED = utils.Prehashed(HASH_METHOD)

    PUBLIC_EXPONENT = 65537  # 65537 Recommended. 3 for legacy compatibility.
    KEY_SIZE = 4096  # Minimum 512

    PRIVATE_KEY_TYPE = rsa.RSAPrivateKey
    PUBLIC_KEY_TYPE = rsa.RSAPublicKey

    @classmethod
    def from_openssh(cls, decoded_b64: bytes):
        # begin parsing
        key_type, remain = openssh_read_string(decoded_b64)
        if key_type != b"ssh-rsa":
            raise ValueError("No RSA key data.")

        e, remain = openssh_read_mpint(remain)
        n, remain = openssh_read_mpint(remain)

        pubkey = rsa.RSAPublicNumbers(e, n).public_key()
        return PublicKey(pubkey)

    def __init__(self, hash_method: hashes.HashAlgorithm = None, key_size: int = None, exponent: int = None):
        if isinstance(hash_method, hashes.HashAlgorithm):
            self.HASH_METHOD = hash_method
            self.PREHASHED = utils.Prehashed(self.HASH_METHOD)
        elif hash_method is not None:
            raise TypeError("hash_method must be an instance of a class derived from hashes.HashAlgorithm or None")

        if key_size:
            self.KEY_SIZE = key_size

        if exponent:
            self.PUBLIC_EXPONENT = exponent

        # Early check parameters
        # noinspection PyProtectedMember
        rsa._verify_rsa_parameters(self.PUBLIC_EXPONENT, self.KEY_SIZE)

    def get_asymetric_padding(self):
        return padding.PSS(
            mgf=padding.MGF1(self.HASH_METHOD),
            salt_length=padding.PSS.MAX_LENGTH
        )

    def create_private_key(self) -> rsa.RSAPrivateKey:
        return rsa.generate_private_key(
            public_exponent=self.PUBLIC_EXPONENT,
            key_size=self.KEY_SIZE
        )

    def sign(self, privatekey: rsa.RSAPrivateKey, data: bytes) -> bytes:
        return privatekey.sign(
            data,
            self.get_asymetric_padding(),
            self.HASH_METHOD
        )

    def sign_prehashed(self, privatekey: rsa.RSAPrivateKey, data: bytes) -> bytes:
        return privatekey.sign(
            data,
            self.get_asymetric_padding(),
            self.PREHASHED
        )

    def verify(self, publickey: rsa.RSAPublicKey, sig: bytes, data: bytes):
        publickey.verify(
            sig,
            data,
            self.get_asymetric_padding(),
            self.HASH_METHOD
        )

    def verify_prehashed(self, publickey: rsa.RSAPublicKey, sig: bytes, data: bytes):
        publickey.verify(
            sig,
            data,
            self.get_asymetric_padding(),
            self.PREHASHED
        )

    def apply_cryptoconfig(self, publickey: rsa.RSAPublicKey):
        self.KEY_SIZE = publickey.key_size
        self.PUBLIC_EXPONENT = publickey.public_numbers().e

    def apply_hash(self, certhash: hashes.HashAlgorithm):
        self.HASH_METHOD = certhash
        self.PREHASHED = utils.Prehashed(self.HASH_METHOD)

    def __repr__(self):
        return f"<{self.__class__.__name__}, KeySize={self.KEY_SIZE} Exponent={self.PUBLIC_EXPONENT}>"


CryptoTypes = {ECCrypto, RSACrypto, Ed25519Crypto, Ed448Crypto}


def convert_timeinfo(d: Union[datetime, int, None]) -> Optional[datetime]:
    if d is None:
        return None
    elif type(d) is int:
        data = datetime.now(timezone.utc) + (_DAY * d)
    elif type(d) is datetime:
        if d.tzinfo is None:
            raise ValueError("datetime object must be timezone aware.")
        data = d
    else:
        raise ValueError("Unsupported type of d: " + repr(d))

    # Convert to UTC
    data = data.astimezone(timezone.utc)

    if data < _EARLIEST_UTC_TIME:
        raise ValueError("Date is below earliest allowed date (01.01.1950): " + str(data))

    return data


def _load_x509_crl(crl: bytes):
    with suppress(ValueError):
        return load_pem_x509_crl(crl)

    return load_der_x509_crl(crl)


def _load_x509_csr(csr: bytes):
    with suppress(ValueError):
        return load_pem_x509_csr(csr)

    return load_der_x509_csr(csr)


def _load_x509_certificate(cert: bytes):
    with suppress(ValueError):
        return load_pem_x509_certificate(cert)

    return load_der_x509_certificate(cert)


def _load_public_key(pubkey: bytes):
    with suppress(ValueError):
        return serialization.load_pem_public_key(pubkey)

    return serialization.load_der_public_key(pubkey)


def _translate_optional_password(password: Union[str, bytes, bytearray]) -> Optional[bytes]:
    """
    Return bytes of a password or None
    """
    if password is None:
        return None

    if isinstance(password, str):
        return password.encode("utf-8")

    if isinstance(password, (bytes, bytearray)):
        return bytes(password)

    raise TypeError("Invalid passwort type: " + str(type(password)))


def _load_private_key(privkey: bytes, password: Union[str, bytes, bytearray] = None):
    password = _translate_optional_password(password)

    with suppress(ValueError):
        # TypeError -> Wrong password
        return serialization.load_pem_private_key(privkey, password)

    return serialization.load_der_private_key(privkey, password)


def _check_file(file: Union[str, Path], must_exist: bool, argname: str = None) -> Path:
    if isinstance(file, str):
        file_res = Path(file)
    elif isinstance(file, Path):
        file_res = file
    else:
        msg = f"Argument '{argname}'" if argname else "Argument"
        raise TypeError(f"{msg} must be str or Path. Not '{type(file)}'.")

    if must_exist and not file_res.is_file():
        msg = f" defined in '{argname}'" if argname else ""
        raise FileNotFoundError(f"File{msg} does not exists: {file_res}")

    return file_res


class PublicKey:
    """
    Simple PublicKey container with its verifying and hash functions
    """

    # For use as default on key creation
    CryptoType = ECCrypto  # Reference this class as default

    def __init__(self, pubkey: Union[str, Path, bytes, PublicKeyTypes]):
        """
        Loads a public key.
        :param pubkey:
            str, Path: Load from file
            bytes: Load from bytes representation
            PublicKeyTypes: Load public key from Cryptography's public key instances
        """

        if isinstance(pubkey, get_args(PublicKeyTypes)):
            # It's a public key already
            self._public_key = pubkey

        elif isinstance(pubkey, bytes):
            # Read pubkey from bytes
            self._public_key = _load_public_key(pubkey)

        elif isinstance(pubkey, (str, Path)):
            # Read pubkey from bytes of file
            pubkey = _check_file(pubkey, must_exist=True, argname="pubkey")
            self._public_key = _load_public_key(pubkey.read_bytes())

        else:
            raise TypeError("Unsupported format for public key given: " + str(type(pubkey)))

        self._read_crypto_type()

    def hash_bytes(self, data: bytes) -> bytes:
        """
        Hash data bytes with configured hash algorythm if available.
        :param data: Data as bytes.
        :return: Hash as bytes
        """

        if not self.CryptoType.HASH_METHOD:
            raise NotImplementedError("We don't have access to the internal hash method. "
                                      "External prehashing not allowed or possible.")

        hasher = hashes.Hash(self.CryptoType.HASH_METHOD)
        hasher.update(data)
        return hasher.finalize()

    def hash_file(self, file: Union[str, Path], chunk_size=512) -> bytes:
        """
        Hash a file on disk.
        :param file: str or Path to the existing file
        :param chunk_size: Size of chunks to read and pass to the hash function.
        :return: Hash as bytes
        """

        if not self.CryptoType.HASH_METHOD:
            raise NotImplementedError("We don't have access to the internal hash method. "
                                      "External prehashing not allowed or possible.")

        file = _check_file(file, must_exist=True, argname="file")

        hasher = hashes.Hash(self.CryptoType.HASH_METHOD)
        with file.open("rb") as fh:
            for chunk in iter(partial(fh.read, chunk_size), b''):  # type: bytes
                hasher.update(chunk)
        return hasher.finalize()

    def hash_file_to_file(self, file_to_hash: Union[str, Path], hash_save_to: Union[str, Path], chunk_size=512):
        """
        Same as hash_file but saves the result in a file directly
        :param file_to_hash: str or Path to the existing file
        :param hash_save_to: str or Path of the file which will be created or overwritten. Contains the calculated hash.
        :param chunk_size: Size of chunks to read and pass to the hash function.
        """

        if not self.CryptoType.HASH_METHOD:
            raise NotImplementedError("We don't have access to the internal hash method. "
                                      "External prehashing not allowed or possible.")

        file_write = _check_file(hash_save_to, must_exist=False, argname="hash_save_to")
        file_hash = self.hash_file(file=file_to_hash, chunk_size=chunk_size)
        file_write.write_bytes(file_hash)

    def _read_crypto_type(self):
        if self.CryptoType not in CryptoTypes:
            # It's a class instance already and not a reference to the default class anymore.
            # Should be a reference to a class derived from _CryptoType
            raise TypeError("CryptoType already defined.")

        for ct in CryptoTypes:
            if isinstance(self._public_key, ct.PUBLIC_KEY_TYPE):
                # Create actual instance
                self.CryptoType = ct()
                self.CryptoType.apply_cryptoconfig(self._public_key)
                break
        else:
            raise TypeError("Unsupported crypto type.")

    @property
    def public_key(self) -> PublicKeyTypes:
        """
        Returns the internal PublicKey from Cryptography
        """
        return self._public_key

    @property
    def public_key_digest(self) -> bytes:
        return SubjectKeyIdentifier.from_public_key(self._public_key).digest

    def public_key_to_bytes(self,
                            encoding=serialization.Encoding.PEM,
                            fmt=serialization.PublicFormat.SubjectPublicKeyInfo) -> bytes:
        """
        Serializes the PublicKey into bytes.
        :param encoding: Encoding from serialization.Encoding, defaults to PEM
        :param fmt: PublicKey format, defaults to X.509
        :return: Serialized PublicKey as bytes
        """
        return self._public_key.public_bytes(
            encoding=encoding,
            format=fmt
        )

    def public_key_to_file(self, file: Union[str, Path],
                           encoding=serialization.Encoding.PEM,
                           fmt=serialization.PublicFormat.SubjectPublicKeyInfo):
        """
        Same as public_key_to_bytes but writes to a file directly.
        :param file: str or Path of the file which will be created or overwritten. Contains the serialized PublicKey
        :param encoding: Encoding from serialization.Encoding, defaults to PEM
        :param fmt: PublicKey format, defaults to X.509
        """

        file = _check_file(file, must_exist=False, argname="file")
        file.write_bytes(self.public_key_to_bytes(encoding, fmt))

    def verify_bytes(self, sig: Union[str, Path, bytes], data_or_hash: bytes, already_hashed=False):
        """
        Verify the data and signature by the PublicKey.
        Especially huge data should be passed prehashed.
        :param sig: Signature of the data created with this Public key. Can be a str or Path to a file on disk.
        :param data_or_hash: Data or prehashed checksum which integrity will be checked. On prehashed set already_hashed to True
        :param already_hashed: Set to True if passing prehashed data
        :raises: Raises InvalidSignature if the signature does not match the data or PublicKey.
        """
        if isinstance(sig, (str, Path)):
            sig_path = _check_file(sig, must_exist=True, argname="sig")
            sig_bytes = sig_path.read_bytes()
        elif isinstance(sig, bytes):
            sig_bytes = sig
        else:
            raise TypeError("sig must be signature as bytes or Path/str pointing to sig file.")

        if already_hashed:
            if self.CryptoType.HASH_METHOD is None:
                raise NotImplementedError("The crypto type does not support prehashed data.")

            self.CryptoType.verify_prehashed(self._public_key, sig_bytes, data_or_hash)
        else:
            # Use verify function of selected cryptotype
            self.CryptoType.verify(self._public_key, sig_bytes, data_or_hash)

    def verify_file(self, sig: Union[str, Path, bytes], file: Union[str, Path]):
        """
        Same as verify_bytes but verifies an existing file on disk.
        :param sig: Signature of the data created with this Public key. Can be a str or Path to a file on disk.
        :param file: File that will be verified against the signature and PublicKey
        :raises: Raises InvalidSignature if the signature does not match the data or PublicKey.
        """
        if self.CryptoType.HASH_METHOD:
            # We can use prehashes and avoid loading the file into RAM completely.
            file = _check_file(file, must_exist=True, argname="file")
            file_hash = self.hash_file(file)
            self.verify_bytes(sig=sig, data_or_hash=file_hash, already_hashed=True)
        else:
            # Prehashing not possible or allowed (yet). We have to read the file completely into RAM.
            self.verify_bytes(sig=sig, data_or_hash=file.read_bytes())

    def __repr__(self):
        return f"<{self.__class__.__name__}({self.CryptoType!r}) {self.public_key_digest.hex(':')}>"


class PrivateKey(PublicKey):
    """
    Simple PrivateKey container with its signing functions.
    Every PrivateKey contains a PublicKey. So this class inherits all PublicKey functions.
    """
    def __init__(self,
                 privkey: Union[str, Path, bytes, PrivateKeyTypes, "PrivateKey", _CryptoType, Type[_CryptoType]] = None,
                 passwd: Union[str, bytes, bytearray] = None):
        """
        Create or load a PrivateKey
        :param privkey:
            str, Path: Load the key from an existing file.
            bytes: Load the key from bytes.
            PrivateKeyTypes: Creates a container based in Cryptography's PrivateKey instances.
            PrivateKey: Create a duplicate from existing instance
            CryptoType: Class or instance of a supported key type to create a new PrivateKey.
            None: Create a new PrivateKey based on the default of this class's CryptoType
        :param passwd: The optional password which protects the PrivateKey
        """

        # Local storage password
        self._password = _translate_optional_password(passwd)

        # Private key
        if isinstance(privkey, get_args(PrivateKeyTypes)):
            # It's a private key already
            self._private_key = privkey

        elif isinstance(privkey, bytes):
            # Read privkey from bytes
            self._private_key = _load_private_key(privkey, password=self._password)

        elif isinstance(privkey, (str, Path)):
            # Read privkey from bytes of file
            privkey = _check_file(privkey, must_exist=True, argname="privkey")
            self._private_key = _load_private_key(privkey.read_bytes(), password=self._password)

        elif isinstance(privkey, PrivateKey):
            # Copy from another instance
            self._private_key = privkey._private_key

        elif isinstance(privkey, _CryptoType):
            # Create private key based on user defined config
            self._private_key = privkey.create_private_key()

        elif isclass(privkey) and issubclass(privkey, _CryptoType):
            # Create private key based on user defined config
            self._private_key = privkey.create_private_key(privkey)

        elif privkey is None and isclass(self.CryptoType):
            # Create a new private key of default type now
            # Call a class method
            self._private_key = self.CryptoType.create_private_key(self.CryptoType)

        else:
            raise TypeError("Unsupported format for private key given: " + str(type(privkey)))

        # Init corresponding public key
        PublicKey.__init__(self, self._private_key.public_key())

    def private_key_to_bytes(self, encoding=serialization.Encoding.PEM, fmt=serialization.PrivateFormat.PKCS8) -> bytes:
        """
        Serializes the PrivateKey into bytes.
        The key is protected by the password given on init.
        :param encoding: Encoding from serialization.Encoding, defaults to PEM
        :param fmt: PrivateKey format, defaults to PKCS8
        :return: Serialized PrivateKey
        """

        if self._password:
            enc = serialization.BestAvailableEncryption(self._password)
        else:
            enc = serialization.NoEncryption()

        return self._private_key.private_bytes(
            encoding=encoding,
            format=fmt,
            encryption_algorithm=enc
        )

    def private_key_to_file(self, file: Union[str, Path],
                            encoding=serialization.Encoding.PEM, fmt=serialization.PrivateFormat.PKCS8):
        """
        Same as private_key_to_bytes but writes the PrivateKey directly to a file.
        :param file: File which will be created or overwritten containing the PrivateKey.
        :param encoding: Encoding from serialization.Encoding, defaults to PEM
        :param fmt: PrivateKey format, defaults to PKCS8
        """

        file = _check_file(file, must_exist=False, argname="file")
        file.write_bytes(self.private_key_to_bytes(encoding, fmt))
        file.chmod(0o600)

    @property
    def private_key(self) -> PrivateKeyTypes:
        """
        Returns the internal PrivateKey from Cryptography
        """
        return self._private_key

    def sign_bytes(self, data: bytes) -> bytes:
        """
        Signs data by the PrivateKey
        :param data: Raw data to be signed
        :return: The signature of the data and PrivateKey
        """
        return self.CryptoType.sign(self._private_key, data)

    def sign_prehashed(self, datahash: bytes) -> bytes:
        """
        Signs prehashed data by the PrivateKey
        :param datahash: Prehashed data to be signed
        :return: The signature of the prehashed data and PrivateKey
        """

        if not self.CryptoType.HASH_METHOD:
            raise NotImplementedError("We don't have access to the internal hash method. "
                                      "External prehashing not allowed or possible.")

        return self.CryptoType.sign_prehashed(self._private_key, datahash)

    def sign_file(self, file_to_sign: Union[str, Path]) -> bytes:
        """
        Signs a file by the PrivateKey
        :param file_to_sign: The file to be signed.
        :return: The signature of the file and PrivateKey
        """
        file_to_sign = _check_file(file_to_sign, must_exist=True, argname="file_to_sign")

        if self.CryptoType.HASH_METHOD:
            file_hash = self.hash_file(file_to_sign)
            return self.sign_prehashed(file_hash)
        else:
            return self.sign_bytes(data=file_to_sign.read_bytes())

    def sign_file_to_file(self, file_to_sign: Union[str, Path], sign_save_to: Union[str, Path]):
        """
        Same as sign_file but writes the signature directly to a file.
        :param file_to_sign: The file to be signed.
        :param sign_save_to: The file to save the signature to.
        """
        sign_of_file = self.sign_file(file_to_sign)
        sign_save_to = _check_file(sign_save_to, must_exist=False, argname="sign_save_to")
        sign_save_to.write_bytes(sign_of_file)


class NameAttributeList:
    @classmethod
    def from_name(cls, name: x509Name, frozen=True) -> "NameAttributeList":
        new_list = NameAttributeList()
        new_list.attribute_list.extend(iter(name))
        if frozen:
            new_list._freeze()
        return new_list

    def __init__(self,
                 country: str = None,
                 state_or_province: str = None,
                 locality: str = None,
                 street: str = None,
                 common_name: str = None,
                 email: str = None,
                 organization: str = None,
                 organization_unit: str = None,
                 ):
        """
        Presets name attributes in fixed order out of supplied arguments.
        None will skip this attributes.

        :param country: two letter country code defined in ISO 3166
        :param state_or_province: State or province
        :param locality: City name
        :param street:
        :param common_name: Name of person as naming convention of the country or culture
        :param email:
        :param organization:
        :param organization_unit:
        """

        self.attribute_list: Union[List[NameAttribute], Tuple[NameAttribute]] = []

        _mapping = [
            (NameOID.COUNTRY_NAME, country),
            (NameOID.STATE_OR_PROVINCE_NAME, state_or_province),
            (NameOID.LOCALITY_NAME, locality),
            (NameOID.STREET_ADDRESS, street),
            (NameOID.COMMON_NAME, common_name),
            (NameOID.EMAIL_ADDRESS, email),
            (NameOID.ORGANIZATION_NAME, organization),
            (NameOID.ORGANIZATIONAL_UNIT_NAME, organization_unit),
        ]

        for oid, data in _mapping:
            if type(data) is str:
                self.attribute_list.append(NameAttribute(oid, data.strip()))

    def get_oid(self, oid: ObjectIdentifier, default=None) -> Optional[NameAttribute]:
        for o in self.attribute_list:
            if o.oid == oid:
                return o
        return default

    def _freeze(self):
        if type(self.attribute_list) is tuple:
            raise ValueError("NameAttributeList is already frozen.")
        self.attribute_list = tuple(self.attribute_list)

    def to_name(self) -> x509Name:
        return x509Name(self.attribute_list)

    def rfc4514_string(self) -> str:
        return self.to_name().rfc4514_string()

    def __repr__(self):
        return f"<NameAttributeList '{self.rfc4514_string()}'>"

    def __str__(self):
        return self.rfc4514_string()


@dataclass
class CommonName:
    common_name: str  # Max 64 letters

    def to_attribute_list(self) -> NameAttributeList:
        return NameAttributeList(common_name=self.common_name)


@dataclass
class FullOrganization(CommonName):
    country_name: str = None  # 2 letters
    state_or_province_name: str = None
    locality_name: str = None
    street_name: str = None
    organization_name: str = None
    organization_unit_name: str = None
    email_address: str = None  # Max 64 letters

    def to_attribute_list(self) -> NameAttributeList:
        return NameAttributeList(common_name=self.common_name,
                                 country=self.country_name,
                                 state_or_province=self.state_or_province_name,
                                 locality=self.locality_name,
                                 street=self.street_name,
                                 organization=self.organization_name,
                                 organization_unit=self.organization_unit_name,
                                 email=self.email_address
                                 )


class AttributesBase:
    def __init__(self):
        self._attributes: List[Tuple[ObjectIdentifier, bytes, Optional[int]]] = []

    def add_attribute(self, oid: ObjectIdentifier, value: bytes):
        if not isinstance(oid, ObjectIdentifier):
            raise TypeError("oid of attribute must be an ObjectIdentifier.")
        if oid in (attr[0] for attr in self._attributes):
            raise ValueError("This attribute has already been set.")
        self._attributes += [(oid, value)]


class ExtensionsBase:
    def __init__(self, frozen_extensions: Iterable[Extension] = None):
        self._extensions: Union[List[Extension], Tuple[Extension, ...]] = \
            [] if frozen_extensions is None else tuple(frozen_extensions)

    def add_extension(self, extension: ExtensionType, critical: bool):
        if isinstance(self._extensions, tuple):
            raise ValueError("Extensions are read only.")

        if not isinstance(extension, ExtensionType):
            raise TypeError("extension must be an ExtensionType")

        if extension.oid in (e.oid for e in self._extensions):
            raise ValueError("This extension has already been set.")

        ext = Extension(extension.oid, critical, extension)
        self._extensions.append(ext)

    def get_extension(self, ext: Union[Type[Extension], Type[ExtensionType]], default=None) -> Optional[Extension]:
        for e in self._extensions:
            # if isinstance(e.value, ext):
            if ext.oid == e.oid:
                return e.value

        return default


class Cert(PublicKey, ExtensionsBase):
    """
    A certificate based on a PublicKey and some X.509 extensions.
    """
    def __init__(self, cert: Union[str, Path, bytes, Certificate]):
        if isinstance(cert, bytes):
            # Read cert from bytes
            self._cert = _load_x509_certificate(cert)

        elif isinstance(cert, Certificate):
            # It's a certificate already
            self._cert = cert

        elif isinstance(cert, (str, Path)):
            # Read cert from bytes of file
            cert = _check_file(cert, must_exist=True, argname="cert")
            self._cert = _load_x509_certificate(cert.read_bytes())

        else:
            raise TypeError("Unsupported format for certificate given: " + str(type(cert)))

        PublicKey.__init__(self, self._cert.public_key())
        self.CryptoType.apply_hash(self._cert.signature_hash_algorithm)

        ExtensionsBase.__init__(self, self._cert.extensions)

        self._issuer = NameAttributeList.from_name(self._cert.issuer)
        self._subject = NameAttributeList.from_name(self._cert.subject)

    @property
    def cert(self) -> Certificate:
        return self._cert

    @property
    def extensions(self) -> Tuple[Extension]:
        return tuple(self._extensions)

    @property
    def serial_number(self) -> int:
        return self._cert.serial_number

    @property
    def not_valid_before(self) -> datetime:
        return self._cert.not_valid_before_utc

    @property
    def not_valid_after(self) -> datetime:
        return self._cert.not_valid_after_utc

    @property
    def issuer(self) -> NameAttributeList:
        return self._issuer

    @property
    def subject(self) -> NameAttributeList:
        return self._subject

    @property
    def version(self) -> Version:
        return self._cert.version

    @property
    def signature(self) -> bytes:
        return self._cert.signature

    @property
    def is_valid_by_date(self) -> bool:
        return self._cert.not_valid_before_utc < datetime.now(timezone.utc) < self._cert.not_valid_after_utc

    def to_bytes(self, encoding=serialization.Encoding.PEM) -> bytes:
        return self._cert.public_bytes(encoding=encoding)

    def to_file(self, file: Union[str, Path], encoding=serialization.Encoding.PEM):
        file = _check_file(file, must_exist=False, argname="file")
        file.write_bytes(self.to_bytes(encoding=encoding))

    def __repr__(self):
        return f"<{self.__class__.__name__}({self.CryptoType!r}) sn='{self._cert.serial_number}' " \
               f"issuer='{self._issuer!s}', " \
               f"subject='{self._subject!s}', " \
               f"not_valid_before='{self._cert.not_valid_before_utc}', " \
               f"not_valid_after='{self._cert.not_valid_after_utc}' " \
               f"{self.public_key_digest.hex(':')}>"


class CertSigningRequest(PublicKey, ExtensionsBase):
    def __init__(self, csr: Union[str, Path, bytes, CertificateSigningRequest]):
        if isinstance(csr, CertificateSigningRequest):
            self._csr = csr

        elif isinstance(csr, bytes):
            self._csr = _load_x509_csr(csr)

        elif isinstance(csr, (str, Path)):
            csr = _check_file(csr, must_exist=True, argname="csr")
            self._csr = _load_x509_csr(csr.read_bytes())

        else:
            raise TypeError("Unsupported type for csr given: " + str(type(csr)))

        PublicKey.__init__(self, self._csr.public_key())
        self.CryptoType.apply_hash(self._csr.signature_hash_algorithm)

        ExtensionsBase.__init__(self, self._csr.extensions)

        self._subject = NameAttributeList.from_name(self._csr.subject)

    @property
    def csr(self) -> CertificateSigningRequest:
        return self._csr

    @property
    def subject(self) -> NameAttributeList:
        return self._subject

    @property
    def extensions(self) -> Tuple[Extension]:
        return tuple(self._extensions)

    @property
    def signature(self) -> bytes:
        return self._csr.signature

    def signature_valid(self) -> bool:
        return self._csr.is_signature_valid

    def to_bytes(self) -> bytes:
        return self._csr.public_bytes(encoding=serialization.Encoding.PEM)

    def to_file(self, file: Union[str, Path]):
        file = _check_file(file, must_exist=False, argname="file")
        file.write_bytes(self.to_bytes())

    def __repr__(self):
        return f"<{self.__class__.__name__}({self.CryptoType!r}) subject='{self._subject!s}'"


class CertBuilder(PrivateKey, ExtensionsBase):
    def __init__(self, privkey: Union[str, Path, bytes, PrivateKeyTypes, PrivateKey, _CryptoType, Type[_CryptoType]],
                 passwd: Union[str, bytes, bytearray] = None):
        PrivateKey.__init__(self, privkey=privkey, passwd=passwd)
        ExtensionsBase.__init__(self)

    @property
    def extensions(self) -> List[Extension]:
        return self._extensions

    def create_cert(self,
                    issuer: NameAttributeList,
                    cert_or_csr_or_subject_pubkey: Union[Cert, CertSigningRequest, Tuple[NameAttributeList, PublicKey]],
                    serial_number: Optional[int] = _RANDOM,
                    not_valid_before: Union[datetime, int] = -1,
                    not_valid_after: Union[datetime, int] = 365,
                    individual_extensions: Iterable[Extension] = None
                    ) -> Cert:

        # Get subject name and public key
        subject_name: x509Name
        subject_pubkey: PublicKeyTypes

        if isinstance(cert_or_csr_or_subject_pubkey, (Cert, CertSigningRequest)):
            subject_name = cert_or_csr_or_subject_pubkey.subject.to_name()
            subject_pubkey = cert_or_csr_or_subject_pubkey.public_key

        elif type(cert_or_csr_or_subject_pubkey) is tuple \
                and len(cert_or_csr_or_subject_pubkey) == 2 \
                and isinstance(cert_or_csr_or_subject_pubkey[0], NameAttributeList) \
                and isinstance(cert_or_csr_or_subject_pubkey[1], PublicKey):
            subject_name = cert_or_csr_or_subject_pubkey[0].to_name()
            subject_pubkey = cert_or_csr_or_subject_pubkey[1].public_key

        else:
            raise TypeError("cert_or_csr_or_subject_pubkey must be: Cert or CertSigningRequest or "
                            "Tuple[NameAttributeList, PublicKey]")

        # Merge extensions
        exts_merged = list(self._extensions)
        if individual_extensions:
            exts_merged.extend(individual_extensions)

        for i, iext in enumerate(exts_merged):
            if not isinstance(iext, Extension):
                raise TypeError("Extension must be type of Extension")

            for jext in exts_merged[:i]:
                if iext.oid == jext.oid:
                    raise ValueError("Extension " + repr(iext.oid) + " has already been set before.")

        # Serial number
        if serial_number is _RANDOM:
            sn = random_serial_number()
        elif serial_number is None or type(serial_number) is int:
            sn = serial_number
        else:
            raise ValueError("serial_number must be _RANDOM (default), None or an integer.")

        # Valid date bounds
        _not_valid_before = convert_timeinfo(not_valid_before)
        _not_valid_after = convert_timeinfo(not_valid_after)

        if _not_valid_before > _not_valid_after:
            raise ValueError("not_valid_before must be lower than not_valid_after.")

        # Create the internal builder
        builder = CertificateBuilder(
            issuer_name=issuer.to_name(),
            subject_name=subject_name,
            public_key=subject_pubkey,
            serial_number=sn,
            not_valid_before=_not_valid_before,
            not_valid_after=_not_valid_after,
            extensions=exts_merged
        )

        cert = builder.sign(private_key=self.private_key, algorithm=self.CryptoType.HASH_METHOD)
        return Cert(cert)


class CsrBuilder(PrivateKey, ExtensionsBase, AttributesBase):
    def __init__(self,
                 privkey: Union[str, Path, bytes, PrivateKeyTypes, _CryptoType, Type[_CryptoType]] = None,
                 passwd: Union[str, bytes, bytearray] = None):
        PrivateKey.__init__(self, privkey=privkey, passwd=passwd)
        ExtensionsBase.__init__(self)
        AttributesBase.__init__(self)

    @property
    def extensions(self) -> List[Extension]:
        return self._extensions

    def build_csr(self,
                  subject: NameAttributeList,
                  individual_extensions: Iterable[Extension] = None) -> CertSigningRequest:
        ext = list(self._extensions)
        if individual_extensions:
            for iext in individual_extensions:
                if not isinstance(iext, Extension):
                    raise TypeError("extension must be type of Extension")

                if iext.oid in (e.oid for e in ext):
                    raise ValueError("This extension has already been set.")

                ext.append(iext)

        # Create the internal builder
        builder = CertificateSigningRequestBuilder(
            subject_name=subject.to_name(),
            extensions=ext,
            attributes=self._attributes
        )
        csr = builder.sign(private_key=self.private_key, algorithm=self.CryptoType.HASH_METHOD)

        return CertSigningRequest(csr)


class RevokedCert(ExtensionsBase):
    def __init__(self, serial_number: int,
                 revocation_date: Union[datetime, int] = 0,
                 extensions_or_reason: Union[CRLReasonFlags, Iterable[Extension]] = None):

        self._sn = serial_number
        self._revdate = revocation_date

        if isinstance(extensions_or_reason, CRLReasonFlags):
            extensions_or_reason = self._reason_to_extensions(extensions_or_reason)

        ExtensionsBase.__init__(self, frozen_extensions=extensions_or_reason)

    @staticmethod
    def _reason_to_extensions(reason: CRLReasonFlags) -> Tuple[Extension, ...]:
        ebuilder = ExtensionBuilder()
        ebuilder.CRLReason(False, reason)
        return tuple(ebuilder.extensions)

    @classmethod
    def from_certificate(cls, cert: Union[Cert, Certificate],
                         revocation_date: Union[datetime, int] = 0,
                         extensions_or_reason: Union[CRLReasonFlags, Iterable[Extension]] = None) -> "RevokedCert":
        if isinstance(cert, (Cert, Certificate)):
            return RevokedCert(cert.serial_number, revocation_date, extensions_or_reason)

        raise TypeError("Expected types for cert are: Cert or Certificate.")

    @classmethod
    def from_revoked_certificate(cls, rcert: RevokedCertificate):
        return RevokedCert(rcert.serial_number, rcert.revocation_date, rcert.extensions)

    @property
    def serial_number(self) -> int:
        return self._sn

    @property
    def revocation_date(self) -> datetime:
        return self._revdate

    @property
    def extensions(self) -> Tuple[Extension]:
        return tuple(self._extensions)

    @property
    def crl_reason(self) -> Optional[CRLReasonFlags]:
        reasons_ext: Optional[CRLReason] = self.get_extension(CRLReason)
        if reasons_ext is None:
            return None

        return CRLReasonFlags[str(reasons_ext.reason.value)]

    def __repr__(self):
        return f"<{self.__class__.__name__} sn='{self._sn}' revocation_date={self._revdate} reason={self.crl_reason}>"


class Crl(ExtensionsBase):
    def __init__(self, crl: Union[str, Path, bytes, CertificateRevocationList]):
        if isinstance(crl, CertificateRevocationList):
            self._crl = crl

        elif isinstance(crl, bytes):
            self._crl = _load_x509_crl(crl)

        elif isinstance(crl, (str, Path)):
            crl = _check_file(crl, must_exist=True, argname="crl")
            self._crl = _load_x509_crl(crl.read_bytes())

        else:
            raise TypeError("Unsupported format for CRL given: " + str(type(crl)))

        ExtensionsBase.__init__(self, self._crl.extensions)

        # TODO: convert crl items directly?

        self._issuer = NameAttributeList.from_name(self._crl.issuer)
        self._next_update = self._crl.next_update
        self._last_update = self._crl.last_update

    @property
    def issuer(self) -> NameAttributeList:
        return self._issuer

    @property
    def next_update(self) -> datetime:
        return self._next_update

    @property
    def last_update(self) -> datetime:
        return self._last_update

    @property
    def extensions(self) -> Tuple[Extension]:
        return tuple(self._extensions)

    @property
    def is_valid_by_date(self) -> bool:
        return self._crl.last_update < datetime.now(timezone.utc) < self._crl.next_update

    def is_signature_valid(self, pubkey: PublicKey) -> bool:
        return self._crl.is_signature_valid(pubkey.public_key)

    def get_revoked_certificate_by_serial_number(self, serial_number: int) -> Optional[RevokedCert]:
        rc = self._crl.get_revoked_certificate_by_serial_number(serial_number)
        if rc is None:
            return None
        return RevokedCert.from_revoked_certificate(rc)

    def get_revoked_certificate_by_certificate(self, cert: Cert) -> Optional[RevokedCert]:
        return self.get_revoked_certificate_by_serial_number(cert.serial_number)

    def __iter__(self):
        return iter(RevokedCert.from_revoked_certificate(c) for c in self._crl)

    def __len__(self):
        return len(self._crl)

    def __getitem__(self, index: int) -> RevokedCert:
        return RevokedCert.from_revoked_certificate(self._crl[index])

    def crl_to_bytes(self, encoding=serialization.Encoding.PEM) -> bytes:
        return self._crl.public_bytes(encoding=encoding)

    def crl_to_file(self, file: Union[str, Path], encoding=serialization.Encoding.PEM):
        file = _check_file(file, must_exist=False, argname="file")
        file.write_bytes(self.crl_to_bytes(encoding=encoding))

    def __repr__(self):
        return f"<{self.__class__.__name__} " \
               f"issuer='{self._issuer!s}' revokes_count={len(self._crl)}, " \
               f"last_update={self._last_update}, next_update={self._next_update}>"


class CrlBuilder(PrivateKey, ExtensionsBase):
    def __init__(self,
                 privkey: Union[str, Path, bytes, PrivateKeyTypes] = None,
                 passwd: Union[str, bytes, bytearray] = None,
                 extensions: Iterable[Extension] = None):
        PrivateKey.__init__(self, privkey=privkey, passwd=passwd)
        ExtensionsBase.__init__(self, frozen_extensions=extensions)

        self._revoked_list: List[RevokedCert] = []

    def _add(self, rcert: RevokedCert):
        """Checks for not a duplicate (by serial number) and then adds to the current list"""

        for rc in self._revoked_list:
            if rcert.serial_number == rc.serial_number:
                raise DuplicateCertException("Serial number is already in crl.")
        self._revoked_list.append(rcert)

    def add_revocation(self, rcert: Union[RevokedCert, RevokedCertificate]):
        """
        Adds a revocation to the current list
        """
        if isinstance(rcert, RevokedCert):
            self._add(rcert)
        elif isinstance(rcert, RevokedCertificate):
            self._add(RevokedCert.from_revoked_certificate(rcert))
        else:
            raise TypeError("Unsupported type of rcert. Expected RevokedCert or RevokedCertificate.")

    @staticmethod
    def _build_revocation(rcert: RevokedCert) -> RevokedCertificate:
        builder = RevokedCertificateBuilder(
            serial_number=rcert.serial_number,
            revocation_date=rcert.revocation_date,
            extensions=list(rcert.extensions)
        )
        return builder.build()

    def clear(self):
        self._revoked_list.clear()

    def build_crl(self,
                  issuer: NameAttributeList,
                  last_update: Union[datetime, int] = 0,
                  next_update: Union[datetime, int] = 31
                  ) -> Crl:

        last_update = convert_timeinfo(last_update)
        next_update = convert_timeinfo(next_update)

        if next_update and last_update and next_update < last_update:
            raise RuntimeError("next_update must be later than last_update.")

        rcerts = [self._build_revocation(rc) for rc in self._revoked_list]

        builder = CertificateRevocationListBuilder(
            issuer_name=issuer.to_name(),
            last_update=last_update,
            next_update=next_update,
            extensions=self._extensions,
            revoked_certificates=rcerts
        )

        crl = builder.sign(private_key=self._private_key, algorithm=self.CryptoType.HASH_METHOD)
        return Crl(crl)


class ExtensionBuilder:
    """Tool for building x509 extensions.
    Wraps some common extensions as methods."""

    def __init__(self):
        self._exts: List[Extension] = []

    def clear(self):
        self._exts.clear()

    @property
    def extensions(self) -> List[Extension]:
        return self._exts

    def append(self, ext: Extension):
        """Method to add custom extensions"""
        for iext in self._exts:
            if iext.oid == ext.oid:
                raise ValueError("Extension " + repr(ext.oid) + " has already been set before.")

        self._exts.append(ext)

    def BasicConstraints(self,
                         critical=False,
                         ca=True,
                         path_length: int = None):

        self.append(Extension(BasicConstraints.oid,
                              critical,
                              BasicConstraints(
                                  ca=ca,
                                  path_length=path_length)
                              )
                    )

    def SubjectKeyIdentifier(self,
                             critical: bool,
                             digest: bytes):
        self.append(Extension(SubjectKeyIdentifier.oid,
                              critical,
                              SubjectKeyIdentifier(digest))
                    )

    def AuthorityKeyIdentifier(self,
                               critical: bool,
                               digest: bytes,
                               issuers: Union[Iterable[GeneralName], GeneralName],
                               sn: int = None):
        if sn is None:
            sn = random_serial_number()

        if isinstance(issuers, GeneralName):
            # Single Name. Handover as sequence.
            issuers = (issuers, )

        self.append(Extension(AuthorityKeyIdentifier.oid,
                              critical,
                              AuthorityKeyIdentifier(digest, issuers, sn))
                    )

    def ExtendedKeyUsage(self, critical: bool, usages: Iterable[ObjectIdentifier]):
        self.append(Extension(ExtendedKeyUsage.oid,
                              critical,
                              ExtendedKeyUsage(usages))
                    )

    def KeyUsage(self,
                 critical: bool,
                 digital_signature=False,
                 content_commitment=False,
                 key_encipherment=False,
                 data_encipherment=False,
                 key_agreement=False,
                 key_cert_sign=False,
                 crl_sign=False,
                 encipher_only=False,
                 decipher_only=False):

        self.append(Extension(KeyUsage.oid,
                              critical,
                              KeyUsage(digital_signature=digital_signature,
                                       content_commitment=content_commitment,
                                       key_encipherment=key_encipherment,
                                       data_encipherment=data_encipherment,
                                       key_agreement=key_agreement,
                                       key_cert_sign=key_cert_sign,
                                       crl_sign=crl_sign,
                                       encipher_only=encipher_only,
                                       decipher_only=decipher_only)
                              )
                    )

    def SubjectAltName(self,
                       critical: bool,
                       subject_alt_name: Union[Iterable[GeneralName], GeneralName]):

        if isinstance(subject_alt_name, GeneralName):
            # Single Name. Handover as sequence.
            subject_alt_name = (subject_alt_name, )

        self.append(Extension(SubjectAlternativeName.oid,
                              critical,
                              SubjectAlternativeName(subject_alt_name)
                              )
                    )

    def CRLReason(self,
                  critical: bool,
                  reason: CRLReasonFlags):

        self.append(Extension(CRLReason.oid,
                              critical,
                              CRLReason(_ReasonFlags(reason.name))
                              )
                    )

    def CRLDistributionPoints(self,
                              critical: bool,
                              endpoints: Iterable[DistributionPoint]):
        self.append(Extension(CRLDistributionPoints.oid,
                              critical,
                              CRLDistributionPoints(endpoints)
                              )
                    )


# Mapping PEM title labels to the corresponding class
_pem_label_to_class = {
    b"CERTIFICATE": Cert,
    b"X509 CRL": Crl,
    b"CERTIFICATE REQUEST": CertSigningRequest,
    b"PRIVATE KEY": PrivateKey,
    b"ENCRYPTED PRIVATE KEY": PrivateKey,
    b"PUBLIC KEY": PublicKey,
    # TODO: BEGIN OPENSSH PRIVATE KEY
}
