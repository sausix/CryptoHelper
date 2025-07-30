# -*- coding: utf-8 -*-

"""
CryptoHelper
Adrian Sausenthaler

Version: 0.3.0
"""

import re
from abc import ABCMeta, abstractmethod
from functools import partial
from typing import Union, Optional, Type, TypeVar, Generic
from pathlib import Path
from contextlib import suppress
from inspect import isclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding, utils, ed25519, ed448, types

from cryptography.x509 import SubjectKeyIdentifier


__all__ = (
    "PublicKey", "PrivateKey", "hashes", "ECCrypto", "RSACrypto", "Ed25519Crypto", "Ed448Crypto", "PublicKeysSupported",
    "PrivateKeysSupported", "PrivateKeysSupportedTypes", "check_file", "PasswordInput", "CryptoDefinition",
    "sanitize_password", "translate_optional_password"
)

__VERSION__ = "unknown"
if isinstance(__doc__, str):
    if _m := re.search("^Version: (.*)", __doc__):
        __VERSION__ = _m.group(1)


PublicKeysSupportedTypes = Union[
    ec.EllipticCurvePublicKey,
    rsa.RSAPublicKey,
    ed25519.Ed25519PublicKey,
    ed448.Ed448PublicKey
]

PrivateKeysSupportedTypes = Union[
    ec.EllipticCurvePrivateKey,
    rsa.RSAPrivateKey,
    ed25519.Ed25519PrivateKey,
    ed448.Ed448PrivateKey
]

PasswordInput = Union[str, bytes, bytearray, None]

PRIVKEY = TypeVar("PRIVKEY")
PUBKEY = TypeVar("PUBKEY")


# Supported key types
PublicKeysSupported = ec.EllipticCurvePublicKey, rsa.RSAPublicKey, ed25519.Ed25519PublicKey, ed448.Ed448PublicKey
PrivateKeysSupported = ec.EllipticCurvePrivateKey, rsa.RSAPrivateKey, ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey


class _CryptoType(Generic[PRIVKEY, PUBKEY], metaclass=ABCMeta):
    """
    Common base class for various crypto methods
    """
    HASH_METHOD = None

    PUBLIC_KEY_TYPE: Optional[Type[PublicKeysSupportedTypes]] = None  # Class of the specific public key
    PRIVATE_KEY_TYPE: Optional[Type[PrivateKeysSupportedTypes]] = None  # Class of the specific private key

    @abstractmethod
    def create_private_key(self) -> PRIVKEY:
        """Create and return a new private key instance"""

    @abstractmethod
    def sign(self, privatekey: PRIVKEY, data: bytes) -> bytes:
        """Sign some bytes with a private key instance.
        Returns bytes as signature."""

    @abstractmethod
    def sign_prehashed(self, privatekey: PRIVKEY, data: bytes) -> bytes:
        """Sign prehashed data with a private key instance.
        Files should be prehashed instead of loading them into memory completely.
        Returns bytes as signature."""

    @abstractmethod
    def verify(self, publickey: PUBKEY, sig: bytes, data: bytes):
        """Verifies data with the signature and a public key.
        Raises cryptography.exceptions.InvalidSignature on mismatch"""

    @abstractmethod
    def verify_prehashed(self, publickey: PUBKEY, sig: bytes, data: bytes):
        """Verifies prehashed data with the signature and a public key.
        Raises cryptography.exceptions.InvalidSignature on mismatch"""

    @abstractmethod
    def apply_cryptoconfig(self, publickey: PUBKEY):
        """Applies crypto parameters from a public key into a specific _CryptoType instance."""

    @abstractmethod
    def apply_hash(self, certhash: hashes.HashAlgorithm):
        """Applies hash algorithms and parameters into the specific _CryptoType instance."""


CryptoDefinition = Union[_CryptoType, Type[_CryptoType]]


class ECCrypto(_CryptoType[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]):
    """Interface class for elliptic curves"""
    HASH_METHOD = hashes.SHA256()

    ALGORITHM = ec.ECDSA(HASH_METHOD)
    ALGORITHM_PREHASHED = ec.ECDSA(utils.Prehashed(HASH_METHOD))
    CURVE_TYPE = ec.SECP521R1()

    PRIVATE_KEY_TYPE = ec.EllipticCurvePrivateKey
    PUBLIC_KEY_TYPE = ec.EllipticCurvePublicKey

    def __init__(self,
                 hash_method: Optional[hashes.HashAlgorithm] = None,
                 curve_type: Optional[ec.EllipticCurve] = None):
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


class Ed25519Crypto(_CryptoType[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]):
    """Interface class for Ed25519"""
    HASH_METHOD = None  # SHA512 but only used in backend internally.

    PRIVATE_KEY_TYPE = ed25519.Ed25519PrivateKey
    PUBLIC_KEY_TYPE = ed25519.Ed25519PublicKey

    # No settings, no __init__ needed

    def create_private_key(self) -> ed25519.Ed25519PrivateKey:
        return ed25519.Ed25519PrivateKey.generate()

    def sign(self, privatekey: ed25519.Ed25519PrivateKey, data: bytes) -> bytes:
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


class Ed448Crypto(_CryptoType[ed448.Ed448PrivateKey, ed448.Ed448PublicKey]):
    """Interface class for Ed448"""

    HASH_METHOD = None  # SHAKE265 but only used in backend internally.

    PRIVATE_KEY_TYPE = ed448.Ed448PrivateKey
    PUBLIC_KEY_TYPE = ed448.Ed448PublicKey

    # No settings, no __init__ needed

    def create_private_key(self) -> ed448.Ed448PrivateKey:
        return ed448.Ed448PrivateKey.generate()

    def sign(self, privatekey: ed448.Ed448PrivateKey, data: bytes) -> bytes:
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


class RSACrypto(_CryptoType[rsa.RSAPrivateKey, rsa.RSAPublicKey]):
    """Interface class for RSA"""
    HASH_METHOD = hashes.SHA256()
    PREHASHED = utils.Prehashed(HASH_METHOD)

    PUBLIC_EXPONENT = 65537  # 65537 Recommended. 3 for legacy compatibility.
    KEY_SIZE = 4096  # Minimum 512

    PRIVATE_KEY_TYPE = rsa.RSAPrivateKey
    PUBLIC_KEY_TYPE = rsa.RSAPublicKey

    def __init__(self,
                 hash_method: Optional[hashes.HashAlgorithm] = None,
                 key_size: Optional[int] = None,
                 exponent: Optional[int] = None):
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


# Register supported crypto classes
# CryptoTypesSupported = ECCrypto, RSACrypto, Ed25519Crypto, Ed448Crypto
PublicKeyTypeToCryptoType: dict[Type[types.PublicKeyTypes], Type[_CryptoType]] = {
    rsa.RSAPublicKey: RSACrypto,
    ec.EllipticCurvePublicKey: ECCrypto,
    ed25519.Ed25519PublicKey: Ed25519Crypto,
    ed448.Ed448PublicKey: Ed448Crypto,
}


def _get_cryptotype_from_publickeytype(pkt: Type[types.PublicKeyTypes]) -> Type[_CryptoType]:
    result = PublicKeyTypeToCryptoType.get(pkt)
    if result is not None:
        return result

    for key, value in PublicKeyTypeToCryptoType.items():
        if issubclass(pkt, key):
            return value

    raise TypeError("Unsupported crypto type.")


def _load_public_key(pubkey: bytes) -> PublicKeysSupportedTypes:
    with suppress(ValueError):
        # ValueError: Not a PEM public key.
        result = serialization.load_pem_public_key(pubkey)
        if not isinstance(result, PublicKeysSupported):
            raise TypeError("Loaded public key type not supported.")
        return result

    result = serialization.load_der_public_key(pubkey)
    if not isinstance(result, PublicKeysSupported):
        raise TypeError("Loaded public key type not supported.")

    return result


def translate_optional_password(password: PasswordInput = None) -> Optional[bytes]:
    """
    Return a bytes representation of a password or None
    """
    if password is None:
        return None

    if isinstance(password, str):
        return password.encode("utf-8")

    if isinstance(password, (bytes, bytearray)):
        return bytes(password)

    raise TypeError("Invalid password type: %s" % type(password))


def sanitize_password(passwd: PasswordInput) -> PasswordInput:
    """
    Translates "empty" passwords to an explicit None.
    Applies to empty strings, bytes and bytearrays which are translated to None.
    Call it early only in public functions.
    """
    if isinstance(passwd, (str, bytes, bytearray)):
        return passwd or None

    return passwd


def _load_private_key(privkey: bytes, password: PasswordInput = None) -> PrivateKeysSupportedTypes:
    password = translate_optional_password(password)

    with suppress(ValueError):
        # TypeError -> Wrong password
        result = serialization.load_pem_private_key(privkey, password)
        if not isinstance(result, PrivateKeysSupported):
            raise TypeError("Loaded private key type not supported.")
        return result

    result = serialization.load_der_private_key(privkey, password)
    if not isinstance(result, PrivateKeysSupported):
        raise TypeError("Loaded private key type not supported.")

    return result


def check_file(file: Union[str, Path], must_exist: bool, argname: str) -> Path:
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

    def __init__(self, pubkey: Union[str, Path, bytes, PublicKeysSupportedTypes, "PublicKey"]):
        """
        Loads a public key.
        :param pubkey:
            str, Path: Load from file
            bytes: Load from bytes representation
            PublicKeyTypes: Load public key from Cryptography's public key instances
            PublicKey: Load public key from another PublicKey instance
        """

        if not hasattr(self, "_source"):
            # Define if not defined yet.
            self._source = ""

        if isinstance(pubkey, PublicKey):
            self._public_key = pubkey.public_key
            self._source = self._source or f"PublicKey: [{pubkey.source}]"

        elif isinstance(pubkey, PublicKeysSupported):
            # It's a cryptography public key
            self._public_key = pubkey
            self._source = self._source or f"cryptography [{type(pubkey)}]"

        elif isinstance(pubkey, bytes):
            # Read pubkey from bytes
            self._public_key = _load_public_key(pubkey)
            self._source = self._source or "public key bytes"

        elif isinstance(pubkey, (str, Path)):
            # Read pubkey from bytes of file
            pubkey = check_file(pubkey, must_exist=True, argname="pubkey")
            self._public_key = _load_public_key(pubkey.read_bytes())
            self._source = self._source or f"public key file: {pubkey}"

        else:
            raise TypeError("Unsupported format for public key given: " + str(type(pubkey)))

        # Get crypto class and read settings
        pubkeytype = type(self._public_key)
        crypto_class = _get_cryptotype_from_publickeytype(pubkeytype)

        self._crypto_config = crypto_class()
        self._crypto_config.apply_cryptoconfig(self._public_key)

    @property
    def crypto_config(self) -> _CryptoType:
        return self._crypto_config

    @property
    def source(self) -> str:
        return self._source or "<unknown source>"

    def hash_bytes(self, data: bytes) -> bytes:
        """
        Hash data bytes with configured hash algorythm if available.
        :param data: Data as bytes.
        :return: Hash as bytes
        """

        if not self._crypto_config.HASH_METHOD:
            raise NotImplementedError("We don't have access to the internal hash method. "
                                      "External prehashing not allowed or possible.")

        hasher = hashes.Hash(self._crypto_config.HASH_METHOD)
        hasher.update(data)
        return hasher.finalize()

    def hash_file(self, file: Union[str, Path], chunk_size=512) -> bytes:
        """
        Hash a file on disk.
        :param file: str or Path to the existing file
        :param chunk_size: Size of chunks to read and pass to the hash function.
        :return: Hash as bytes
        """

        if not self._crypto_config.HASH_METHOD:
            raise NotImplementedError("We don't have access to the internal hash method. "
                                      "External prehashing not allowed or possible.")

        file = check_file(file, must_exist=True, argname="file")

        hasher = hashes.Hash(self._crypto_config.HASH_METHOD)
        with file.open("rb") as fh:
            for chunk in iter(partial(fh.read, chunk_size), b''):
                hasher.update(chunk)
        return hasher.finalize()

    def hash_file_to_file(self, file_to_hash: Union[str, Path], hash_save_to: Union[str, Path], chunk_size=512):
        """
        Same as hash_file but saves the result in a file directly
        :param file_to_hash: str or Path to the existing file
        :param hash_save_to: str or Path of the file which will be created or overwritten. Contains the calculated hash.
        :param chunk_size: Size of chunks to read and pass to the hash function.
        """

        if not self._crypto_config.HASH_METHOD:
            raise NotImplementedError("We don't have access to the internal hash method. "
                                      "External prehashing not allowed or possible.")

        file_write = check_file(hash_save_to, must_exist=False, argname="hash_save_to")
        file_hash = self.hash_file(file=file_to_hash, chunk_size=chunk_size)
        file_write.write_bytes(file_hash)

    @property
    def public_key(self) -> PublicKeysSupportedTypes:
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

        file = check_file(file, must_exist=False, argname="file")
        file.write_bytes(self.public_key_to_bytes(encoding, fmt))

    def verify_bytes(self, sig: Union[str, Path, bytes], data_or_hash: bytes, already_hashed=False):
        """
        Verify the data and signature by the PublicKey.
        Especially huge data should be passed prehashed.
        :param sig: Signature of the data created with this Public key. Can be a str or Path to a file on disk.
        :param data_or_hash: Data or prehashed checksum which integrity will be checked.
                             On prehashed set already_hashed to True
        :param already_hashed: Set to True if passing prehashed data
        :raises: Raises InvalidSignature if the signature does not match the data or PublicKey.
        """
        if isinstance(sig, (str, Path)):
            sig_path = check_file(sig, must_exist=True, argname="sig")
            sig_bytes = sig_path.read_bytes()
        elif isinstance(sig, bytes):
            sig_bytes = sig
        else:
            raise TypeError("sig must be signature as bytes or Path/str pointing to sig file.")

        if already_hashed:
            if self._crypto_config.HASH_METHOD is None:
                raise NotImplementedError("The crypto type does not support prehashed data.")

            self._crypto_config.verify_prehashed(self._public_key, sig_bytes, data_or_hash)
        else:
            # Use verify function of selected cryptotype
            self._crypto_config.verify(self._public_key, sig_bytes, data_or_hash)

    def verify_file(self, sig: Union[str, Path, bytes], file: Union[str, Path]):
        """
        Same as verify_bytes but verifies an existing file on disk.
        :param sig: Signature of the data created with this Public key. Can be a str or Path to a file on disk.
        :param file: File that will be verified against the signature and PublicKey
        :raises: Raises InvalidSignature if the signature does not match the data or PublicKey.
        """
        file = check_file(file, must_exist=True, argname="file")

        if self._crypto_config.HASH_METHOD:
            # We can use prehashes and avoid loading the file into RAM completely.
            file_hash = self.hash_file(file)
            self.verify_bytes(sig=sig, data_or_hash=file_hash, already_hashed=True)
        else:
            # Prehashing not possible or allowed (yet). We have to read the file completely into RAM.
            self.verify_bytes(sig=sig, data_or_hash=file.read_bytes())

    def __eq__(self, other):
        if not isinstance(other, type(self)):
            return NotImplemented

        return self.public_key == other.public_key

    def __repr__(self):
        return f"<{self.__class__.__name__}({self._crypto_config!r} {self.public_key_digest.hex(':')})>"


class PrivateKey(PublicKey):
    """
    Simple PrivateKey container with its signing functions.
    Every PrivateKey contains a PublicKey. So this class inherits all PublicKey functions.
    """
    def __init__(self,
                 privkey: Union[str, Path, bytes, PrivateKeysSupportedTypes, "PrivateKey", CryptoDefinition],
                 passwd: PasswordInput = None):
        """
        Create or load a PrivateKey
        :param privkey:
            str, Path: Load the key from an existing file.
            bytes: Load the key from bytes.
            PrivateKeysSupportedTypes: Creates a container based in Cryptography's PrivateKey instances.
            PrivateKey: Create a duplicate from existing PrivateKey instance
            CryptoLike: Class or instance of a supported crypto type to create a new PrivateKey.
        :param passwd: The optional password which protects the PrivateKey for opening or storing.
        """

        # Local storage password
        self._password = translate_optional_password(sanitize_password(passwd))

        if not hasattr(self, "_source"):
            # Define if not defined yet.
            self._source = ""

        if isinstance(privkey, PrivateKey):
            # Load from another PrivateKey instance
            self._private_key = privkey.private_key
            self._source = self._source or f"PrivateKey: [{privkey.source}]"

        elif isinstance(privkey, PrivateKeysSupported):
            # It's a cryptography private key already
            self._private_key = privkey
            self._source = self._source or f"cryptography [{type(privkey)}]"

        elif isinstance(privkey, bytes):
            # Read private key from bytes
            self._private_key = _load_private_key(privkey, password=self._password)
            self._source = self._source or "private key bytes"

        elif isinstance(privkey, (str, Path)):
            # Read private key from bytes of file
            privkey = check_file(privkey, must_exist=True, argname="privkey")
            self._private_key = _load_private_key(privkey.read_bytes(), password=self._password)
            self._source = self._source or f"private key file: {privkey}"

        elif isinstance(privkey, _CryptoType):
            # Create private key based on user defined config. It's an instance of a subclass of _CryptoType.
            self._private_key = privkey.create_private_key()

        elif isclass(privkey) and issubclass(privkey, _CryptoType):
            # Create private key based on user defined config. Instantiate the class with defaults.
            privkey_config_instance = privkey()  # We work with instances.
            self._private_key = privkey_config_instance.create_private_key()

        else:
            raise TypeError("Unsupported format for private key given: %s", type(privkey))

        # Init corresponding public key
        PublicKey.__init__(self, self.private_key.public_key())

    def change_password(self, passwd: PasswordInput = None):
        """
        Changes or sets a password which was used to open the private key.
        The new password is only effectively applied when the private key is being saved again to a file or to bytes.
        :param passwd: New password or None if no password wanted.
        """
        self._password = translate_optional_password(sanitize_password(passwd))

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

        file = check_file(file, must_exist=False, argname="file")
        file.write_bytes(self.private_key_to_bytes(encoding, fmt))
        file.chmod(0o600)

    @property
    def private_key(self) -> PrivateKeysSupportedTypes:
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
        return self._crypto_config.sign(self._private_key, data)

    def sign_prehashed(self, datahash: bytes) -> bytes:
        """
        Signs prehashed data by the PrivateKey
        :param datahash: Prehashed data to be signed
        :return: The signature of the prehashed data and PrivateKey
        """

        if not self._crypto_config.HASH_METHOD:
            raise NotImplementedError("We don't have access to the internal hash method. "
                                      "External prehashing not allowed or possible.")

        return self._crypto_config.sign_prehashed(self._private_key, datahash)

    def sign_file(self, file_to_sign: Union[str, Path]) -> bytes:
        """
        Signs a file by the PrivateKey
        :param file_to_sign: The file to be signed.
        :return: The signature of the file and PrivateKey
        """
        file_to_sign = check_file(file_to_sign, must_exist=True, argname="file_to_sign")

        if self._crypto_config.HASH_METHOD:
            file_hash = self.hash_file(file_to_sign)
            return self.sign_prehashed(file_hash)
        return self.sign_bytes(data=file_to_sign.read_bytes())

    def sign_file_to_file(self, file_to_sign: Union[str, Path], sign_save_to: Union[str, Path]):
        """
        Same as sign_file but writes the signature directly to a file.
        :param file_to_sign: The file to be signed.
        :param sign_save_to: The file to save the signature to.
        """
        sign_of_file = self.sign_file(file_to_sign)
        sign_save_to = check_file(sign_save_to, must_exist=False, argname="sign_save_to")
        sign_save_to.write_bytes(sign_of_file)
