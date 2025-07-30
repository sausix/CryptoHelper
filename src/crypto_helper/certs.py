# -*- coding: utf-8 -*-

"""
CryptoHelper - Certificate/x.509 related stuff
"""

from typing import Union, Optional, Type, Iterable
from dataclasses import dataclass
from pathlib import Path
from contextlib import suppress
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import serialization

from cryptography.x509 import NameAttribute, CertificateBuilder, Name as x509Name, random_serial_number, Certificate, \
    load_pem_x509_certificate, CertificateSigningRequest, load_pem_x509_csr, Version, NameOID, ObjectIdentifier, \
    CertificateSigningRequestBuilder, CertificateRevocationList, CertificateRevocationListBuilder, load_pem_x509_crl, \
    RevokedCertificate, RevokedCertificateBuilder, load_der_x509_crl, load_der_x509_csr, load_der_x509_certificate

from cryptography.x509.extensions import ExtensionType, Extension, CRLReason, ReasonFlags, KeyUsage

from crypto_helper import check_file, PublicKey, PrivateKey, PasswordInput, CryptoDefinition, \
    PrivateKeysSupportedTypes, PublicKeysSupported


_DAY = timedelta(days=1)
_EARLIEST_UTC_TIME = datetime(1950, 1, 1, tzinfo=timezone.utc)


class _Random:
    pass


RANDOM = _Random()


class DuplicateCertException(Exception):
    pass


def convert_timeinfo(d: Union[datetime, int, None]) -> Optional[datetime]:
    if d is None:
        return None
    if isinstance(d, int):
        data = datetime.now(timezone.utc) + (_DAY * d)
    elif isinstance(d, datetime):
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


class NameAttributeList:
    @classmethod
    def from_name(cls, name: x509Name, frozen=True) -> "NameAttributeList":
        new_list = NameAttributeList()

        if not isinstance(new_list.attribute_list, list):
            raise RuntimeError("New attribute list is not a list.")
        new_list.attribute_list.extend(iter(name))

        if frozen:
            new_list._freeze()
        return new_list

    def __init__(self,
                 country: Optional[str] = None,
                 state_or_province: Optional[str] = None,
                 locality: Optional[str] = None,
                 street: Optional[str] = None,
                 common_name: Optional[str] = None,
                 email: Optional[str] = None,
                 organization: Optional[str] = None,
                 organization_unit: Optional[str] = None,
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

        self.attribute_list: Union[list[NameAttribute], tuple[NameAttribute, ...]] = []

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
            if isinstance(data, str):
                self.attribute_list.append(NameAttribute(oid, data.strip()))

    def get_oid(self, oid: ObjectIdentifier, default=None) -> Optional[NameAttribute]:
        for o in self.attribute_list:
            if o.oid == oid:
                return o
        return default

    def _freeze(self):
        if isinstance(self.attribute_list, tuple):
            raise ValueError("NameAttributeList is already frozen.")

        if isinstance(self.attribute_list, list):
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
    country_name: Optional[str] = None  # 2 letters
    state_or_province_name: Optional[str] = None
    locality_name: Optional[str] = None
    street_name: Optional[str] = None
    organization_name: Optional[str] = None
    organization_unit_name: Optional[str] = None
    email_address: Optional[str] = None  # Max 64 letters

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
        self._attributes: list[tuple[ObjectIdentifier, bytes, Optional[int]]] = []  # TODO: dict

    def add_attribute(self, oid: ObjectIdentifier, value: bytes):
        if not isinstance(oid, ObjectIdentifier):
            raise TypeError("oid of attribute must be an ObjectIdentifier.")
        if oid in (attr[0] for attr in self._attributes):
            raise ValueError("This attribute has already been set.")
        self._attributes.append((oid, value, None))


class ExtensionsBase:
    def __init__(self, frozen_extensions: Optional[Iterable[Extension]] = ()):
        self._extensions: Union[list[Extension], tuple[Extension, ...]] = \
            tuple(frozen_extensions) if frozen_extensions else []  # TODO: dict[oid, Extension]?

    def add_extension(self, extension: ExtensionType, critical: bool):
        if isinstance(self._extensions, tuple):
            raise ValueError("Extensions of this object are read only.")

        if not isinstance(extension, ExtensionType):
            raise TypeError("extension must be an ExtensionType")

        if self.get_extension(extension.oid) is not None:
            raise ValueError("This extension has already been set.")

        ext = Extension(extension.oid, critical, extension)
        self._extensions.append(ext)

    def get_extension(self, ext: Union[Type[ExtensionType], ObjectIdentifier]) -> Optional[Extension]:
        if isinstance(ext, ObjectIdentifier):
            oid = ext
        elif isinstance(ext, ExtensionType):
            oid = ext.oid
        else:
            raise TypeError("Unsupported argument: %r" % ext)

        for e in self._extensions:
            # if isinstance(e.value, ext):
            if e.oid == oid:
                return e

        return None

    def clear_extenstions(self):
        if isinstance(self._extensions, tuple):
            raise TypeError("Cannot clear frozen extensions.")
        self._extensions.clear()


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
            cert = check_file(cert, must_exist=True, argname="cert")
            self._cert = _load_x509_certificate(cert.read_bytes())

        else:
            raise TypeError("Unsupported format for certificate given: " + str(type(cert)))

        pkey = self._cert.public_key()
        if not isinstance(pkey, PublicKeysSupported):
            raise TypeError("The crypto type used in this certificate is not supported.")

        PublicKey.__init__(self, pkey)

        hash_algo = self._cert.signature_hash_algorithm
        if hash_algo is not None:
            self._crypto_config.apply_hash(hash_algo)

        ExtensionsBase.__init__(self, self._cert.extensions)

        self._issuer = NameAttributeList.from_name(self._cert.issuer)
        self._subject = NameAttributeList.from_name(self._cert.subject)

    @property
    def cert(self) -> Certificate:
        return self._cert

    @property
    def extensions(self) -> tuple[Extension, ...]:
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
        file = check_file(file, must_exist=False, argname="file")
        file.write_bytes(self.to_bytes(encoding=encoding))

    def __repr__(self):
        return f"<{self.__class__.__name__}({self._crypto_config!r}) sn='{self._cert.serial_number}' " \
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
            csr = check_file(csr, must_exist=True, argname="csr")
            self._csr = _load_x509_csr(csr.read_bytes())

        else:
            raise TypeError("Unsupported type for csr given: " + str(type(csr)))

        pkey = self._csr.public_key()
        if not isinstance(pkey, PublicKeysSupported):
            raise TypeError("The crypto type used in this CSR is not supported.")

        PublicKey.__init__(self, pkey)

        hash_algo = self._csr.signature_hash_algorithm
        if hash_algo is not None:
            self._crypto_config.apply_hash(hash_algo)

        ExtensionsBase.__init__(self, self._csr.extensions)

        self._subject = NameAttributeList.from_name(self._csr.subject)

    @property
    def csr(self) -> CertificateSigningRequest:
        return self._csr

    @property
    def subject(self) -> NameAttributeList:
        return self._subject

    @property
    def extensions(self) -> tuple[Extension, ...]:
        return tuple(self._extensions)

    @property
    def signature(self) -> bytes:
        return self._csr.signature

    def signature_valid(self) -> bool:
        return self._csr.is_signature_valid

    def to_bytes(self) -> bytes:
        return self._csr.public_bytes(encoding=serialization.Encoding.PEM)

    def to_file(self, file: Union[str, Path]):
        file = check_file(file, must_exist=False, argname="file")
        file.write_bytes(self.to_bytes())

    def __repr__(self):
        return f"<{self.__class__.__name__}({self._crypto_config!r}) subject='{self._subject!s}'"


class CertBuilder(PrivateKey, ExtensionsBase):
    def __init__(self,
                 privkey: Union[str, Path, bytes, PrivateKeysSupportedTypes, PrivateKey, CryptoDefinition],
                 passwd: PasswordInput = None):
        PrivateKey.__init__(self, privkey=privkey, passwd=passwd)
        ExtensionsBase.__init__(self)

    @property
    def extensions(self) -> list[Extension]:
        return list(self._extensions)

    def create_cert(self,
                    issuer: NameAttributeList,
                    cert_or_csr_or_subject_pubkey: Union[Cert, CertSigningRequest, tuple[NameAttributeList, PublicKey]],
                    serial_number: Optional[Union[int, _Random]] = RANDOM,
                    not_valid_before: Union[datetime, int, None] = -1,
                    not_valid_after: Union[datetime, int, None] = 365,
                    individual_extensions: Optional[Iterable[Extension]] = None
                    ) -> Cert:

        if isinstance(cert_or_csr_or_subject_pubkey, (Cert, CertSigningRequest)):
            subject_name = cert_or_csr_or_subject_pubkey.subject.to_name()
            subject_pubkey = cert_or_csr_or_subject_pubkey.public_key

        elif isinstance(cert_or_csr_or_subject_pubkey, tuple) \
                and len(cert_or_csr_or_subject_pubkey) == 2 \
                and isinstance(cert_or_csr_or_subject_pubkey[0], NameAttributeList) \
                and isinstance(cert_or_csr_or_subject_pubkey[1], PublicKey):
            subject_name = cert_or_csr_or_subject_pubkey[0].to_name()
            subject_pubkey = cert_or_csr_or_subject_pubkey[1].public_key

        else:
            raise TypeError("cert_or_csr_or_subject_pubkey must be: Cert or CertSigningRequest or "
                            "tuple[NameAttributeList, PublicKey]")

        # Merge extensions
        exts_merged = list(self._extensions)
        if individual_extensions is not None:
            exts_merged.extend(individual_extensions)

        for i, iext in enumerate(exts_merged):
            if not isinstance(iext, Extension):
                raise TypeError("Extension must be type of Extension")

            for jext in exts_merged[:i]:
                if iext.oid == jext.oid:
                    raise ValueError("Extension " + repr(iext.oid) + " has already been set before.")

        # Serial number
        if serial_number is RANDOM:
            sn = random_serial_number()
        elif serial_number is None or isinstance(serial_number, int):
            sn = serial_number
        else:
            raise ValueError("serial_number must be _RANDOM (default), None or an integer.")

        # Valid date bounds
        _not_valid_before = convert_timeinfo(not_valid_before)
        _not_valid_after = convert_timeinfo(not_valid_after)

        if (_not_valid_before is not None and _not_valid_after is not None
                and _not_valid_before > _not_valid_after):
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

        cert = builder.sign(private_key=self.private_key, algorithm=self._crypto_config.HASH_METHOD)
        return Cert(cert)


class CsrBuilder(PrivateKey, ExtensionsBase, AttributesBase):
    def __init__(self,
                 privkey: Union[str, Path, bytes, PrivateKeysSupportedTypes, PrivateKey, CryptoDefinition],
                 passwd: PasswordInput = None):
        PrivateKey.__init__(self, privkey=privkey, passwd=passwd)
        ExtensionsBase.__init__(self)
        AttributesBase.__init__(self)

    @property
    def extensions(self) -> list[Extension]:
        return list(self._extensions)

    def build_csr(self,
                  subject: NameAttributeList,
                  individual_extensions: Iterable[Extension] = ()) -> CertSigningRequest:

        csr_ext = list(self._extensions)
        if individual_extensions:
            for iext in individual_extensions:
                if not isinstance(iext, Extension):
                    raise TypeError("extension must be type of Extension")

                if iext.oid in (e.oid for e in csr_ext):
                    raise ValueError("This extension has already been set.")

                csr_ext.append(iext)

        # Create the internal builder
        builder = CertificateSigningRequestBuilder(
            subject_name=subject.to_name(),
            extensions=csr_ext,
            attributes=self._attributes
        )
        csr = builder.sign(private_key=self.private_key, algorithm=self._crypto_config.HASH_METHOD)

        return CertSigningRequest(csr)


class RevokedCert(ExtensionsBase):
    def __init__(self,
                 serial_number: int,
                 revocation_date: Union[datetime, int, None] = 0,
                 extensions_or_reason: Union[ReasonFlags, Iterable[Extension]] = ()):

        self._sn = serial_number
        self._revdate = convert_timeinfo(revocation_date)

        if isinstance(extensions_or_reason, ReasonFlags):
            exts = self._reason_to_extensions(extensions_or_reason)
        else:
            # Iterable of Extension
            exts = tuple(extensions_or_reason)

        ExtensionsBase.__init__(self, frozen_extensions=exts)

    @staticmethod
    def _reason_to_extensions(reason: ReasonFlags) -> tuple[Extension, ...]:
        ebuilder = ExtensionBuilder()
        ebuilder.add_extension(CRLReason(reason), True)
        return tuple(ebuilder.extensions)

    @classmethod
    def from_certificate(cls, cert: Union[Cert, Certificate],
                         revocation_date: Union[datetime, int] = 0,
                         extensions_or_reason: Union[ReasonFlags, Iterable[Extension]] = ()) -> "RevokedCert":
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
    def revocation_date(self) -> Optional[datetime]:
        return self._revdate

    @property
    def extensions(self) -> tuple[Extension, ...]:
        return tuple(self._extensions)

    @property
    def crl_reason(self) -> Optional[ReasonFlags]:
        reasons_ext = self.get_extension(CRLReason)

        if isinstance(reasons_ext, CRLReason):
            return reasons_ext.reason
        return None

    def __repr__(self):
        return f"<{self.__class__.__name__} sn='{self._sn}' revocation_date={self._revdate} reason={self.crl_reason}>"


class Crl(ExtensionsBase):
    def __init__(self, crl: Union[str, Path, bytes, CertificateRevocationList]):
        if isinstance(crl, CertificateRevocationList):
            self._crl = crl

        elif isinstance(crl, bytes):
            self._crl = _load_x509_crl(crl)

        elif isinstance(crl, (str, Path)):
            crl = check_file(crl, must_exist=True, argname="crl")
            self._crl = _load_x509_crl(crl.read_bytes())

        else:
            raise TypeError("Unsupported format for CRL given: " + str(type(crl)))

        ExtensionsBase.__init__(self, self._crl.extensions)

        # TODO: convert crl items directly?

        self._issuer = NameAttributeList.from_name(self._crl.issuer)

    @property
    def issuer(self) -> NameAttributeList:
        return self._issuer

    @property
    def next_update(self) -> Optional[datetime]:
        return self._crl.next_update_utc

    @property
    def last_update(self) -> datetime:
        return self._crl.last_update_utc

    @property
    def extensions(self) -> tuple[Extension, ...]:
        return tuple(self._extensions)

    @property
    def is_valid_by_date(self) -> bool:
        now = datetime.now(timezone.utc)

        if now < self._crl.last_update_utc:
            return False

        if self._crl.next_update_utc is None:
            return True

        return now < self._crl.next_update_utc

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
        file = check_file(file, must_exist=False, argname="file")
        file.write_bytes(self.crl_to_bytes(encoding=encoding))

    def __repr__(self):
        return f"<{self.__class__.__name__} " \
               f"issuer='{self._issuer!s}' revokes_count={len(self._crl)}, " \
               f"last_update={self._crl.last_update_utc}, next_update={self._crl.next_update_utc}>"


class CrlBuilder(PrivateKey, ExtensionsBase):
    def __init__(self,
                 privkey: Union[str, Path, bytes, PrivateKeysSupportedTypes, PrivateKey, CryptoDefinition],
                 passwd: PasswordInput = None,
                 extensions: Iterable[Extension] = ()):
        PrivateKey.__init__(self, privkey=privkey, passwd=passwd)
        ExtensionsBase.__init__(self, frozen_extensions=extensions)

        self._revoked_list: list[RevokedCert] = []

    def _add(self, rcert: RevokedCert):
        """Checks for not a duplicate (by serial number) and then adds to the current list"""

        if rcert.serial_number in self:
            raise DuplicateCertException("Serial number is already in crl.")

        self._revoked_list.append(rcert)

    def __contains__(self, item: Union[int, RevokedCert, RevokedCertificate]):
        if isinstance(item, int):
            sn = item
        elif isinstance(item, RevokedCert):
            sn = item.serial_number
        elif isinstance(item, RevokedCertificate):
            sn = item.serial_number
        else:
            return False

        for rc in self._revoked_list:
            if rc.serial_number == sn:
                return True

        return False

    def add_revocation(self, rcert: Union[RevokedCert, RevokedCertificate]):
        """
        Adds a revocation to the current CR list
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
                  next_update: Union[datetime, int, None] = 31
                  ) -> Crl:

        last_ = convert_timeinfo(last_update)
        if last_ is None:
            raise ValueError("last_update is required.")

        next_ = convert_timeinfo(next_update)

        if next_ is not None and next_ < last_:
            raise RuntimeError("next_update must be later than last_update.")

        rcerts = [self._build_revocation(rc) for rc in self._revoked_list]

        builder = CertificateRevocationListBuilder(
            issuer_name=issuer.to_name(),
            last_update=last_,
            next_update=next_,
            extensions=list(self._extensions),
            revoked_certificates=rcerts
        )

        crl = builder.sign(private_key=self._private_key, algorithm=self._crypto_config.HASH_METHOD)
        return Crl(crl)


class ExtensionBuilder(ExtensionsBase):
    """Tool for building x509 extensions.
    Wraps some common extensions as methods."""

    def __init__(self):
        ExtensionsBase.__init__(self)

    @property
    def extensions(self) -> list[Extension]:
        return list(self._extensions)


def _load_x509_crl(crl: bytes) -> CertificateRevocationList:
    with suppress(ValueError):
        return load_pem_x509_crl(crl)

    return load_der_x509_crl(crl)


def _load_x509_csr(csr: bytes) -> CertificateSigningRequest:
    with suppress(ValueError):
        return load_pem_x509_csr(csr)

    return load_der_x509_csr(csr)


def _load_x509_certificate(cert: bytes) -> Certificate:
    with suppress(ValueError):
        return load_pem_x509_certificate(cert)

    return load_der_x509_certificate(cert)


def key_usage_builder(
    digital_signature: bool = False,
    content_commitment: bool = False,
    key_encipherment: bool = False,
    data_encipherment: bool = False,
    key_agreement: bool = False,
    key_cert_sign: bool = False,
    crl_sign: bool = False,
    encipher_only: bool = False,
    decipher_only: bool = False
) -> KeyUsage:
    return KeyUsage(
            digital_signature=digital_signature,
            content_commitment=content_commitment,
            key_encipherment=key_encipherment,
            data_encipherment=data_encipherment,
            key_agreement=key_agreement,
            key_cert_sign=key_cert_sign,
            crl_sign=crl_sign,
            encipher_only=encipher_only,
            decipher_only=decipher_only,
    )
