# -*- coding: utf-8 -*-

import sqlite3
from pathlib import Path
from typing import Union, Optional, Iterable, Dict
from os import environ
from shutil import copyfile
from enum import Enum
from datetime import datetime, timezone
from logging import getLogger

from cryptography.x509 import NameOID, DirectoryName, random_serial_number, DNSName
from cryptography.x509.extensions import BasicConstraints, SubjectKeyIdentifier, AuthorityKeyIdentifier, \
    ExtendedKeyUsage, SubjectAlternativeName
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.hazmat.primitives import serialization

from crypto_helper import ECCrypto, PasswordInput, sanitize_password, translate_optional_password
from crypto_helper.certs import CommonName, CertBuilder, ExtensionBuilder, Cert, CertSigningRequest, CsrBuilder, \
    CrlBuilder, Crl, convert_timeinfo, RevokedCert, ReasonFlags, key_usage_builder


logger = getLogger(__name__)


class SignType(Enum):
    Client = 1
    Server = 2
    # CA = 3


class PKICrypto(ECCrypto):
    pass


default_ca_cn = CommonName("ca")
default_peer_cn = CommonName("peer")


def x509_sn(sn: int) -> str:
    """
    Create even number of upper case hex chars
    """
    sn_str = hex(sn)[2:].upper()
    if len(sn_str) % 2 == 1:
        sn_str = "0" + sn_str
    return sn_str


class PKI:
    _PKI_SUBFOLDERS = "private", "reqs"

    def __init__(self, path: Optional[Path] = None):
        self._path: Path = (path or Path(environ.get("PKI_DIR", "pki"))).expanduser().absolute()
        self.subfolder = {folder: (self._path / folder).absolute() for folder in self._PKI_SUBFOLDERS}

    @property
    def path(self) -> Path:
        return self._path

    def _add_extra_folders(self, f: Iterable[str]) -> Dict[str, Path]:
        extra_folders = {folder: (self._path / folder).absolute() for folder in f}
        self.subfolder.update(extra_folders)
        return extra_folders

    def init_pki(self, exist_ok: bool):
        # /usr/bin/easyrsa --pki-dir=testpki init-pki
        if self._path.exists() and not exist_ok:
            raise FileExistsError("PKI dir already existing")

        if self._path.exists():
            try:
                self._path.chmod(0o700)
            except PermissionError:
                logger.warning("Could not change file attributes to 0700: %s", self._path)
        else:
            # Create PKI root
            self._path.mkdir(mode=0o700, parents=True, exist_ok=False)

        # Create subfolders
        for subfolder in self.subfolder.values():
            subfolder.mkdir(mode=0o700, parents=True, exist_ok=False)

    def check_pki(self):
        for p in (self._path,) + tuple(self.subfolder.values()):
            if not p.is_dir():
                raise FileNotFoundError("Folder not found: " + str(p))


class CA(PKI):
    _CA_SUBFOLDERS = "certs_by_serial", "issued", "revoked/certs_by_serial", "revoked/reqs_by_serial"
    CA_VALIDITY_DAYS = 3650
    CA_FILENAME = "ca"

    def __init__(self,
                 path: Optional[Path] = None,
                 use_database_file=True,
                 ):

        PKI.__init__(self, path)

        self.ca_folder = self._add_extra_folders(self._CA_SUBFOLDERS)
        self._ca_cert: Optional[Cert] = None
        self._crt_builder: Optional[CertBuilder] = None
        self._crl_builder: Optional[CrlBuilder] = None

        self._use_database_file = use_database_file
        self._dbcon: Optional[sqlite3.Connection] = None

    def build_ca(self,
                 password: PasswordInput = None,
                 ca_dn: CommonName = default_ca_cn,
                 path_len: Optional[int] = None):
        # /usr/bin/easyrsa --pki-dir=testpki build-ca

        if self._ca_cert:
            raise RuntimeError("CA already created or just opened.")

        if self.private_key_file.exists():
            raise FileExistsError("CA private key file already existing.")

        if self.ca_cert_file.exists():
            raise FileExistsError("CA cert file already existing.")

        self.init_pki(exist_ok=True)

        if not password:
            print("WARNING: CA private key should be secured by a password for local storage safety.")
        passwd = translate_optional_password(sanitize_password(password))

        # Create new Certbuilder and keys
        crtb = CertBuilder(PKICrypto, passwd)

        # Save keys
        crtb.private_key_to_file(self.private_key_file)

        # Set extensions for CA self sign
        crtb.add_extension(BasicConstraints(ca=True, path_length=path_len), True)

        ca_digest = crtb.public_key_digest
        crtb.add_extension(SubjectKeyIdentifier(ca_digest), True)

        name_attribute_list = ca_dn.to_attribute_list()
        name = name_attribute_list.to_name()
        issuer = DirectoryName(name)

        sn = random_serial_number()
        crtb.add_extension(AuthorityKeyIdentifier(ca_digest, (issuer,), sn), True)

        crtb.add_extension(key_usage_builder(
            key_cert_sign=True,
            crl_sign=True,
        ), True)

        # Finally self sign own certificate
        selfcrt = \
            crtb.create_cert(issuer=name_attribute_list,
                             cert_or_csr_or_subject_pubkey=(name_attribute_list, crtb),
                             serial_number=sn,
                             not_valid_after=self.CA_VALIDITY_DAYS)

        selfcrt.to_file(self.ca_cert_file)

        # Open CA for regular use
        self.open_ca(password)

    def open_ca(self, password: PasswordInput = None):
        if self._ca_cert:
            raise RuntimeError("CA already open or just created.")

        # Open CA cert
        self._ca_cert = Cert(self.ca_cert_file)

        passwd = translate_optional_password(sanitize_password(password))

        # Raises ValueError on wrong password
        try:
            self._crt_builder = self._create_crt_builder(passwd)
        except ValueError:
            raise ValueError("Could not open CA. Wrong password?") from None

        # Create and prepare a CRL builder
        self._crl_builder = self._create_crl_builder(passwd)

        # Open DB if wanted
        if self._use_database_file:
            self._open_db()

    def _create_crl_builder(self, password: PasswordInput = None) -> CrlBuilder:
        if self._ca_cert is None:
            raise RuntimeError("You have to call 'open_ca' or 'build_ca' before.")

        crlbuilder = CrlBuilder(self.private_key_file, password)

        crlbuilder.add_extension(AuthorityKeyIdentifier(
            self._ca_cert.public_key_digest,
            (DirectoryName(self._ca_cert.issuer.to_name()),),
            self._ca_cert.serial_number), True
        )
        return crlbuilder

    def _create_crt_builder(self, password: PasswordInput = None) -> CertBuilder:
        if self._ca_cert is None:
            raise RuntimeError("You have to call 'open_ca' or 'build_ca' before.")

        crtb = CertBuilder(self.private_key_file, password)
        crtb.add_extension(BasicConstraints(ca=False, path_length=None), True)

        issuer = DirectoryName(self._ca_cert.subject.to_name())
        crtb.add_extension(
            AuthorityKeyIdentifier(
                self._ca_cert.public_key_digest,
                (issuer,),
                self._ca_cert.serial_number
            ), True)

        return crtb

    def name(self) -> Optional[str]:
        if self._ca_cert is None:
            return None

        return self._ca_cert.subject.to_name().rfc4514_string()

    @property
    def private_key_file(self) -> Path:
        return self.subfolder["private"] / (self.CA_FILENAME + ".key")

    @property
    def ca_crl_file(self) -> Path:
        return self._path / (self.CA_FILENAME + ".crl.pem")

    @property
    def ca_cert_file(self) -> Path:
        return self._path / (self.CA_FILENAME + ".crt")

    @property
    def database_file(self) -> Path:
        return self._path / (self.CA_FILENAME + ".db")

    def _open_db(self):
        self._dbcon = sqlite3.connect(self.database_file, isolation_level=None)
        self._dbcon.execute("CREATE TABLE IF NOT EXISTS "
                            "cert_index("
                            "id INTEGER PRIMARY KEY, "
                            "sn TEXT NOT NULL UNIQUE, "
                            "cn TEXT NOT NULL UNIQUE, "
                            "dn TEXT NOT NULL, "
                            "issue_date INTEGER NOT NULL, "
                            "start_date INTEGER NULL, "
                            "end_date INTEGER NULL, "
                            "revocation_date INTEGER NULL, "
                            "revocation_reason TEXT NULL) "
                            "STRICT;")

    @staticmethod
    def _iter_translated_query_result(result: sqlite3.Cursor):
        def _ts2utcdate(ts: Optional[int]) -> Optional[datetime]:
            if ts is None:
                return None

            return datetime.fromtimestamp(ts).astimezone(timezone.utc)

        for data in result:
            yield (
                data[0],  # id
                int(data[1]),  # sn
                data[2],  # cn
                data[3],  # dn
                _ts2utcdate(data[4]),  # issue_date
                _ts2utcdate(data[5]),  # start_date
                _ts2utcdate(data[6]),  # end_date
                _ts2utcdate(data[7]),  # revocation_date
                data[8] and ReasonFlags(data[8])
            )

    def query_db(self,
                 cid: Optional[str] = None,
                 sn: Optional[int] = None,
                 cn: Optional[str] = None,
                 valid_date: Optional[bool] = None,
                 revoked: Optional[bool] = None):

        if not self._dbcon:
            return

        data = {}
        where = []

        if cid is not None:
            data["id"] = cid
            where.append("id=:id")

        if sn is not None:
            data["sn"] = str(sn)
            where.append("sn=:sn")

        if cn is not None:
            data["cn"] = cn
            where.append("cn=:cn")

        if valid_date is not None:
            data["now"] = int(datetime.now(timezone.utc).timestamp())

            if valid_date:
                where.append("start_date>:now AND stop_date<:now")
            else:
                where.append("(start_date<:now OR stop_date>:now)")

        if revoked is not None:
            if revoked:
                where.append("revocation_date IS NOT NULL")
            else:
                where.append("revocation_date IS NULL")

        if where:
            cur = self._dbcon.execute(f"SELECT * FROM cert_index WHERE {' AND '.join(where)};", data)
        else:
            cur = self._dbcon.execute("SELECT * FROM cert_index;")

        yield from self._iter_translated_query_result(cur)

    def import_req(self, csr_file: Path):
        # /usr/bin/easyrsa --pki-dir=testpki import-req clientpkitest/reqs/client1.req client1
        csr = CertSigningRequest(csr_file)
        cname = csr.subject.to_name().rfc4514_string()

        dest_file = self.subfolder["reqs"] / (cname + ".req")
        if dest_file.exists():
            raise FileExistsError("File already existing based on CNAME: " + str(dest_file))

        copyfile(csr_file, dest_file)

    def sign_req(self,
                 cname: str,
                 signtype: SignType,
                 validity_start: Union[datetime, int] = -1,
                 validity_end: Union[datetime, int] = 3650) -> Cert:
        # /usr/bin/easyrsa --pki-dir=testpki sign-req client client1
        # resources$ openssl ca -in testpki/reqs/client1.req -days 10 -keyfile testpki/private/ca.key
        #            -cert testpki/ca.crt -outdir testpki/newcerts -config testpki/safessl-easyrsa.cnf -notext
        if self._ca_cert is None:
            raise RuntimeError("CA cert missing.")

        if self._crt_builder is None:
            raise RuntimeError("You have to call 'open_ca' or 'build_ca' before.")

        req_in_file = self.subfolder["reqs"] / (cname + ".req")
        crt_out_file = self.subfolder["issued"] / (cname + ".crt")

        if not req_in_file.exists():
            raise FileNotFoundError("req file not found: " + str(req_in_file))

        if crt_out_file.exists():
            raise FileExistsError("crt file already existing: " + str(crt_out_file))

        req_csr = CertSigningRequest(req_in_file)

        # Set extensions for cert
        indiv_exts = ExtensionBuilder()

        # Subject identifyer
        indiv_exts.add_extension(SubjectKeyIdentifier(req_csr.public_key_digest), True)

        if signtype is SignType.Client:
            indiv_exts.add_extension(ExtendedKeyUsage((ExtendedKeyUsageOID.CLIENT_AUTH,)), True)
            indiv_exts.add_extension(
                key_usage_builder(
                    digital_signature=True
                ), True
            )

        elif signtype is SignType.Server:
            indiv_exts.add_extension(ExtendedKeyUsage((ExtendedKeyUsageOID.SERVER_AUTH,)), True)
            indiv_exts.add_extension(
                key_usage_builder(
                    digital_signature=True,
                    key_encipherment=True
                ), True
            )

            subject_cname = req_csr.subject.get_oid(NameOID.COMMON_NAME)
            if not subject_cname:
                raise RuntimeError("Server req/csr has no CN")

            subject_dns = DNSName(subject_cname.value)
            indiv_exts.add_extension(SubjectAlternativeName((subject_dns,)), True)
        else:
            raise RuntimeError("Unsupported signtype: " + repr(signtype))

        new_sn = random_serial_number()

        start = convert_timeinfo(validity_start)
        if start is None:
            raise ValueError("validity_start is required.")
        end = convert_timeinfo(validity_end)
        if end is None:
            raise ValueError("validity_end is required.")

        if self._dbcon:
            with self._dbcon:
                data = (
                    str(new_sn),
                    cname,
                    req_csr.subject.rfc4514_string(),
                    int(datetime.now(timezone.utc).timestamp()),
                    validity_start and int(start.timestamp()),
                    validity_end and int(end.timestamp())
                )

                self._dbcon.execute("INSERT INTO cert_index (sn, cn, dn, issue_date, start_date, end_date)"
                                    " VALUES (?, ?, ?, ?, ?, ?)", data)

        new_crt = self._crt_builder.create_cert(issuer=self._ca_cert.subject,
                                                cert_or_csr_or_subject_pubkey=req_csr,
                                                serial_number=new_sn,
                                                not_valid_before=validity_start,
                                                not_valid_after=validity_end,
                                                individual_extensions=indiv_exts.extensions)

        new_crt.to_file(crt_out_file, encoding=serialization.Encoding.PEM)
        # openssl x509 -in client1.crt -text
        crt_by_serial_file = self.subfolder["certs_by_serial"] / (x509_sn(new_sn) + ".crt")
        copyfile(crt_out_file, crt_by_serial_file)

        return new_crt

    def check_pki(self):
        # Check base class folders
        PKI.check_pki(self)

        # Check own folders
        for p in self.ca_folder.values():
            if not p.is_dir():
                raise FileNotFoundError("Folder not found: " + str(p))

    def get_cert_by(self, cn_or_sn: Union[str, int]) -> Optional[Cert]:
        if isinstance(cn_or_sn, int):
            # Find by serial number (int)
            sn_hex = x509_sn(cn_or_sn)
            cert_file: Path = self.subfolder["certs_by_serial"] / (sn_hex + ".crt")

        elif isinstance(cn_or_sn, str):
            # Find by CNAME
            cert_file: Path = self.subfolder["issued"] / (cn_or_sn + ".crt")
        else:
            raise TypeError("cn_or_sn expected to be int for a serial number or str für a CNAME.")

        if not cert_file.is_file():
            return None

        cert = Cert(cert_file)
        return cert

    def revoke(self, cert: Cert, reason: ReasonFlags, delete=True):
        if self._crt_builder is None:
            raise RuntimeError("You have to call 'open_ca' or 'build_ca' before.")

        # Get CN and CN based cert file
        cn_oid = cert.subject.get_oid(NameOID.COMMON_NAME)
        if cn_oid is None:
            raise RuntimeError("Cert's subject has no CommonName: " + str(cert))
        cn = cn_oid.value

        issued_file = self.subfolder["issued"] / (cn + ".crt")
        if not issued_file.is_file():
            raise FileNotFoundError(f"Could not find a matching cert for CommonName '{cn}' ({issued_file}).")

        # Get SN and SN based cert file
        sn = cert.serial_number
        sn_hex = x509_sn(sn)
        by_serial_file = self.subfolder["certs_by_serial"] / (sn_hex + ".crt")
        if not by_serial_file.is_file():
            raise FileNotFoundError(f"Could not find cert file by serial number {sn}/{sn_hex}: ({by_serial_file}).")

        # Get REQ file
        req_file = self.subfolder["reqs"] / (cn + ".req")
        if not req_file.is_file():
            raise FileNotFoundError(f"Could not find a matching signing request file: {req_file}")

        if self._dbcon:
            # Check DB
            data = (
                str(sn),
                cn
            )
            cur = self._dbcon.execute("SELECT id FROM cert_index WHERE sn=? AND cn=?", data)
            res = cur.fetchone()
            if res is None:
                raise RuntimeError("Could not find serial number and common name in database.")
            rev_id = res[0]

            data = (
                int(datetime.now(timezone.utc).timestamp()),
                reason.value,
                rev_id
            )
            cursor = self._dbcon.execute(
                "UPDATE cert_index SET revocation_date=?, "
                "revocation_reason=? "
                "WHERE id=?",
                data
            )
            if cursor.rowcount != 1:
                raise ValueError("Updates rows in DB expected to be 1 but was: " + str(cursor.rowcount))

        # Copy/Move certs_by_serial/SN.crt to revoked/certs_by_serial/SN.crt
        copyfile(by_serial_file, self.subfolder["revoked/certs_by_serial"] / by_serial_file.name)

        # Copy/Move reqs/CN.req to revoked/reqs_by_serial/SN.req
        copyfile(req_file, self.subfolder["revoked/reqs_by_serial"] / (sn_hex + ".req"))

        if delete:
            by_serial_file.unlink()
            req_file.unlink()
            issued_file.unlink()

    def gen_crl(self, next_update: Union[datetime, int] = 31, with_outdated_certs=False) -> Crl:
        if self._crl_builder is None or self._ca_cert is None:
            raise RuntimeError("You have to call 'open_ca' or 'build_ca' before.")

        self._crl_builder.clear()  # Clear crl list

        for rc in self.query_db(valid_date=None if with_outdated_certs else True, revoked=True):
            self._crl_builder.add_revocation(RevokedCert(rc[1], rc[7], rc[8]))

        crl = self._crl_builder.build_crl(issuer=self._ca_cert.subject, next_update=next_update)
        crl.crl_to_file(self.ca_crl_file)
        return crl

    def __del__(self):
        if self._dbcon:
            self._dbcon.close()


class Peer(PKI):
    _PEER_SUBFOLDERS = "certs",

    def __init__(self, path: Optional[Path] = None):
        PKI.__init__(self, path)
        self.peer_folder = self._add_extra_folders(self._PEER_SUBFOLDERS)

    def gen_req(self, password: PasswordInput = None, endpoint_dn: CommonName = default_peer_cn) -> Path:
        """Create and save key pair and Csr"""
        # /usr/bin/easyrsa --pki-dir=testpki gen-req client1
        if not self._path.exists():
            self.init_pki(exist_ok=False)

        passwd = translate_optional_password(sanitize_password(password))

        cn = endpoint_dn.common_name

        private_key_file = self.subfolder["private"] / (cn + ".key")
        req_file = self.subfolder["reqs"] / (cn + ".req")

        for f in private_key_file, req_file:
            if f.exists():
                raise FileExistsError(f"File is already existing: {f}")

        # Create new private key
        builder = CsrBuilder(PKICrypto, passwd)
        builder.private_key_to_file(private_key_file)

        # Sign Csr/req
        csr = builder.build_csr(subject=endpoint_dn.to_attribute_list())
        csr.to_file(req_file)
        return req_file
