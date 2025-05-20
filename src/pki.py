# -*- coding: utf-8 -*-

from pathlib import Path
from typing import Union, Optional, Iterable, Dict
from os import environ
from shutil import copyfile
from enum import Enum
from datetime import datetime, timezone
import sqlite3

from cryptography.x509 import NameOID, DirectoryName, random_serial_number, DNSName
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.hazmat.primitives import serialization

from CryptoHelper import CommonName, CertBuilder, ExtensionBuilder, Cert, CertSigningRequest, CsrBuilder, ECCrypto, \
    CrlBuilder, Crl, convert_timeinfo, RevokedCert, CRLReasonFlags

# TODO: file permissions


class SignType(Enum):
    Client = 1
    Server = 2
    # CA = 3


class PKICrypto(ECCrypto):
    KEY_SIZE = 1024


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

    def __init__(self, path: Path = None):
        self._path: Path = (path or environ.get("PKI-DIR") or Path("./pki")).absolute()
        self.subfolder = {folder: (self._path / folder).absolute() for folder in self._PKI_SUBFOLDERS}

    def _add_extra_folders(self, f: Iterable[str]) -> Dict[str, Path]:
        extra_folders = {folder: (self._path / folder).absolute() for folder in f}
        self.subfolder.update(extra_folders)
        return extra_folders

    def init_pki(self):
        # /usr/bin/easyrsa --pki-dir=testpki init-pki
        if self._path.exists():
            raise FileExistsError("PKI dir already existing")

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

    def __init__(self,
                 path: Path = None,
                 database_file: Path = None,
                 ):

        PKI.__init__(self, path or Path("./ca").absolute())

        self.ca_folder = self._add_extra_folders(self._CA_SUBFOLDERS)
        self._ca_name: Optional[str] = None
        self._ca_cert: Optional[Cert] = None
        self._crt_builder: Optional[CertBuilder] = None
        self._crl_builder: Optional[CrlBuilder] = None

        self._database_file = database_file
        self._dbcon: Optional[sqlite3.Connection] = None

    @property
    def private_key_file(self) -> Path:
        if self._ca_name is None:
            raise RuntimeError("This property is unavailable until 'open_ca' or 'build_ca' is called before.")
        return self.subfolder["private"] / (self._ca_name + ".key")

    @property
    def ca_crl_file(self) -> Path:
        if self._ca_name is None:
            raise RuntimeError("This property is unavailable until 'open_ca' or 'build_ca' is called before.")
        return self._path / (self._ca_name + ".crl.pem")

    @property
    def ca_cert_file(self) -> Path:
        if self._ca_name is None:
            raise RuntimeError("This property is unavailable until 'open_ca' or 'build_ca' is called before.")
        return self._path / (self._ca_name + ".crt")

    def build_ca(self,
                 password: Union[str, bytes, bytearray, None],
                 ca_dn: CommonName = default_ca_cn,
                 path_len: int = None):
        # /usr/bin/easyrsa --pki-dir=testpki build-ca

        if self._ca_name or self._ca_cert:
            raise RuntimeError("CA already created or just opened.")

        self._ca_name = ca_dn.common_name

        if self.private_key_file.exists():
            raise FileExistsError("CA private key file already existing.")

        if self.ca_cert_file.exists():
            raise FileExistsError("CA cert file already existing.")

        self.init_pki()

        if not password:
            print("WARNING: CA private key should be secured by a password for local storage.")

        if self._database_file:
            self._open_db()

        self._crt_builder = CertBuilder(PKICrypto, password)
        self._crt_builder.private_key_to_file(self.private_key_file)

        # Set extensions for cert
        exts = ExtensionBuilder()

        exts.BasicConstraints(False, ca=True, path_length=path_len)

        ca_digest = self._crt_builder.public_key_digest
        exts.SubjectKeyIdentifier(False, ca_digest)

        name_attribute_list = ca_dn.to_attribute_list()
        name = name_attribute_list.to_name()
        issuer = DirectoryName(name)

        sn = random_serial_number()
        exts.AuthorityKeyIdentifier(False, ca_digest, issuer, sn)

        exts.KeyUsage(False,
                      key_cert_sign=True,
                      crl_sign=True)

        # Create certificate
        self._ca_cert = \
            self._crt_builder.create_cert(issuer=name_attribute_list,
                                          cert_or_csr_or_subject_pubkey=(name_attribute_list, self._crt_builder),
                                          serial_number=sn,
                                          not_valid_after=self.CA_VALIDITY_DAYS,
                                          individual_extensions=exts.extensions)

        self._ca_cert.to_file(self.ca_cert_file)

        # Create and prepare a CRL builder
        self._crl_builder = self._create_crl_builder(password)

    def _open_db(self):
        self._dbcon = sqlite3.connect(self._database_file, isolation_level=None)
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
                            "revocation_reason INTEGER NULL) "
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
                data[8] and CRLReasonFlags(data[8])
            )

    def query_db(self,
                 cid: str = None,
                 sn: int = None,
                 cn: str = None,
                 valid_date: bool = None,
                 revoked: bool = None):

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
            cur = self._dbcon.execute(f"SELECT * FROM cert_index;")

        yield from self._iter_translated_query_result(cur)

    def open_ca(self, password: Union[str, bytes, bytearray] = None, ca_cname: Union[str, CommonName] = "ca"):
        if self._ca_name or self._ca_cert:
            raise RuntimeError("CA already open or just created.")

        if isinstance(ca_cname, CommonName):
            self._ca_name = ca_cname.common_name
        elif isinstance(ca_cname, str):
            self._ca_name = ca_cname
        else:
            raise TypeError("ca_name has invalid type.")

        self._ca_cert = Cert(self.ca_cert_file)
        self._crt_builder = CertBuilder(self.private_key_file, password)

        if self._database_file:
            self._open_db()

        # Create and prepare a CRL builder
        self._crl_builder = self._create_crl_builder(password)

    def import_req(self, import_file: Path, local_cname: str):
        # /usr/bin/easyrsa --pki-dir=testpki import-req clientpkitest/reqs/client1.req client1
        dest_file = self.subfolder["reqs"] / (local_cname + ".req")
        if dest_file.exists():
            raise FileExistsError("File is already existing: " + str(dest_file))

        copyfile(import_file, dest_file)

    def sign_req(self,
                 local_cname: str,
                 signtype: SignType,
                 validity_start: Union[datetime, int] = -1,
                 validity_end: Union[datetime, int] = 3650) -> Cert:
        # /usr/bin/easyrsa --pki-dir=testpki sign-req client client1
        # resources$ openssl ca -in testpki/reqs/client1.req -days 10 -keyfile testpki/private/ca.key
        #            -cert testpki/ca.crt -outdir testpki/newcerts -config testpki/safessl-easyrsa.cnf -notext
        if self._crt_builder is None:
            raise RuntimeError("You have to call 'open_ca' or 'build_ca' before.")

        req_in_file = self.subfolder["reqs"] / (local_cname + ".req")
        crt_out_file = self.subfolder["issued"] / (local_cname + ".crt")

        if not req_in_file.exists():
            raise FileNotFoundError("REQ file not found: " + str(req_in_file))

        if crt_out_file.exists():
            raise FileExistsError("CRT file already existing: " + str(crt_out_file))

        req_csr = CertSigningRequest(req_in_file)

        # Set extensions for cert
        exts = ExtensionBuilder()

        exts.BasicConstraints(False, ca=False, path_length=None)
        exts.SubjectKeyIdentifier(False, req_csr.public_key_digest)

        issuer = DirectoryName(self._ca_cert.subject.to_name())
        exts.AuthorityKeyIdentifier(False, self._ca_cert.public_key_digest, issuer, self._ca_cert.serial_number)

        if signtype is SignType.Client:
            exts.ExtendedKeyUsage(False, (ExtendedKeyUsageOID.CLIENT_AUTH,))
            exts.KeyUsage(False,
                          digital_signature=True)

        elif signtype is SignType.Server:
            exts.ExtendedKeyUsage(False, (ExtendedKeyUsageOID.SERVER_AUTH,))
            exts.KeyUsage(False,
                          digital_signature=True,
                          key_encipherment=True)

            subject_cname = req_csr.subject.get_oid(NameOID.COMMON_NAME)
            if not subject_cname:
                raise RuntimeError("Server req/csr has no CN")

            subject_dns = DNSName(subject_cname.value)
            exts.SubjectAltName(False, subject_dns)
        else:
            raise RuntimeError("Unsupported signtype: " + repr(signtype))

        crt_sn = random_serial_number()

        validity_start = convert_timeinfo(validity_start)
        validity_end = convert_timeinfo(validity_end)

        if self._dbcon:
            with self._dbcon:
                data = (
                    str(crt_sn),
                    local_cname,
                    req_csr.subject.rfc4514_string(),
                    int(datetime.now(timezone.utc).timestamp()),
                    validity_start and int(validity_start.timestamp()),
                    validity_end and int(validity_end.timestamp())
                )

                self._dbcon.execute("INSERT INTO cert_index (sn, cn, dn, issue_date, start_date, end_date)"
                                    " VALUES (?, ?, ?, ?, ?, ?)", data)

        new_crt = self._crt_builder.create_cert(issuer=self._ca_cert.subject,
                                                cert_or_csr_or_subject_pubkey=req_csr,
                                                serial_number=crt_sn,
                                                not_valid_before=validity_start,
                                                not_valid_after=validity_end,
                                                individual_extensions=exts.extensions)

        new_crt.to_file(crt_out_file, encoding=serialization.Encoding.PEM)
        # openssl x509 -in client1.crt -text
        crt_by_serial_file = self.subfolder["certs_by_serial"] / (x509_sn(crt_sn) + ".crt")
        copyfile(crt_out_file, crt_by_serial_file)

        return new_crt

    def check_pki(self):
        # Check base class folders
        PKI.check_pki(self)

        # Check own folders
        for p in self.ca_folder.values():
            if not p.is_dir():
                raise FileNotFoundError("Folder not found: " + str(p))

    def revoke(self, cn_or_sn: Union[str, int], reason: CRLReasonFlags = None, delete=True):
        if type(cn_or_sn) is int:
            # Revoke by serial number (int)
            sn = cn_or_sn
            sn_hex = x509_sn(sn)

            file_by_sn: Path = self.subfolder["certs_by_serial"] / (sn_hex + ".crt")
            if not file_by_sn.is_file():
                raise FileNotFoundError(f"Could not find a matching cert for serial number {cn_or_sn} ({file_by_sn}).")

            # Open cert and extract dn
            cert = Cert(file_by_sn)
            cn_oid = cert.subject.get_oid(NameOID.COMMON_NAME)
            if not cn_oid:
                raise RuntimeError("Cert's subject has no CommonName: " + str(file_by_sn))
            cn = cn_oid.value

            file_by_cn: Path = self.subfolder["issued"] / (cn + ".crt")
            if not file_by_cn.is_file():
                raise FileNotFoundError(f"Could not find a matching cert for CommonName {cn} ({file_by_cn}).")

        elif type(cn_or_sn) is str:
            file_by_cn: Path = self.subfolder["issued"] / (cn_or_sn + ".crt")
            if not file_by_cn.is_file():
                raise FileNotFoundError(f"Could not find a matching cert for CommonName {cn_or_sn} ({file_by_cn}).")

            # Open cert and extract sn
            cert = Cert(file_by_cn)
            sn = cert.serial_number
            sn_hex = x509_sn(sn)

            file_by_sn: Path = self.subfolder["certs_by_serial"] / (sn_hex + ".crt")
            if not file_by_sn.is_file():
                raise FileNotFoundError(f"Could not find a matching cert for serial number {cn_or_sn} ({file_by_sn}).")

            cn = cn_or_sn

        else:
            raise TypeError("You have to pass either the serial number as int or the CommonName as string.")

        req_by_cn: Path = self.subfolder["reqs"] / (cn + ".req")
        if not req_by_cn.is_file():
            raise FileNotFoundError(f"Could not find a matching signing request file: {req_by_cn}")

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
                reason and reason.value,
                rev_id
            )
            self._dbcon.execute("UPDATE cert_index SET revocation_date=?, revocation_reason=? WHERE id=?", data)

        # Remove issued/CN.crt
        if delete:
            file_by_cn.unlink()

        # Move certs_by_serial/SN.crt to revoked/certs_by_serial/SN.crt
        copyfile(file_by_sn, self.subfolder["revoked/certs_by_serial"] / file_by_sn.name)

        # Move reqs/CN.req to revoked/reqs_by_serial/SN.req
        copyfile(req_by_cn, self.subfolder["revoked/reqs_by_serial"] / (sn_hex + ".req"))

        if delete:
            file_by_sn.unlink()
            req_by_cn.unlink()

    def gen_crl(self, next_update: Union[datetime, int] = 31, with_outdated_certs=False) -> Crl:
        self._crl_builder.clear()  # Clear list

        for rc in self.query_db(valid_date=None if with_outdated_certs else True, revoked=True):
            self._crl_builder.add_revocation(RevokedCert(rc[1], rc[7], rc[8]))

        crl = self._crl_builder.build_crl(issuer=self._ca_cert.subject, next_update=next_update)
        crl.crl_to_file(self.ca_crl_file)
        return crl

    def _create_crl_builder(self, password: Union[str, bytes, bytearray] = None) -> CrlBuilder:
        exts = ExtensionBuilder()

        exts.AuthorityKeyIdentifier(False,
                                    self._ca_cert.public_key_digest,
                                    DirectoryName(self._ca_cert.issuer.to_name()),
                                    self._ca_cert.serial_number)
        crlbuilder = CrlBuilder(self._crt_builder.private_key, password)
        return crlbuilder

    def __del__(self):
        if self._dbcon:
            self._dbcon.close()


class Peer(PKI):
    _PEER_SUBFOLDERS = "certs",

    def __init__(self, path: Path = None):
        PKI.__init__(self, path or Path("./peer").absolute())
        self.peer_folder = self._add_extra_folders(self._PEER_SUBFOLDERS)

    def gen_req(self, password: Union[str, bytes, bytearray, None], endpoint_dn: CommonName = default_peer_cn):
        """Create and save key pair and Csr"""
        # /usr/bin/easyrsa --pki-dir=testpki gen-req client1
        if not self._path.exists():
            self.init_pki()

        cn = endpoint_dn.common_name

        private_key_file: Path = self.subfolder["private"] / (cn + ".key")
        req_file: Path = self.subfolder["reqs"] / (cn + ".req")

        for f in private_key_file, req_file:
            if f.exists():
                raise FileExistsError("File is already existing: " + str(private_key_file))

        builder = CsrBuilder(PKICrypto, password)
        builder.private_key_to_file(private_key_file)

        csr = builder.build_csr(subject=endpoint_dn.to_attribute_list())
        csr.to_file(req_file)


def print_cert(p: Path):
    print("\n===", p, "===")
    cert = Cert(p)
    print(cert)
    for e in cert.extensions:
        print(e)


def print_csr(p: Path):
    print("\n===", p, "===")
    csr = CertSigningRequest(p)
    print(csr)
    for e in csr.extensions:
        print(e)
