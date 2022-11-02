import os
from datetime import timedelta
from typing import List, Literal, Union

from cryptography.x509.base import random_serial_number
from OpenSSL import crypto

__author__ = "Aprila Hijriyan"
__license__ = "MIT"


def init_certificate(
    *,
    certificate_age: dict,
    distinguished_name: dict,
):
    cert = crypto.X509()
    cert.set_version(2)
    cert.set_serial_number(random_serial_number())
    subject = cert.get_subject()
    for dn, value in distinguished_name.items():
        if value:
            setattr(subject, dn, value)

    not_before = 0
    not_after = int(timedelta(**certificate_age).total_seconds())
    cert.gmtime_adj_notBefore(not_before)
    cert.gmtime_adj_notAfter(not_after)
    return cert, subject


class CertificateAuthority:
    def __init__(self, master: "CertPy", key: crypto.PKey) -> None:
        self.master = master
        self.key = key

    def dumps(self):
        cert, subject = init_certificate(
            certificate_age=self.master.certificate_age,
            distinguished_name=self.master.distinguished_name,
        )
        cert.add_extensions(
            [
                crypto.X509Extension(
                    b"subjectKeyIdentifier", False, b"hash", subject=cert
                ),
            ]
        )
        cert.add_extensions(
            [
                crypto.X509Extension(
                    b"authorityKeyIdentifier", False, b"keyid:always", issuer=cert
                ),
            ]
        )
        cert.add_extensions(
            [
                crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE"),
                crypto.X509Extension(
                    b"keyUsage", True, b"digitalSignature, cRLSign, keyCertSign"
                ),
            ]
        )
        cert.set_issuer(subject)
        cert.set_pubkey(self.key)
        cert.sign(self.key, self.master.digest_type)
        cert_bytes = crypto.dump_certificate(self.master.certificate_format, cert)
        key_bytes = crypto.dump_privatekey(self.master.certificate_format, self.key)
        return cert_bytes, key_bytes


class SelfSignedCertificate:
    def __init__(
        self, master: "CertPy", key: crypto.PKey, ca: crypto.X509, ca_key: crypto.PKey
    ) -> None:
        self.master = master
        self.key = key
        self.ca = ca
        self.ca_key = ca_key
        self.cert_type = None
        self.cert, self.subject = init_certificate(
            certificate_age=self.master.certificate_age,
            distinguished_name=self.master.distinguished_name,
        )

    def set_certificate_type(self, cert_type: Literal["client", "server"]):
        self.cert_type = cert_type

    def _set_extension_for_client(self):
        self.cert.add_extensions(
            [
                crypto.X509Extension(
                    b"subjectKeyIdentifier", False, b"hash", subject=self.cert
                ),
            ]
        )
        self.cert.add_extensions(
            [
                crypto.X509Extension(
                    b"authorityKeyIdentifier", False, b"keyid", issuer=self.ca
                ),
            ]
        )
        self.cert.add_extensions(
            [
                crypto.X509Extension(b"basicConstraints", True, b"CA:FALSE"),
                crypto.X509Extension(
                    b"keyUsage",
                    True,
                    b"nonRepudiation, digitalSignature, keyEncipherment",
                ),
                crypto.X509Extension(
                    b"extendedKeyUsage", False, b"clientAuth, emailProtection"
                ),
                crypto.X509Extension(b"nsCertType", False, b"client, email"),
                crypto.X509Extension(
                    b"nsComment", False, b"CertPy generated certificate for client"
                ),
            ]
        )

    def _set_extension_for_server(self):
        self.cert.add_extensions(
            [
                crypto.X509Extension(
                    b"subjectKeyIdentifier", False, b"hash", subject=self.cert
                ),
            ]
        )
        self.cert.add_extensions(
            [
                crypto.X509Extension(
                    b"authorityKeyIdentifier", False, b"keyid", issuer=self.ca
                ),
            ]
        )
        # reference: https://stackoverflow.com/questions/24475768/is-it-possible-to-set-subjectaltname-using-pyopenssl
        san = []
        for ip in self.master.san.get("ip", []):
            if isinstance(ip, str):
                ip = ip.encode()
            san.append(b"IP:" + ip)
        for dns in self.master.san.get("dns", []):
            if isinstance(dns, str):
                dns = dns.encode()
            san.append(b"DNS:" + dns)
        self.cert.add_extensions(
            [crypto.X509Extension(b"subjectAltName", False, b", ".join(san))]
        )
        self.cert.add_extensions(
            [
                crypto.X509Extension(b"basicConstraints", True, b"CA:FALSE"),
                crypto.X509Extension(
                    b"keyUsage", True, b"digitalSignature, keyEncipherment"
                ),
                crypto.X509Extension(b"extendedKeyUsage", False, b"serverAuth"),
                crypto.X509Extension(b"nsCertType", False, b"server"),
                crypto.X509Extension(
                    b"nsComment", False, b"CertPy generated certificate for server"
                ),
            ]
        )

    def dumps(self):
        if self.cert_type not in ("client", "server"):
            raise ValueError(f"unknown certificate type: {self.cert_type!r}")

        if self.cert_type == "client":
            self._set_extension_for_client()
        else:
            self._set_extension_for_server()

        self.cert.set_issuer(self.ca.get_subject())
        self.cert.set_pubkey(self.key)
        self.cert.sign(self.ca_key, self.master.digest_type)
        cert_bytes = crypto.dump_certificate(self.master.certificate_format, self.cert)
        key_bytes = crypto.dump_privatekey(self.master.certificate_format, self.key)
        return cert_bytes, key_bytes


class CertPy:
    def __init__(
        self, ca: Union[str, crypto.X509] = None, ca_key: Union[str, crypto.PKey] = None
    ):
        self.ca = ca
        self.ca_key = ca_key
        self.distinguished_name = {}
        self.certificate_age = {"days": 365}
        self.digest_type = "sha256"
        self.certificate_format = crypto.FILETYPE_PEM
        self.san = {}

    def set_certificate_age(self, **kwargs):
        self.certificate_age.update(kwargs)

    def set_digest_type(self, digest_type: str = "sha256"):
        self.digest_type = digest_type

    def set_certificate_format(self, certificate_format: int = crypto.FILETYPE_PEM):
        self.certificate_format = certificate_format

    def set_san(self, ip: List[str] = [], dns: List[str] = []):
        self.san["ip"] = ip
        self.san["dns"] = dns

    def set_distinguished_name(
        self,
        countryName: str = None,
        stateOrProvinceName: str = None,
        localityName: str = None,
        organizationName: str = None,
        organizationalUnitName: str = None,
        commonName: str = None,
        emailAddress: str = None,
    ):
        """
        An X.509 Distinguished Name.
        """

        self.distinguished_name.update(
            {
                "countryName": countryName,
                "stateOrProvinceName": stateOrProvinceName,
                "localityName": localityName,
                "organizationName": organizationName,
                "organizationalUnitName": organizationalUnitName,
                "commonName": commonName,
                "emailAddress": emailAddress,
            }
        )

    def load_certificate_authority(
        self, ca_type: int = crypto.FILETYPE_PEM, passphrase: str = None
    ):
        """
        Load CA from file.
        """
        # Reference: https://stackoverflow.com/questions/14565597/pyopenssl-reading-certificate-pkey-file
        if isinstance(self.ca, str):
            assert os.path.isfile(self.ca), "Can't import CA file."
            with open(self.ca, "rb") as fp:
                ca_data = fp.read()
            self.ca = crypto.load_certificate(ca_type, ca_data)

        if isinstance(self.ca_key, str):
            assert os.path.isfile(self.ca_key), "Can't import CA Key file."
            with open(self.ca_key, "rb") as fp:
                ca_key_data = fp.read()
            self.ca_key = crypto.load_privatekey(
                ca_type, ca_key_data, passphrase=passphrase
            )

        return self.ca, self.ca_key

    def create_certificate_authority(
        self, key_type: int = crypto.TYPE_RSA, bits: int = 4096
    ):
        """
        Create our CA.
        """

        key = crypto.PKey()
        key.generate_key(key_type, bits)
        return CertificateAuthority(self, key)

    def create_self_signed_certificate(
        self, key_type: int = crypto.TYPE_RSA, bits: int = 4096
    ):
        """
        Create self-signed certificate.
        """

        assert isinstance(self.ca, crypto.X509) and isinstance(
            self.ca_key, crypto.PKey
        ), "You have to load the CA file and CA key first"
        key = crypto.PKey()
        key.generate_key(key_type, bits)
        return SelfSignedCertificate(self, key, self.ca, self.ca_key)
