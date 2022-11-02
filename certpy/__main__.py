import os
from distutils.dir_util import remove_tree
from ipaddress import AddressValueError, IPv4Address, IPv6Address
from typing import Dict, List, Tuple

import yaml
from typer import Option, Typer, confirm

from . import CertPy
from .utils import print_table

USR_HOME = os.path.expanduser("~")
BASE_DIR = os.path.join(USR_HOME, ".certpy")
CERTPY_DIR = {
    "ca": os.path.join(BASE_DIR, "ca"),
    "server": os.path.join(BASE_DIR, "server"),
    "client": os.path.join(BASE_DIR, "client"),
}

cli = Typer(name="certpy")

ca_cli = Typer(name="ca", help="CA Manager")


@ca_cli.command("init")
def ca_init(force: bool = Option(False, help="Re-init certpy directory")):
    """
    Initialize certpy directory.
    """

    if os.path.isdir(BASE_DIR) and force:
        confirm(
            "You will delete all Root CA and other certificates. Are you sure?",
            abort=True,
        )
        remove_tree(BASE_DIR)
        print("Successfully delete all certificates")
        print("Re-initializing the certpy directory...")
    else:
        print("Initializing the certpy directory...")

    os.makedirs(BASE_DIR, exist_ok=True)
    for _, dir in CERTPY_DIR.items():
        certs_dir = os.path.join(dir, "certs")
        private_dir = os.path.join(dir, "private")
        os.makedirs(certs_dir, exist_ok=True)
        os.makedirs(private_dir, exist_ok=True)

    ca_file = os.path.join(CERTPY_DIR["ca"], "certs", "rootCA.pem")
    ca_keyfile = os.path.join(CERTPY_DIR["ca"], "private", "rootCA.key")
    if os.path.isfile(ca_file) and os.path.isfile(ca_keyfile):
        print(
            "Default root CA already exists. Try using the '--force`` option to reinitialize it."
        )
        return

    print("Creating the default Root CA...")
    cp = CertPy()
    cp.set_distinguished_name(
        countryName="ID",
        stateOrProvinceName="Indonesia",
        localityName="Jawa Barat",
        organizationName="Kuli Dev",
        organizationalUnitName="OSS",
        commonName="CertPy Root CA",
    )
    ca = cp.create_certificate_authority()
    ca_bytes, key_bytes = ca.dumps()
    with open(ca_file, "wb") as fp:
        fp.write(ca_bytes)
    with open(ca_keyfile, "wb") as fp:
        fp.write(key_bytes)

    print("Successfully created a default Root CA")
    print("CA file:", ca_file)
    print("CA key file:", ca_keyfile)


@cli.command("create")
def create_cert(name: List[str] = Option([], help="Certificate name in workflow file")):
    """
    Create certificate from CertPy workflow.
    """
    workflow_file = os.path.abspath("certpy.yml")
    if not os.path.isfile(workflow_file):
        print("Cannot find CertPy workflow file")
        return

    with open(workflow_file) as fp:
        workflow: dict = yaml.safe_load(fp)

    CA_DICT: Dict[str, dict] = {}
    USER_CERT_DICT: Dict[str, dict] = {}
    for cert_name, cert_obj in workflow.get("certificates", {}).items():
        if name and cert_name in name:
            continue

        cert_type = cert_obj["type"]
        if cert_type == "ca":
            CA_DICT[cert_name] = cert_obj
        elif cert_type in ("client", "server"):
            USER_CERT_DICT[cert_name] = cert_obj
        else:
            print(f"Invalid certificate type: {cert_name} ({cert_type})")
            exit(1)

    CA_PATHS: Dict[str, Tuple[str, str]] = {}
    for ca_name, cert_obj in CA_DICT.items():
        ca_file = os.path.join(CERTPY_DIR["ca"], "certs", f"{ca_name}.pem")
        ca_keyfile = os.path.join(CERTPY_DIR["ca"], "private", f"{ca_name}.key")
        overwrite = cert_obj.get("overwrite", False)
        if os.path.isfile(ca_file) and os.path.isfile(ca_keyfile) and not overwrite:
            print(
                f"Root CA {ca_name!r} already exists. Try using the 'overwrite' option to regenerate certificate."
            )
            continue

        cert_dn = cert_obj["distinguished_name"]
        cert_age = cert_obj["age"]
        cert_hash = cert_obj["hash"]
        cp = CertPy()
        cp.set_distinguished_name(**cert_dn)
        cp.set_certificate_age(**cert_age)
        cp.set_hash_type(cert_hash)
        ca = cp.create_certificate_authority()
        ca_bytes, key_bytes = ca.dumps()
        with open(ca_file, "wb") as fp:
            fp.write(ca_bytes)
        with open(ca_keyfile, "wb") as fp:
            fp.write(key_bytes)

        CA_PATHS[ca_name] = (ca_file, ca_keyfile)
        print_table(
            f"{ca_name!r} Root CA",
            columns=["CA File", "CA Key"],
            rows=[(ca_file, ca_keyfile)],
        )

    for cert_name, cert_obj in USER_CERT_DICT.items():
        cert_type = cert_obj["type"]
        cert_file = os.path.join(CERTPY_DIR[cert_type], "certs", f"{cert_name}.pem")
        cert_keyfile = os.path.join(
            CERTPY_DIR[cert_type], "private", f"{cert_name}.key"
        )
        overwrite = cert_obj.get("overwrite", False)
        if os.path.isfile(cert_file) and os.path.isfile(cert_keyfile) and not overwrite:
            print(
                f"Certificate for {cert_name!r} already exists. Try using the 'overwrite' option to regenerate certificate."
            )
            continue

        ca_bundle = cert_obj.get("ca_file")
        if not ca_bundle:
            print(f"Root CA required to sign certificate {cert_name!r}")
            exit(1)

        if isinstance(ca_bundle, str):
            if ca_bundle not in CA_PATHS:
                print(f"Cannot find Root CA for {cert_name!r}")
                exit(1)

            ca_file, ca_keyfile = CA_PATHS[ca_bundle]

        elif isinstance(ca_bundle, list):
            ca_file = os.path.expanduser(ca_bundle[0])
            ca_keyfile = os.path.expanduser(ca_bundle[1])

        else:
            print(
                f"Unsupported format: {type(ca_bundle)} (We only support string and array types for 'ca_file' field)"
            )
            exit(1)

        ip_address = []
        dns = []
        if cert_type == "server":
            san = cert_obj.get("san", {})
            ip_address = san.get("ip", [])
            dns = san.get("dns", [])
            if len(ip_address) == 0 and len(dns) == 0:
                print("You must provide a SAN for the server certificate.")
                exit(1)

            for ip in ip_address:
                valid_ip = False
                for ip_validator in (IPv4Address, IPv6Address):
                    try:
                        ip_validator(ip)
                    except AddressValueError:
                        pass
                    else:
                        valid_ip = True
                if not valid_ip:
                    print(f"Invalid IP address: {ip!r}")
                    exit(1)

        cert_dn = cert_obj["distinguished_name"]
        cert_age = cert_obj["age"]
        cert_hash = cert_obj["hash"]
        cp = CertPy(ca=ca_file, ca_key=ca_keyfile)
        cp.set_san(ip_address, dns)
        cp.load_certificate_authority()
        cp.set_distinguished_name(**cert_dn)
        cp.set_certificate_age(**cert_age)
        cp.set_hash_type(cert_hash)
        self_signed_cert = cp.create_self_signed_certificate()
        self_signed_cert.set_certificate_type(cert_type=cert_type)
        cert_bytes, key_bytes = self_signed_cert.dumps()
        with open(cert_file, "wb") as fp:
            fp.write(cert_bytes)
        with open(cert_keyfile, "wb") as fp:
            fp.write(key_bytes)

        print_table(
            f"{cert_name!r} Certificate",
            columns=["Cert File", "Cert Key"],
            rows=[(cert_file, cert_keyfile)],
        )


# add subcommand
cli.add_typer(ca_cli)
