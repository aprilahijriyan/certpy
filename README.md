# certpy

Simple python package to create self-signed SSL certificate

This tool is an experiment to learn _"How to create a self-signed certificate"_.

## Installation

With `pip`:

```
pip install certpy
```

Install from source (you need to install [python-pdm](https://pdm.fming.dev/latest/) first):

```
git clone https://github.com/aprilahijriyan/certpy.git
cd certpy
pdm install
```

## Usage

CertPy provides a workflow file, which will be used to instruct the creation of the certificate.

> The workflow file name is `certpy.yml` (you cannot change the file name or extension to `.yaml`) and the workflow file must be in the directory you are working in.

Here's an example of a workflow:

```yml
# Save it as certpy.yml in the current directory.
certificate_age: &age
  days: 365

certificates:
  kuli:
    type: ca
    distinguished_name:
      countryName: ID
      stateOrProvinceName: Indonesia
      localityName: Jawa Barat
      organizationName: Kuli Dev
      organizationalUnitName: OSS
      commonName: Kuli Dev Root CA
      emailAddress: null
    age: *age
    digest: sha256
    overwrite: true

  server:
    type: server
    distinguished_name:
      commonName: Server
    ca_file: kuli
    age: *age
    digest: sha256
    san:
      ip:
        - 192.168.18.203
      dns:
        - ca.example.com
    overwrite: true

  client:
    type: client
    distinguished_name:
      commonName: Client
    ca_file: kuli
    age: *age
    digest: sha256
    overwrite: true
```

Then, create a CertPy environment (this is to hold all certificates created by CertPy).

```sh
# this will create a `~/.certpy` directory and create a default `Root CA` certificate stored in `~/.certpy/ca/certs/rootCA.pem`.
certpy ca init
```

Now you can create your own certificate from the workflow file!

```
$ certpy create
                                  'kuli' Root CA
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ CA File                               ┃ CA Key                                  ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ /home/april/.certpy/ca/certs/kuli.pem │ /home/april/.certpy/ca/private/kuli.key │
└───────────────────────────────────────┴─────────────────────────────────────────┘
                                     'server' Certificate
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Cert File                                   ┃ Cert Key                                      ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ /home/april/.certpy/server/certs/server.pem │ /home/april/.certpy/server/private/server.key │
└─────────────────────────────────────────────┴───────────────────────────────────────────────┘
                                     'client' Certificate
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Cert File                                   ┃ Cert Key                                      ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ /home/april/.certpy/client/certs/client.pem │ /home/april/.certpy/client/private/client.key │
└─────────────────────────────────────────────┴───────────────────────────────────────────────┘
```

You can verify the self-signed certificate, using the command:

```
$ openssl verify -verbose -CAfile /home/april/.certpy/ca/certs/kuli.pem /home/april/.certpy/server/certs/server.pem
/home/april/.certpy/server/certs/server.pem: OK
```

All certificates generated by CertPy will be stored in the `~/.certpy` directory. And each type of certificate is stored in a different directory.

* For `Root CA` stored in `~/.certpy/ca`.
* For `Server Certificate` stored in `~/.certpy/server`.
* For `Client Certificate` stored in `~/.certpy/client`.

In the directory `~/.certpy/{ca,server,client}` there are 2 directories.

* The `certs` directory is used to store certificates.
* The `private` directory is used to store certificate keys.


## Workflow structure details

* About `certificates` in workflow file

    It contains the definition of certificate.
    In CertPy only supports `Root CA`, `Server` and `Client` certificate types.

    Each type of certificate has a different data structure. Read more below...

* About `Root CA` Certificate

  The structure for `Root CA` is as follows:

  * `type`: set to `ca` to mark if this is a **Root CA** certificate. (**required**)
  * `distinguished_name`: (`object`, **required**)

      * `countryName`: Country Code (e.g. `ID`) (**optional**)
      * `stateOrProvinceName`: State (e.g. `Indonesia`) (**optional**)
      * `localityName`: Province (e.g. `Jawa Barat`) (**optional**)
      * `organizationName`: Organization Name (e.g. `Kuli Dev`) (**optional**)
      * `organizationalUnitName`: Organization Unit Name (e.g. `OSS`) (**optional**)
      * `commonName`: Common Name (e.g. `Kuli Dev Root CA`) (**required**)
      * `emailAddress`: Email address (e.g. `your@company.com`) (**optional**)
  * `age`: (`object`, **required**)

      You must fill in one of the fields below. For example fill `days` with `365` (which is a certificate valid in 1 year)

      * `days`
      * `seconds`
      * `microseconds`
      * `milliseconds`
      * `minutes`
      * `hours`
      * `weeks`

  * `hash`: See https://www.pyopenssl.org/en/latest/api/crypto.html#digest-names (**required**)
  * `overwrite`: If it is set to `true` it will overwrite the old certificate with the new one. By default, if the certificate already exists it will be skipped. (`bool`, **optional**)

* About `Server` Certificate

  Its structure is the same as `Root CA`.

  However, there is a slight addition to the `Server` certificate. Here's a list of the new fields in the `server` certificate:

  * `ca_file`: (`str` or `array`, **required**)

    The CA file is required to sign certificates for `server` or `client`.

    - If it is `str`, it will use the `Root CA` certificate from the workflow file.
    - If using `array`, must have 2 items. For example index `0` is `CA File` and index `1` is `CA Key`.

  * `san`: (`object`, **required**)

    * `ip`: IP address list (`array`)
    * `dns`: Domain name list (`array`)

  > Note: the certificate must be marked with `type: server` if you want to create a certificate for `Server`.

* About `Client` Certificate

  Its structure is the same as `Server Certificate`.

  However, on the client certificate it doesn't have a `san` field.

  > Note: the certificate must be marked with `type: client` if you want to create a certificate for `Client`.

## Related projects

CertPy is heavily inspired by the following tools:

* [mkcert](https://github.com/FiloSottile/mkcert)
* [step-cli](https://smallstep.com/)
