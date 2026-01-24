# Embedded Certificate Manager
A Go program that updates certificates (e.g. for web servers) and obtains them from the EJBCA API for systems that are not able to run an ACME client such as *certbot* or *lego*. It is intended to run for multiple embedded hosts to update certificates (and possibly keys). Each embedded host (a target) is represented by a “job”.

The program reads `.conf` configuration files from a configuration directory. Each file represents one job and contains all parameters required for that job.

Embedded Certificate Manager will then:
- Check its `/etc/embed-cert-manager/jobs.d` folder and load `*.conf` job INI files. Each INI file represents one host or certificate update job
- Test whether the certificate is available on the EJBCA CA and whether it is still valid – if it is valid, the job is skipped
- Connect to the target host via SSH and execute the shell script defined in the job INI file (e.g. to generate a CSR)
- The CSR must be printed (`cat`) to the console (STDOUT) by the shell script so it can be captured and read into a local buffer
- Send the CSR to the relevant CA via the EJBCA API
- Retrieve the signed certificate
- Upload the certificate to the target host via a script defined in the job INI file
- The script may also contain a command to restart the target service

## Content
- [Build](#build)
- [Configuration](#configuration)
  - [Job Files](#job-files)
    - [File Section Job](#job)
    - [File Section Ca](#ca)
    - [File Section Target](#target)
    - [Command parameters](#command-parameters)
- [Run](#run)
- [Development](#development)

## Build
```
go build
```

## Configuration
The default configuration path is `/etc/embed-cert-manager/`. It contains a subdirectory `tls/`, which should include:
- The CA public certificate of the EJBCA SOAP API (often the EJBCA ManagementCA)
- A client certificate associated with a client that has the rights to access the required API calls
- The corresponding client key

### Job Files

The configuration directory also contains a subfolder `jobs.d`. It should contain INI files with the extension `*.conf`, which are automatically loaded and processed one after another. Check the examples.

Each job INI file contains the sections `job`, `ca`, and `target` and has the following parameters:

#### File Section `[job]`
| Key       | Type   | Default | Description |
|-----------|--------|---------|-------------|
| `host`    | string | —       | Name of the host to connect to for certificate renewal and part of the CN |
| `enabled` | bool   | `false` | If set to false, the job is always skipped |

#### File Section `[ca]`
| Key       | Type   | Default | Description |
|--------------|--------|---------|-------------|
| `host`       | string | —       | Host name of the CA API (EJBCA) |
| `client_cert`| string | -       | Client certificate file authorized to access the EJBCA API, typically located in `/etc/embed-cert-manager/tls` |
| `client_key` | string | -       | Key corresponding to the client certificate, typically located in `/etc/embed-cert-manager/tls` |
| `server_cert_chain` | string | -       | Public certificate chain of the CA providing the API server certificate, typically located in `/etc/embed-cert-manager/tls` |
| `ca_cert` | string | -       | File containing CA PEM data that should be appended to the delivered certificate to provide a full certificate chain or CA information for the equipped service, typically located in `/etc/embed-cert-manager/tls` |
| `ejbca_api_url` | string | -       | URL of the EJBCA SOAP service, typically something like `https://<my-ejbca-host.tld>/ejbca/ejbcaws/ejbcaws` |
| `password` | string | -       | Password configured in the EJBCA End Entity to authorize certificate issuance for this End Entity |

#### File Section `[target]`
| Key       | Type   | Default | Description |
|--------------|--------|---------|-------------|
| `ssh_user`       | string | —       | Username used to access the target system via SSH |
| `ssh_port`       | int    | —       | SSH port of the target system |
| `ssh_key`        | string | —       | Path to the private SSH key used for unattended access to the target system |
| `cert_path`      | string | —       | Path to the certificate to be renewed on the target system |
| `key_path`       | string | —       | Path to the certificate key to be renewed on the target system |
| `csr_path`       | string | —       | Location where the CSR should be stored |
| `subjectAltName` | string | —       | SANs for the CSR, e.g. `DNS:web.domain.tld,DNS:web,IP:1.1.1.1,IP:2.2.2.2` |
| `change_after`   | string | —       | Time before certificate expiration when renewal should be triggered. It uses the EJBCA nomenclature:<br>• y=year(s)<br>• mo=month(s)<br>• d=day(s)<br>• h=hour(s)<br>• m=minute(s)<br>• s=second(s)<br>E.g. `1y 2mo 4d 1h 44m 10s` |
| `csr_command`    | string | —       | Script used to create the CSR. See section [Command parameters](#command-parameters) |
| `set_cert_command`| string | —       | Shell script used to write certificate files to the target system and optionally restart a service. Uses the same variable environment as `csr_command`. See section [Command parameters](#command-parameters) |

#### Command parameters
The shell script may reference variables derived from the configuration. Variable names are prefixed by the INI section name. For example, the parameter `key_path` in the `target` section is available as `target_key_path` in the script. In addition to the parameters defined in the job INI file, the following variables are also available:

- `target_certificate` = certificate loaded from the CA
- `ca_ca_cert_loaded` = CA certificate loaded from the file specified in `ca_cert`.

Note: Multi line commands need to be enclosed in tripple quote signs - '"""' (see sample files).

**Special requirements for `csr_command`:**
At the end of the script it needs to print the CSR to STDOUT so the CSR data can be fetched by SSH.

## Run
```
/> ./embed-cert-manager
Usage: ./embed-cert-manager [options]

Options:
  -c, --config  <path>     Configuration path to read *.conf files from.
                           (default: /etc/embed-cert-manager.d)

  -f, --force              Force generation and poll of Zertifikate
                           even it is still valid (default: false)

  -l, --loglevel <level>   Sets a verbosity level. Default is "warn".
                           Possible level: error | warn | info | debug

  -h, --help               Prints this help and exit

  -v, --version            Prints the version and exit

```

## Development
This section is not relevant for users, but was required during project setup.

```
go get gopkg.in/ini.v1
go get golang.org/x/crypto/ssh
go get github.com/fullsailor/pkcs7
go install github.com/hooklift/gowsdl/cmd/gowsdl@latest
go build
```
