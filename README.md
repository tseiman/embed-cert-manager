# Embedded Certificate Manager
A GO program which is updating certificates (e.g. for web servers) and obtains those from EJBCA API. which are not able to run e.g. an ACME client such as *certbot* or *lego*. It os meant to run for multiple embedded hosts to update the certificate (and may key). Each embedded host (a target) is  "job". It reads configuration .conf files from a configuration directory. Each file is one job. Each file contains parameters for this job. 

Embedded Certificate Manager will then:
- Checks its `/etc/embed-cert-manager/jobs.d` folder and load `*.conf` jobs INI files. Each ini file represents one host or certificate update job
- testing if the certificate is available on the EJBCA CA and if it is valid - if it is valid the job is skipped
- SSH to the target host and executes the shell script given in the Job INI e.g. to generate a CSR
- The CSR must be cat(ed) to the console (STDOUT) in the shellscript so it can be catched and read to local buffer
- sends the CSR via EJBCA API to the relevant CA
- get the signed Certificate
- uploads the certificate to the target host via a script given in the job INIT file
- the script may contains also a command to restart target service


## Build
```
go build
```

## Configuration
The configuration path is by default `/etc/embed-cert-manager/` it contains a sub directory `tls/` which should contain:
- The CA public certificate of the EJBCA SOAP API (often EJBCA ManagmentCA)
- A client certificate related to a client with the rights to access the right API calls
- the related client key

### Job Files

the folder cotains as well a sub folder `jobs.d`. It should contain INI files wit hthe extension `*.conf` which are automatically loaded and processed one by the other. 
The job INI file contains 3 sections: 'job', 'ca', 'target' and has the following parameters:

#### `[job]`
| Key       | Type   | Default | Description |
|-----------|--------|---------|-------------|
| `host`    | string | —       | Name of the host to connect to renew certificate and part of the CN |
| `enabled` | bool   | `false` | If false the job is always skipped |

#### `[ca]`
| Key       | Type   | Default | Description |
|--------------|--------|---------|-------------|
| `host`       | string | —       | Host name of the CA API (EJBCA) |
| `client_cert`| string | -       | client certificate file to be authorized to access EJBCa API, typically in `/etc/embed-cert-manager/tls` |
| `client_key` | string | -       | key related to the client certificate, typically in `/etc/embed-cert-manager/tls` |
| `server_cert_chain` | string | -       | Public certificate chain from the CA providing the API server certificate, as well located typically in `/etc/embed-cert-manager/tls` |
| `ca_cert` | string | -       | a file containing CA PEM dta which should be added to the delivered certificate to provide a chain certificate or CA information fort the service we equip with new certificate `/etc/embed-cert-manager/tls` |
| `ejbca_api_url` | string | -       | the URL to the EJBCA SOAP service. typically something like `https://<my ejbca host.tld>/ejbca/ejbcaws/ejbcaws` |
| `password` | string | -       | the password configured in the EJBCA End Entity configuration to get eccess to get a certificate from thos End Entity  |

#### `[target]`
| Key       | Type   | Default | Description |
|--------------|--------|---------|-------------|
| `ssh_user`       | string | —       | username to use when accessing the target system via SSH |
| `ssh_port`       | int    | —       | target SSH port |
| `ssh_key`        | string | —       | File to the private SSH key to be able to connect unattended to the target system |
| `cert_path`      | string | —       | Path to the certificate to renew on the target system |
| `key_path`       | string | —       | Path to the certificate key to renew on the target system |
| `csr_path`       | string | —       | wher to store the CSR |
| `subjectAltName` | string | —       | Have a SAN for the CSR e.g. `DNS:web.domain.tld,DNS:web,IP:1.1.1.1,IP:2.2.2.2` |
| `change_after`   | string | —       | the time after the certificate should be renewed it uses the EJBCA nomencature <br>• y=year(s)<br>• mo=month(s)<br>• d=day(s)<br>• h=hour(s)<br>• m=minute(s)<br>• s=second(s)<br>E.g. `1y 2mo 4d 1h 44m 10s` |
| `csr_command`    | string | —       | a shel script to create the CSR and to print it to STDOUT the shell scripts can have variables which are referencing to variables in the configuration. the variable is prefixed by the INI section. E.g. the parameter from this job INI file wit the name `key_path` is in the section `target` so the full variable name in the shell script is `target_key_path`. Next to the parameters which are available here in the INI job config file there are also the followimg variables avilable:<br>• `target_certificate` = the certificated loaded from the CA <br>• `ca_ca_cert_loaded` = the ca certifcate loaded from the file given in `ca_cert`. Be careful that the script might be executed in one line, It is recommended to seoarate the commands with a ";" | 
| `set_cert_command`| string | —       | Shell script to write certifcate files on the target and may restart a service. Same varaible environment as in `csr_command` |


## Run
```
/> ./embed-cert-manager
Usage: ./embed-cert-manager [options]

Options:
  -c, --config <path>     Configuration path to read *.conf files from.
                          (default: /etc/embed-cert-manager.d)

  -f, --force             Force generation and poll of Zertifikate
                          even it is still valid (default: false)
```



## Devvelopment
This is not important for a user, but was requred when setting up the project.
```
go get gopkg.in/ini.v1
go get golang.org/x/crypto/ssh
go get github.com/fullsailor/pkcs7
go install github.com/hooklift/gowsdl/cmd/gowsdl@latest
go build
```
