# Embedded Certificate Manager
A GO program which is updating certificates (e.g. for web servers) and obtains those from EJBCA API. which are not able to run e.g. an ACME client such as *certbot* or *lego*. It os meant to run for multiple embedded hosts to update the certificate (and may key). Each embedded host (a target) is  "job". It reads configuration .conf files from a configuration directory. Each file is one job. Each file contains parameters for this job. 

Embedded Certificate Manager will then:
- SSH to the target host and generates a CSR
- downlods the CSR
- sends the CSR via EJBCA API to the relevant CA
- get the signed Certificate
- uploads the certificate to the target host
- restart target service


## build
```
go get gopkg.in/ini.v1
go get golang.org/x/crypto/ssh
go get github.com/fullsailor/pkcs7
go install github.com/hooklift/gowsdl/cmd/gowsdl@latest
go build
```

## ToDo
Nearly everything ...
- SSH into host
- API access to EJBCA using client certificate
