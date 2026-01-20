#!/bin/bash

if [ -z $1 ] || [ ! -f "$1.p12" ]; then
    echo "USAGE: extract.sh <.p12 file name without .p12 extension> [clean]"
    exit
fi

if [[ $2 == "clean" ]]; then
    echo Cleaning
    rm -f  $1.crt $1.key
else
    openssl pkcs12 -in $1.p12 -clcerts -nokeys -out $1.crt
    openssl pkcs12 -in $1.p12 -nocerts -nodes -out $1.key
fi