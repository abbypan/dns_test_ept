#!/bin/bash

openssl genrsa -out ept.key.priv.pem 1024
openssl rsa -in ept.key.priv.pem -out ept.key.pub.pem -pubout
