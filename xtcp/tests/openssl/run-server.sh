#!/bin/sh

openssl s_server -debug -msg -state -key key.pem -cert cert.pem -accept 8080
