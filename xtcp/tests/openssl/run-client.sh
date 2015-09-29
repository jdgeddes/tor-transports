#!/bin/sh

echo "hi there" | openssl s_client -debug -msg -state -connect localhost:8080
