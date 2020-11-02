#!/usr/bin/env bash

# Build the build base image
docker build -t cray/hms-certs-build-base -f Dockerfile.build-base .

docker build -t cray/hms-certs-coverage -f Dockerfile.coverage .
