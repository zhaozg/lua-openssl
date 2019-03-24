#!/bin/bash

OPENSSL_TAG=$1
if [ -z "${OPENSSL_TAG}" ]; then
  OPENSSL_TAG=$(git describe --tags)
fi

bash .travis/make_rockspec.sh ${OPENSSL_TAG}
github-release upload --user zhaozg --repo lua-openssl --tag ${OPENSSL_TAG} \
  --file openssl-${OPENSSL_TAG}.tar.gz --name openssl-${OPENSSL_TAG}.tar.gz
if [ -n "${LUAROCKS_TOKEN}" ]; then
  luarocks upload openssl-${OPENSSL_TAG}.rockspec --api-key=${LUAROCKS_TOKEN}
fi
