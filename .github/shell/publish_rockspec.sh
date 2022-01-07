#!/bin/bash

OPENSSL_TAG=$1
if [ -z "${OPENSSL_TAG}" ]; then
  OPENSSL_TAG=$(git describe --tags)
fi

bash .github/shell/make_rockspec.sh ${OPENSSL_TAG}
if [ -n "${LUAROCKS_TOKEN}" ]; then
  $HOME/.usr/bin/luarocks install lua-cjson
  $HOME/.usr/bin/luarocks upload openssl-${OPENSSL_TAG}.rockspec --api-key=${LUAROCKS_TOKEN}
fi
