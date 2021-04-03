#!/bin/bash

source .travis/platform.sh

TAG=$(git describe --abbrev=0)
NOW=$(git describe)

PKG_CONFIG_PATH=$HOME/.usr/lib/pkgconfig

if [[ "$TRAVIS_OS_NAME" == "osx" && -z "$SSL" ]]; then
  PKG_CONFIG_PATH=/usr/local/opt/openssl/lib/pkgconfig:$PKG_CONFIG_PATH
fi
if [[ "$TRAVIS_OS_NAME" == "linux" && -z "$SSL" ]]; then
  pip install cpp-coveralls
  export CFLAGS="-g -fPIC -fprofile-arcs -ftest-coverage"
  export LDFLAGS="-g -fprofile-arcs"
fi

make install PREFIX=$HOME/.usr PKG_CONFIG="PKG_CONFIG_PATH=$PKG_CONFIG_PATH pkg-config"
