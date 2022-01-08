#!/bin/bash

TAG=$(git describe --abbrev=0)
NOW=$(git describe)

PKG_CONFIG_PATH=$HOME/.usr/lib64/pkgconfig:$HOME/.usr/lib/pkgconfig

if [[ "$RUNNER_OS" == "macOS" && -z "$SSL" ]]; then
  PKG_CONFIG_PATH=/usr/local/opt/openssl/lib/pkgconfig:$PKG_CONFIG_PATH
fi

if [[ "$RUNNER_OS" == "Linux" && "$SSL" == "openssl-1.0.2u" ]]; then
  export CFLAGS="-g -fPIC -fprofile-arcs -ftest-coverage"
  export LDFLAGS="-g -fprofile-arcs"
fi

export PATH=$HOME/.usr/bin:$PATH
export LD_LIBRARY_PATH=$HOME/.usr/lib
export PKG_CONFIG_PATH

make install PREFIX=$HOME/.usr PKG_CONFIG="PKG_CONFIG_PATH=$PKG_CONFIG_PATH pkg-config"
