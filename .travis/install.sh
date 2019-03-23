#!/bin/bash

source .travis/platform.sh

TAG=$(git describe --abbrev=0)
NOW=$(git describe)

PKG_CONFIG_PATH=$HOME/.usr/lib/pkgconfig

if [[ "$TRAVIS_OS_NAME" == "osx" && -z "$SSL" ]]; then
  PKG_CONFIG_PATH=/usr/local/opt/openssl/lib/pkgconfig:$PKG_CONFIG_PATH
fi
make install PREFIX=$HOME/.usr PKG_CONFIG="PKG_CONFIG_PATH=$PKG_CONFIG_PATH pkg-config"

if [ "$TAG" == "$NOW" ]; then
  .travis/publish_rockspec.sh $TAG
  if [[ "$TRAVIS_OS_NAME" == "osx" && -z "$SSL" ]]; then
    sudo $HOME/.usr/bin/luarocks install openssl OPENSSL_DIR=/usr/local/opt/openssl
  fi
  if [[ "$TRAVIS_OS_NAME" == "osx" && -n "$SSL" ]]; then
    sudo $HOME/.usr/bin/luarocks install openssl OPENSSL_DIR=$HOME/.usr
  fi
  if [[ "$TRAVIS_OS_NAME" == "linux" && -z "$SSL" ]]; then
    sudo -H $HOME/.usr/bin/luarocks install openssl
  fi
  if [[ "$TRAVIS_OS_NAME" == "linux" && -n "$SSL" ]]; then
    sudo -H $HOME/.usr/bin/luarocks install openssl OPENSSL_DIR=$HOME/.usr
  fi
fi
