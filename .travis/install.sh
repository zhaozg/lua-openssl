#!/bin/bash

TAG=$(git describe --abbrev=0)
NOW=$(git describe)

if [[ "$TRAVIS_OS_NAME" == "osx" && -z "$SSL" ]]; then
  sudo make install PREFIX=$HOME/.usr
fi
if [[ "$TRAVIS_OS_NAME" == "osx" && -n "$SSL" ]]; then
  sudo make install PREFIX=$HOME/.usr
fi
if [[ "$TRAVIS_OS_NAME" == "linux" && -z "$SSL" ]]; then
  sudo -H make install PREFIX=$HOME/.usr
fi
if [[ "$TRAVIS_OS_NAME" == "linux" && -n "$SSL" ]]; then
  sudo -H make install PREFIX=$HOME/.usr
fi

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
