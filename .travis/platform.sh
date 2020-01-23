#!/bin/sh

if [ -z "${PLATFORM:-}" ]; then
  PLATFORM=$TRAVIS_OS_NAME
fi

if [ "$PLATFORM" == "osx" ]; then
  PLATFORM="macosx"
  export MACOSX_DEPLOYMENT_TARGET=10.12
fi

if [ -z "$PLATFORM" ]; then
  if [ "$(uname)" == "Linux" ]; then
    PLATFORM="linux"
  else
    PLATFORM="macosx"
    export MACOSX_DEPLOYMENT_TARGET=10.12
  fi
fi
