if [ -z "${PLATFORM:-}" ]; then
  PLATFORM=$TRAVIS_OS_NAME;
fi

if [ "$PLATFORM" == "osx" ]; then
  PLATFORM="macosx";
fi

if [ -z "$PLATFORM" ]; then
  if [ "$(uname)" == "Linux" ]; then
    PLATFORM="linux";
  else
    PLATFORM="macosx";
  fi;
fi

if [ "$PLATFORM" == "macosx" ]; then
  echo update openssl;
  brew update;
  brew install openssl;
  brew link --force openssl;
fi
