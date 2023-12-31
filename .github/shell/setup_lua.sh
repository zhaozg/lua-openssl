#MACOSX_DEPLOYMENT_TARGET! /bin/bash

# A script for setting up environment for travis-ci testing.
# Sets up Lua and Luarocks.
# LUA must be "lua5.1", "lua5.2" or "luajit".
# luajit2.0 - master v2.0
# luajit2.1 - master v2.1

set -eufo pipefail

LUAJIT_VERSION="2.0.5"
LUAJIT_BASE="LuaJIT-$LUAJIT_VERSION"

LUA_HOME_DIR=$HOME/.usr
LR_HOME_DIR=$HOME/.usr

LUAJIT="no"
PLATFORM=linux

if [ "$RUNNER_OS" == "macOS" ]; then
  if [ "$LUA" == "luajit" ]; then
    LUAJIT="yes"
  fi
  if [ "$LUA" == "luajit2.0" ]; then
    LUAJIT="yes"
  fi
  if [ "$LUA" == "luajit2.1" ]; then
    LUAJIT="yes"
  fi
  PLATFORM=macosx
elif [ "$(expr substr $LUA 1 6)" == "luajit" ]; then
  LUAJIT="yes"
fi

mkdir -p "$LUA_HOME_DIR"

if [ "$LUAJIT" == "yes" ]; then

  if [ "$LUA" == "luajit" ]; then
    curl --location https://github.com/LuaJIT/LuaJIT/archive/v$LUAJIT_VERSION.tar.gz | tar xz
  else
    git clone https://github.com/LuaJIT/LuaJIT.git $LUAJIT_BASE
  fi

  cd $LUAJIT_BASE

  if [ "$LUA" == "luajit2.1" ]; then
    git checkout v2.1
  fi

  make && make install PREFIX="$LUA_HOME_DIR"
  ln -s $LUA_HOME_DIR/bin/luajit $LUA_HOME_DIR/bin/lua
else

  if [ "$LUA" == "lua5.1" ]; then
    curl https://www.lua.org/ftp/lua-5.1.5.tar.gz | tar xz
    cd lua-5.1.5
  elif [ "$LUA" == "lua5.2" ]; then
    curl https://www.lua.org/ftp/lua-5.2.4.tar.gz | tar xz
    cd lua-5.2.4
  elif [ "$LUA" == "lua5.3" ]; then
    curl https://www.lua.org/ftp/lua-5.3.6.tar.gz | tar xz
    cd lua-5.3.6
  elif [ "$LUA" == "lua5.4" ]; then
    curl https://www.lua.org/ftp/lua-5.4.6.tar.gz | tar xz
    cd lua-5.4.6
  fi

  # Build Lua without backwards compatibility for testing
  perl -i -pe 's/-DLUA_COMPAT_(ALL|5_2)//' src/Makefile
  make $PLATFORM
  make INSTALL_TOP="$LUA_HOME_DIR" install
fi

export PATH=$LUA_HOME_DIR/bin:$PATH

lua -v

if [[ -n "$LUAROCKS" ]]; then
  LUAROCKS_BASE=luarocks-$LUAROCKS

  curl --location https://luarocks.org/releases/$LUAROCKS_BASE.tar.gz | tar xz

  cd $LUAROCKS_BASE

  if [ "$LUA" == "luajit" ]; then
    ./configure --lua-suffix=jit --with-lua-include="$LUA_HOME_DIR/include/luajit-2.0" --prefix="$LR_HOME_DIR"
  elif [ "$LUA" == "luajit2.0" ]; then
    ./configure --lua-suffix=jit --with-lua-include="$LUA_HOME_DIR/include/luajit-2.0" --prefix="$LR_HOME_DIR"
  elif [ "$LUA" == "luajit2.1" ]; then
    ./configure --lua-suffix=jit --with-lua-include="$LUA_HOME_DIR/include/luajit-2.1" --prefix="$LR_HOME_DIR"
  else
    ./configure --with-lua="$LUA_HOME_DIR" --prefix="$LR_HOME_DIR"
  fi

  make build && make install

  luarocks --version

  rm -rf $LUAROCKS_BASE
fi

if [ "$LUAJIT" == "yes" ]; then
  rm -rf $LUAJIT_BASE
elif [ "$LUA" == "lua5.1" ]; then
  rm -rf lua-5.1.5
elif [ "$LUA" == "lua5.2" ]; then
  rm -rf lua-5.2.4
elif [ "$LUA" == "lua5.3" ]; then
  rm -rf lua-5.3.6
elif [ "$LUA" == "lua5.4" ]; then
  rm -rf lua-5.4.3
fi
