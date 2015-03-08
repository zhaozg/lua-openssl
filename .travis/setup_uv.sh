#! /bin/bash

source .travis/platform.sh

cd $TRAVIS_BUILD_DIR
git clone https://github.com/luvit/luv
cd luv
git submodule update --init --recursive
git submodule update --recursive

sudo add-apt-repository --yes ppa:kalakris/cmake
sudo apt-get update -qq
sudo apt-get install cmake

make
export LUA_LIBDIR=/usr/local/lib/lua/`shell lua -e "_,_,v=string.find(_VERSION,'Lua (.+)');print(v)"`
cp build/luv.so $(LUA_LIBDIR)

cd $TRAVIS_BUILD_DIR
