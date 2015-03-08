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
sudo cp luv.so /usr/local/lib/lua/`luajit -e "_,_,v=string.find(_VERSION,'Lua (.+)');print(v)"`

cd $TRAVIS_BUILD_DIR
