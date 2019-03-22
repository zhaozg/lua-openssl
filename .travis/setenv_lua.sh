export PATH=$HOME/.usr/bin:${PATH}
export PKG_CONFIG_PATH=$HOME/.usr/lib/pkgconfig:$PKG_CONFIG_PATH
export LD_LIBRARY_PATH=$HOME/.usr/lib:$LD_LIBRARY_PATH
#MacOS OpenSSL
export PKG_CONFIG_PATH=/usr/local/opt/openssl/lib/pkgconfig:$PKG_CONFIG_PATH
export LD_LIBRARY_PATH=/usr/local/opt/openssl/lib:$LD_LIBRARY_PATH

bash .travis/setup_lua.sh
eval `$HOME/.usr/bin/luarocks path`

