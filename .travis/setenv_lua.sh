export PATH=$HOME/.usr/bin:${PATH}
bash .travis/setup_lua.sh
eval `$HOME/.usr/luarocks path`
