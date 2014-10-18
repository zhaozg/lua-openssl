package = "openssl"
version = "scm-0"

source = {
  url = "https://github.com/zhaozg/lua-openssl/archive/master.zip",
  dir = "lua-openssl-master",
}

description = {
  summary    = "Openssl binding for Lua",
  homepage   = "https://github.com/zhaozg/lua-openssl",
  license    = "MIT/X11",
  maintainer = "George Zhao",
  detailed   = [[
  ]],
}

dependencies = {
  "lua >= 5.1, < 5.3"
}

external_dependencies = {
}

build = {
  type = "builtin",

  platforms = {
    windows = {
      type = "command",
      build_command = [[nmake -f makefile.win]],
      install_command = [[nmake -f makefile.win install]]
    },
    unix = {
      type = "command",
      build_command = [[make]],
      install_command = [[make install]]
	}
  }
}
