package = "openssl"
version = "scm-3"

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
  "lua >= 5.1, < 5.4"
}

external_dependencies = {
  OPENSSL = {
    header = "openssl/evp.h"
  }
}

build = {
  type = "builtin",

  modules = {
    openssl = {
      sources = {
        "src/asn1.c","src/auxiliar.c","src/bio.c","src/callback.c",
        "src/cipher.c","src/cms.c","src/compat.c","src/crl.c",
        "src/csr.c","src/dh.c","src/digest.c","src/dsa.c",
        "src/ec.c","src/engine.c","src/hmac.c","src/lbn.c",
        "src/lhash.c","src/misc.c","src/ocsp.c","src/openssl.c",
        "src/ots.c","src/pkcs7.c","src/pkcs12.c","src/pkey.c",
        "src/rsa.c","src/ssl.c","src/th-lock.c","src/util.c",
        "src/x509.c","src/xattrs.c","src/xexts.c","src/xname.c",
        "src/xalgor.c","src/xstore.c",
      },
      incdirs = {"${OPENSSL_INCDIR}", "$(OPENSSL_DIR)/include", "deps", "deps/lua-compat"},
      libdirs = {"$(OPENSSL_LIBDIR}", "$(OPENSSL_DIR)/lib"},
      defines = {"PTHREADS"},
      libraries = {"ssl", "crypto"},
    }
  },

  platforms = {
    windows = {
      modules = {
        openssl = {
          libraries = {"libeay32", "ssleay32", "ws2_32", "kernel32", "user32", "gdi32", "advapi32"},
          defines = {"LUA_BUILD_AS_DLL", "LUA_LIB", "WIN32_LEAN_AND_MEAN"},
        }
      }
    },
    macosx = {
      modules = {
        openssl = {
          incdirs = {"/usr/local/opt/openssl/include"},
          libdirs = {"/usr/local/opt/openssl/lib"},
        }
      }    
    }
  },
}
