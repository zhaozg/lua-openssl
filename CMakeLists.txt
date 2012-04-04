# Copyright (C) 2007-2011 LuaDist.
# Created by F¨¦lix A.A.
# Redistribution and use of this file is allowed according to the terms of the MIT license.
# For details see the COPYRIGHT file distributed with LuaDist.
# Please note that the package source code is licensed under its own license.

project ( lua-openssl C )
cmake_minimum_required ( VERSION 2.8 )
include ( dist.cmake )

find_package(OpenSSL REQUIRED)

# lua-openssl modules
install_lua_module( openssl src/auxiliar.c src/bio.c src/cipher.c src/crl.c src/csr.c
                                src/digest.c src/misc.c src/openssl.c src/pkcs12.c src/pkcs7.c
                                src/pkey.c src/x509.c src/conf.c src/ots.c LINK ${OPENSSL_CRYPTO_LIBRARY} ${OPENSSL_SSL_LIBRARY})


# Install lua-openssl Documentation
install_data( README STATE )

# Install Tests
install_test( test/ )
