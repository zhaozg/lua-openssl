# Copyright (C) 2007-2011 LuaDist.
# Created by Peter Kapec
# Redistribution and use of this file is allowed according to the terms of the MIT license.
# For details see the COPYRIGHT file distributed with LuaDist.
# Please note that the package source code is licensed under its own license.

project ( lua-openssl C )
cmake_minimum_required ( VERSION 2.6 )
include ( dist.cmake )


find_library(openssl_ssl_libraries names ssl ssleay32 ssleay32md)
find_library(openssl_crypto_libraries names crypto)
if(not openssl_ssl_libraries)
    message("cannot find openssl.")
endif()

# lua-openssl modules
install_lua_module( lua_openssl src/auxiliar.c src/bio.c src/cipher.c src/crl.c src/csr.c
                                src/digest.c src/misc.c src/openssl.c src/pkcs12.c src/pkcs7.c
                                src/pkey.c src/x509.c src/conf.c src/ots.c )


# Install lua-openssl Documentation
install_data( README STATE )

# Install Tests
install_test( test/ )