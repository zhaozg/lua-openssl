cmake_minimum_required(VERSION 2.8.9)
project(lua-openssl C)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules")
option(BUILD_SHARED_LUA_OPENSSL "Shared or Static libluv" ON)

include(GNUInstallDirs)

find_package(LuaJIT 2.0 REQUIRED)
find_package(OpenSSL REQUIRED)

set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
set(THREADS_PREFER_PTHREAD_FLAG TRUE)
find_package(Threads REQUIRED)
add_definitions(-DPTHREADS)

if(BUILD_SHARED_LUA_OPENSSL)
    set(LUA_OPENSSL_LIBTYPE SHARED)
else()
    set(LUA_OPENSSL_LIBTYPE STATIC)
endif()

add_library(lua-openssl ${LUA_OPENSSL_LIBTYPE}
    deps/auxiliar/auxiliar.c
    deps/auxiliar/subsidiar.c
    src/asn1.c
    src/bio.c
    src/callback.c
    src/cipher.c
    src/cms.c
    src/compat.c
    src/crl.c
    src/csr.c
    src/dh.c
    src/digest.c
    src/dsa.c
    src/ec.c
    src/engine.c
    src/hmac.c
    src/lbn.c
    src/lhash.c
    src/misc.c
    src/ocsp.c
    src/oids.txt
    src/openssl.c
    src/ots.c
    src/pkcs12.c
    src/pkcs7.c
    src/pkey.c
    src/private.h
    src/rsa.c
    src/sk.h
    src/srp.c
    src/ssl.c
    src/th-lock.c
    src/util.c
    src/x509.c
    src/xattrs.c
    src/xexts.c
    src/xname.c
    src/xalgor.c
    src/xstore.c
)

target_include_directories(lua-openssl PUBLIC
    ${OPENSSL_INCLUDE_DIR}
    ${LUAJIT_INCLUDE_DIRS}
    deps
    deps/lua-compat
    deps/auxiliar
)

target_link_libraries(lua-openssl PUBLIC
    ${OPENSSL_LIBRARIES}
    ${LUAJIT_LIBRARIES}
    Threads::Threads
)

set_target_properties(lua-openssl PROPERTIES
    PREFIX ""
    OUTPUT_NAME "openssl"
    VERSION 0.7.6.0 SOVERSION 1
)

install(TARGETS lua-openssl
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/lua/5.1
)