T=openssl


PREFIX=/usr/local
LUA_LIBDIR= $(PREFIX)/lib/lua/5.1
LIB_OPTION= -shared #for Linux

#Lua auto detect
LUA_VERSION = $(shell pkg-config luajit --print-provides)
ifeq ($(LUA_VERSION),)
LUA_VERSION = $(shell pkg-config lua --print-provides)
ifeq ($(LUA_VERSION,)
LUA_CFLAGS=$(shell pkg-config lua --cflags)
LUA_LIBS=$(shell pkg-config lua --libs)
else
LUA_CFLAGS=-I$(PREFIX)/include/lua5.2
LUA_LIBS=-L$(PREFIX)/lib -llua5.2
endif
else
LUA_CFLAGS=$(shell pkg-config luajit --cflags)
LUA_LIBS=$(shell pkg-config luajit --libs)
endif


LIBNAME= $T.so.$V

#LIB_OPTION= -bundle -undefined dynamic_lookup #for MacOS X
OPENSSL_LIBS=$(shell pkg-config openssl --libs) 
OPENSSL_CFLAGS=$(shell pkg-config openssl --cflags)

# Compilation directives
WARN_MOST= -Wall -fPIC -W -Waggregate-return -Wcast-align -Wmissing-prototypes -Wnested-externs -Wshadow -Wwrite-strings -pedantic
WARN= -Wall -fPIC -Wno-unused-value
CFLAGS= $(WARN) $(OPENSSL_CFLAGS) $(LUA_CFLAGS) -DPTHREADS -DLOAD_ENGINE_CUSTOM=ENGINE_load_gmsm2
CC= gcc -g -fPIC $(CFLAGS)


OBJS=src/asn1.o src/auxiliar.o src/bio.o src/cipher.o src/compat.o src/crl.o src/csr.o src/digest.o \
src/ec.o src/engine.o src/hmac.o src/lbn.o src/lhash.o src/misc.o src/ocsp.o src/openssl.o src/ots.o \
src/pkcs12.o src/pkcs7.o src/pkey.o src/ssl.o src/x509.o src/xname.o src/xexts.o src/xattrs.o src/th-lock.o

.c.o:
	$(CC) $(CFLAGS) -c -o $@ $?

all: $T.so

$T.so: $(OBJS)
	MACOSX_DEPLOYMENT_TARGET="10.3"; export MACOSX_DEPLOYMENT_TARGET; $(CC) $(CFLAGS) $(LIB_OPTION) -o $T.so $(OBJS) $(OPENSSL_LIBS) $(LUA_LIBS) -lrt -ldl

install: all
	mkdir -p $(LUA_LIBDIR)
	cp $T.so $(LUA_LIBDIR)

clean:
	rm -f $T.so $(OBJS) 

