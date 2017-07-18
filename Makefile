T=openssl

PREFIX		?=/usr/local
LIB_OPTION	?= -shared 
CC		?= gcc

#Lua auto detect
LUA_VERSION ?= $(shell pkg-config luajit --print-provides)
ifeq ($(LUA_VERSION),)                         ############ Not use luajit
LUAV		?= $(shell lua -e "_,_,v=string.find(_VERSION,'Lua (.+)');print(v)")
LUA_CFLAGS	?= -I$(PREFIX)/include/lua$(LUAV)
LUA_LIBS	?= -L$(PREFIX)/lib 
LUA_LIBDIR	?= $(PREFIX)/lib/lua/$(LUAV)
else
LUAV		?= $(shell lua -e "_,_,v=string.find(_VERSION,'Lua (.+)');print(v)")
LUA_CFLAGS	?= $(shell pkg-config luajit --cflags)
LUA_LIBS	?= $(shell pkg-config luajit --libs)
LUA_LIBDIR	?= $(PREFIX)/lib/lua/$(LUAV)
endif

#OS auto detect
SYS := $(shell gcc -dumpmachine)

ifneq (, $(findstring linux, $(SYS)))
# Do linux things
LDFLAGS		 = -fpic -lrt -ldl -lm
OPENSSL_LIBS	?= $(shell pkg-config openssl --libs) 
OPENSSL_CFLAGS	?= $(shell pkg-config openssl --cflags)
CFLAGS		 = -fpic $(OPENSSL_CFLAGS) $(LUA_CFLAGS)
LIB_OPTION	+= -Wl,--no-undefined
endif
ifneq (, $(findstring apple, $(SYS)))
# Do darwin things
LDFLAGS		 = -fPIC -lrt -ldl
OPENSSL_LIBS	?= $(shell pkg-config openssl --libs) 
OPENSSL_CFLAGS	?= $(shell pkg-config openssl --cflags)
CFLAGS		 = -fPIC $(OPENSSL_CFLAGS) $(LUA_CFLAGS)
#LIB_OPTION	 = -bundle -undefined dynamic_lookup #for MacOS X
MACOSX_DEPLOYMENT_TARGET="10.3"
CC := MACOSX_DEPLOYMENT_TARGET=${MACOSX_DEPLOYMENT_TARGET} $(CC)
endif
ifneq (, $(findstring mingw, $(SYS)))
# Do mingw things
V		= $(shell lua -e "v=string.gsub('$(LUAV)','%.','');print(v)")
LDFLAGS		= -mwindows -lcrypt32 -lssl -lcrypto -lws2_32 $(PREFIX)/bin/lua$(V).dll 
LUA_CFLAGS	= -DLUA_LIB -DLUA_BUILD_AS_DLL -I$(PREFIX)/include/
CFLAGS		= $(OPENSSL_CFLAGS) $(LUA_CFLAGS)
endif
ifneq (, $(findstring cygwin, $(SYS)))
# Do cygwin things
OPENSSL_LIBS	?= $(shell pkg-config openssl --libs) 
OPENSSL_CFLAGS  ?= $(shell pkg-config openssl --cflags)
CFLAGS		 = -fPIC $(OPENSSL_CFLAGS) $(LUA_CFLAGS)
endif
#custom config
ifeq (.config, $(wildcard .config))
include .config
endif

LIBNAME= $T.so.$V

# Compilation directives
WARN_MIN	= -Wall -Wno-unused-value
WARN		= -Wall
WARN_MOST	= $(WARN) -W -Waggregate-return -Wcast-align -Wmissing-prototypes -Wnested-externs -Wshadow -Wwrite-strings -pedantic
CFLAGS		+= -g $(WARN_MIN) -DPTHREADS -Ideps


OBJS=src/asn1.o src/auxiliar.o src/bio.o src/cipher.o src/cms.o src/compat.o src/crl.o src/csr.o src/dh.o src/digest.o src/dsa.o \
src/ec.o src/engine.o src/hmac.o src/lbn.o src/lhash.o src/misc.o src/ocsp.o src/openssl.o src/ots.o src/pkcs12.o src/pkcs7.o    \
src/pkey.o src/rsa.o src/ssl.o src/th-lock.o src/util.o src/x509.o src/xattrs.o src/xexts.o src/xname.o src/xstore.o src/xalgor.o src/callback.o 

.c.o:
	$(CC) $(CFLAGS) -c -o $@ $?

all: $T.so
	@echo "Target system: "$(SYS)

$T.so: $(OBJS)
	$(CC) $(LDFLAGS) $(LIB_OPTION) -o $T.so $(OBJS) $(OPENSSL_LIBS) $(LUA_LIBS)

install: all
	mkdir -p $(LUA_LIBDIR)
	cp $T.so $(LUA_LIBDIR)

clean:
	rm -f $T.so $(OBJS) 
