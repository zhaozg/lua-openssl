T=openssl

PREFIX		?=/usr/local
PKG_CONFIG	?=pkg-config
CC		:= $(CROSS)$(CC)
AR		:= $(CROSS)$(AR)
LD		:= $(CROSS)$(LD)
LUA		:=

#OS auto detect
ifneq (,$(TARGET_SYS))
  SYS		:= $(TARGET_SYS)
else
  SYS		:= $(shell gcc -dumpmachine)
endif

#Lua auto detect
LUA_VERSION	:= $(shell $(PKG_CONFIG) luajit --print-provides)
ifeq ($(LUA_VERSION),)
  # Not found luajit package, try lua
  LUA_VERSION	:= $(shell $(PKG_CONFIG) lua --print-provides)
  ifeq ($(LUA_VERSION),)
    # Not found lua package, try from prefix
    LUA_VERSION := $(shell lua -e "_,_,v=string.find(_VERSION,'Lua (.+)');print(v)")
    LUA_CFLAGS	?= -I$(PREFIX)/include
    LUA_LIBS	?= -L$(PREFIX)/lib #-llua
    LUA_LIBDIR	?= $(PREFIX)/lib/lua/$(LUA_VERSION)
    LUA		:= lua
  else
    # Found lua package
    LUA_VERSION	:= $(shell lua -e "_,_,v=string.find(_VERSION,'Lua (.+)');print(v)")
    LUA_CFLAGS	?= $(shell $(PKG_CONFIG) lua --cflags)
    LUA_LIBS	?= $(shell $(PKG_CONFIG) lua --libs)
    LUA_LIBDIR	?= $(PREFIX)/lib/lua/$(LUA_VERSION)
    LUA		:= lua
  endif
else
  # Found luajit package
  LUA_VERSION	:= $(shell luajit -e "_,_,v=string.find(_VERSION,'Lua (.+)');print(v)")
  LUA_CFLAGS	?= $(shell $(PKG_CONFIG) luajit --cflags)
  LUA_LIBS	?= $(shell $(PKG_CONFIG) luajit --libs)
  LUA_LIBDIR	?= $(PREFIX)/lib/lua/$(LUA_VERSION)
  LUA		:= luajit
endif

#OpenSSL auto detect
OPENSSL_CFLAGS	?= $(shell $(PKG_CONFIG) openssl --cflags)
ifdef OPENSSL_STATIC
  # User requested static linking: use pkg-config --static
  OPENSSL_LIBS	?= $(shell $(PKG_CONFIG) openssl --static --libs)
else
  # Default: dynamic linking via pkg-config
  OPENSSL_LIBS	?= $(shell $(PKG_CONFIG) openssl --libs)
endif

# Detect build target
BUILD_TARGET := $(firstword $(MAKECMDGOALS))
ifeq ($(BUILD_TARGET),)
  BUILD_TARGET := all
endif

ifeq (coveralls, $(BUILD_TARGET))
  CFLAGS	+=-g -fprofile-arcs -ftest-coverage
  LDFLAGS	+=-g -fprofile-arcs
endif

# asan {{{

ifeq (asan, $(BUILD_TARGET))
ifneq (, $(findstring apple, $(SYS)))
  ASAN_LIB      ?= $(shell dirname $(shell dirname $(shell clang -print-libgcc-file-name)))/darwin/libclang_rt.asan_osx_dynamic.dylib
  LDFLAGS       +=-g -fsanitize=address
endif
ifneq (, $(findstring linux, $(SYS)))
  ASAN_LIB      ?= $(shell dirname $(shell cc -print-libgcc-file-name))/libasan.so
  LDFLAGS       +=-g -fsanitize=address -lubsan
endif
CC            ?= clang
LD            ?= clang
CFLAGS	+=-g -O0 -fsanitize=address,undefined
endif

# asan }}}

# tsan {{{

ifeq (tsan, $(BUILD_TARGET))
ifneq (, $(findstring apple, $(SYS)))
  ASAN_LIB      ?= $(shell dirname $(shell dirname $(shell clang -print-libgcc-file-name)))/darwin/libclang_rt.tsan_osx_dynamic.dylib
  LDFLAGS       +=-g -fsanitize=thread
endif

ifneq (, $(findstring linux, $(SYS)))
  ASAN_LIB      ?= $(shell dirname $(shell cc -print-libgcc-file-name))/libtsan.so
  LDFLAGS       +=-g -fsanitize=thread -lubsan -ltsan
endif
CC            ?= clang
LD            ?= clang
CFLAGS	+=-g -O0 -fsanitize=thread
endif

# tsan }}}

ifeq (debug, $(BUILD_TARGET))
  CFLAGS	+=-g -Og
  LDFLAGS       +=-g -Og
endif

ifeq (valgrind, $(BUILD_TARGET))
  CFLAGS	+=-g -O0
  LDFLAGS	+=-g -O0
endif

ifneq (, $(findstring linux, $(SYS)))
  # Do linux things
  CFLAGS	+= -fPIC
  LDFLAGS	+= -fPIC # -Wl,--no-undefined
endif

ifneq (, $(findstring apple, $(SYS)))
  # Do darwin things
  export MACOSX_DEPLOYMENT_TARGET := 10.12
  CFLAGS	+= -fPIC
  LDFLAGS	+= -fPIC -Wl,-undefined,dynamic_lookup -ldl
endif

ifneq (, $(findstring mingw, $(SYS)))
  # Do mingw things
  CFLAGS	+= -DLUA_LIB -DLUA_BUILD_AS_DLL -DWIN32_LEAN_AND_MEAN
endif

ifneq (, $(findstring cygwin, $(SYS)))
  # Do cygwin things
  CFLAGS	+= -fPIC
endif

ifneq (, $(findstring iOS, $(SYS)))
  # Do iOS things
  CFLAGS	+= -fPIC
  LDFLAGS	+= -fPIC -ldl
endif

#custom config
ifeq (.config, $(wildcard .config))
  include .config
endif

CFLAGS		+= $(OPENSSL_CFLAGS) $(LUA_CFLAGS) $(TARGET_FLAGS)
LDFLAGS		+= $(OPENSSL_LIBS)
# Compilation directives
WARN_MIN	 = -Wall -Wno-unused-value -Wno-unused-function
WARN		 = -Wall
WARN_MOST	 = $(WARN) -W -Waggregate-return -Wcast-align -Wmissing-prototypes \
		   -Wnested-externs -Wshadow -Wwrite-strings -pedantic
CFLAGS		+= $(WARN_MIN) -Ideps -Ideps/lua-compat/c-api -Ideps/auxiliar

OBJS=src/asn1.o deps/auxiliar/auxiliar.o src/bio.o src/cipher.o src/cms.o src/compat.o \
     src/crl.o src/csr.o src/dh.o src/digest.o src/dsa.o src/ec.o src/engine.o         \
     src/hmac.o src/lbn.o src/lhash.o src/misc.o src/ocsp.o src/openssl.o  \
     src/ots.o src/pkcs12.o src/pkcs7.o src/pkey.o src/provider.o src/rsa.o src/ssl.o  \
     src/th-lock.o src/util.o src/x509.o src/xattrs.o src/xexts.o src/xname.o          \
     src/xstore.o src/xalgor.o src/param.o src/kdf.o                                   \
     src/callback.o src/srp.o src/mac.o src/ssl_pqc.o deps/auxiliar/subsidiar.o

.PHONY: all install test info doc coveralls asan debug valgrind tsan clean check

.c.o:
	$(CC) $(CFLAGS) -c -o $@ $?

all: $T.so
	@echo "Target system: "$(SYS)

$T.so: lib$T.a
ifneq (, $(findstring apple, $(SYS)))
	$(CC) -shared -o $@ -Wl,-force_load,$^ $(LDFLAGS)
else
	$(CC) -shared -o $@ -Wl,--whole-archive $^ -Wl,--no-whole-archive $(LDFLAGS)
endif

lib$T.a: $(OBJS)
	$(AR) rcs $@ $?

src/pkey.o: src/pkey.c src/pkey/core.c src/pkey/engine.c src/pkey/read.c src/pkey/sign.c \
            src/pkey/derive.c src/pkey/new.c src/pkey/seal.c src/pkey/sm2.c src/pkey/kem.c
	$(CC) $(CFLAGS) -c -o $@ src/pkey.c

install: all
	mkdir -p $(LUA_LIBDIR)
	cp $T.so $(LUA_LIBDIR)

doc:
	ldoc src -d doc -s .ldoc.css

info:
	@echo "Target system: "$(SYS)
	@echo "CC:" $(CC)
	@echo "AR:" $(AR)
	@echo "PREFIX:" $(PREFIX)

test:	all
	cd test && LUA_CPATH=$(shell pwd)/?.so $(shell which $(LUA)) test.lua -v && cd ..

debug: all

check:
	luajit .github/shell/analyze_ldoc.lua src

coveralls: test
ifeq ($(CI),)
	lcov -c -d src -o ${T}.info
	genhtml -o ${T}.html -t "${T} coverage" --num-spaces 2 ${T}.info
endif

valgrind: all
	cd test && LUA_CPATH=$(shell pwd)/?.so \
	valgrind --gen-suppressions=all --suppressions=../.github/lua-openssl.supp \
	--error-exitcode=1 --leak-check=full --show-leak-kinds=all --num-callers=64 \
	--child-silent-after-fork=yes $(LUA) test.lua && cd ..

asan: all
ifneq (, $(findstring apple, $(SYS)))
	cd test && LUA_CPATH=$(shell pwd)/?.so \
	ASAN_LIB=$(ASAN_LIB) \
	LSAN_OPTIONS=suppressions=${shell pwd}/.github/asan.supp \
	DYLD_INSERT_LIBRARIES=$(ASAN_LIB) \
	$(LUA) test.lua && cd ..
endif
ifneq (, $(findstring linux, $(SYS)))
	cd test && LUA_CPATH=$(shell pwd)/?.so \
	ASAN_LIB=$(ASAN_LIB) \
	LSAN_OPTIONS=suppressions=${shell pwd}/.github/asan.supp \
	LD_PRELOAD=$(ASAN_LIB) \
	$(LUA) test.lua && cd ..
endif

tsan: all
ifneq (, $(findstring apple, $(SYS)))
	cd test && LUA_CPATH=$(shell pwd)/?.so \
	ASAN_LIB=$(ASAN_LIB) \
	LSAN_OPTIONS=suppressions=${shell pwd}/.github/asan.supp \
	DYLD_INSERT_LIBRARIES=$(ASAN_LIB) \
	$(LUA) test.lua && cd ..
endif
ifneq (, $(findstring linux, $(SYS)))
	cd test && LUA_CPATH=$(shell pwd)/?.so \
	ASAN_LIB=$(ASAN_LIB) \
	LSAN_OPTIONS=suppressions=${shell pwd}/.github/asan.supp \
	LD_PRELOAD=$(ASAN_LIB) \
	$(LUA) test.lua && cd ..
endif

clean:
	rm -rf $T.* lib$T.a $(OBJS) src/*.g* doc/
	$(RM) -r test/__cache

# vim: ts=8 sw=8 noet
