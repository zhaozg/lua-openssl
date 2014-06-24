T=openssl

CONFIG= ./config
include $(CONFIG)

OBJS=src/asn1.o src/auxiliar.o src/bio.o src/cipher.o src/compat.o src/crl.o src/csr.o src/digest.o \
src/ec.o src/engine.o src/hmac.o src/lbn.o src/lhash.o src/misc.o src/ocsp.o src/openssl.o src/ots.o \
src/pkcs12.o src/pkcs7.o src/pkey.o src/ssl.o src/x509.o src/xname.o src/xexts.o src/xattrs.o src/th-lock.o

.c.o:
	$(CC) $(INCS) -c -o $@ $?

all: $T.so

$T.so: $(OBJS)
	MACOSX_DEPLOYMENT_TARGET="10.3"; export MACOSX_DEPLOYMENT_TARGET; $(CC) $(CFLAGS) $(LIB_OPTION) -o $T.so $(OBJS) $(STATIC_LIBS) -lrt -ldl
	chcon -t texrel_shlib_t  $T.so

install: all
	mkdir -p $(LUA_LIBDIR)
	cp $T.so $(LUA_LIBDIR)

clean:
	rm -f $T.so $(OBJS) 

