T=openssl

CONFIG= ./config
include $(CONFIG)

OBJS=src/auxiliar.o src/bio.o src/cipher.o src/crl.o src/csr.o src/digest.o src/misc.o src/openssl.o src/pkcs12.o src/pkcs7.o  src/pkey.o src/x509.o src/conf.o src/ots.o   




.c.o:
	$(CC) $(INCS) -c -o $@ $?

all: $T.so

$T.so: $(OBJS)
	MACOSX_DEPLOYMENT_TARGET="10.3"; export MACOSX_DEPLOYMENT_TARGET; $(CC) $(CFLAGS) $(LIB_OPTION) -o $T.so $(OBJS) -lcrypto -lssl -lrt -ldl

install: all
	mkdir -p $(LUA_LIBDIR)
	cp $T.so $(LUA_LIBDIR)

clean:
	rm -f $T.so $(OBJS) 

