#include "openssl.h"

int lo_lt2name(lua_State*L, X509_NAME* name, int dn);
int lo_lt2extensions(lua_State*L,
    STACK_OF(X509_EXTENSION) *exts,
    X509V3_CTX* ctx,
    int extensions);
int lo_lt2attrs(lua_State*L,
    STACK_OF(X509_ATTRIBUTE) **attributes,
    int attr);