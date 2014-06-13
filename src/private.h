#include "openssl.h"
#include "compat.h"

#define AUXILIAR_SETOBJECT(L, cval, ltype, idx, lvar)	\
	do {									\
	int n = (idx < 0)?idx-1:idx;						\
	PUSH_OBJECT(cval,ltype);				\
	lua_setfield(L, n, lvar);				\
	} while(0)

int XNAME_from_ltable(lua_State*L, X509_NAME* name, int dn);
int XATTRS_from_ltable(lua_State*L,STACK_OF(X509_ATTRIBUTE) **attributes,int attr);
int XEXTS_from_ltable(lua_State*L, STACK_OF(X509_EXTENSION) *exts, X509V3_CTX* ctx, int extensions);

void add_assoc_name_entry(lua_State*L, const  char *key, X509_NAME *name, int shortname);
void add_assoc_x509_extension(lua_State*L, const char* key, STACK_OF(X509_EXTENSION)* ext, BIO* bio);
