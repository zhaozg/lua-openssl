#include "openssl.h"
#include "compat.h"

#define AUXILIAR_SETOBJECT(L, cval, ltype, idx, lvar)	\
	do {									\
	int n = (idx < 0)?idx-1:idx;						\
	PUSH_OBJECT(cval,ltype);				\
	lua_setfield(L, n, lvar);				\
	} while(0)

enum {
	FORMAT_AUTO = 0,
	FORMAT_DER,
	FORMAT_PEM,
	FORMAT_SMIME,
	FORMAT_NUM
};

extern const char* format[];

BIO* load_bio_object(lua_State* L, int idx);
const EVP_MD* get_digest(lua_State* L, int idx);
const EVP_CIPHER* get_cipher(lua_State* L, int idx);
BIGNUM *BN_get(lua_State *L, int i);
int RAND_init(const char *file);

int XNAME_from_ltable(lua_State*L, X509_NAME* name, int dn);
int XATTRS_from_ltable(lua_State*L,STACK_OF(X509_ATTRIBUTE) **attributes,int attr);
int XEXTS_from_ltable(lua_State*L, STACK_OF(X509_EXTENSION) *exts, X509V3_CTX* ctx, int extensions);

X509_STORE* skX509_to_store(STACK_OF(X509)* calist,const char* files,const char* dirs);

void add_assoc_name_entry(lua_State*L, const  char *key, X509_NAME *name, int shortname);
void add_assoc_x509_extension(lua_State*L, const char* key, STACK_OF(X509_EXTENSION)* ext);
int openssl_pushresult(lua_State*L,int result);
