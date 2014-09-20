#include "openssl.h"
#include "compat.h"

#define AUXILIAR_SETOBJECT(L, cval, ltype, idx, lvar) \
  do {                                                \
  int n = (idx < 0)?idx-1:idx;                        \
  PUSH_OBJECT(cval,ltype);                            \
  lua_setfield(L, n, lvar);                           \
  } while(0)


#define OPENSSL_PKEY_GET_BN(bn, _name)    \
  if (bn != NULL) {                       \
  BIGNUM* b = BN_dup(bn);                 \
  PUSH_OBJECT(b,"openssl.bn");            \
  lua_setfield(L,-2,#_name);              \
  }

#define OPENSSL_PKEY_SET_BN(n, _type, _name)  {             \
  lua_getfield(L,n,#_name);                                 \
  if(lua_isstring(L,-1)) {                                  \
  size_t l = 0;                                             \
  const char* bn = luaL_checklstring(L,-1,&l);              \
  if(_type->_name==NULL)  _type->_name = BN_new();          \
  BN_bin2bn((const unsigned char *)bn,l,_type->_name);      \
  }else if(auxiliar_isclass(L,"openssl.bn",n)) {            \
  const BIGNUM* bn = CHECK_OBJECT(n,BIGNUM,"openssl.bn");   \
  if(_type->_name==NULL)  _type->_name = BN_new();          \
  BN_copy(_type->_name, bn);                                \
  }else if(!lua_isnil(L,-1))                                \
  luaL_error(L,"arg #%d must be string or openssl.bn",n);   \
  lua_pop(L,1);                                             \
}


enum
{
  FORMAT_AUTO = 0,
  FORMAT_DER,
  FORMAT_PEM,
  FORMAT_SMIME,
  FORMAT_NUM
};

extern const char* format[];

BIO* load_bio_object(lua_State* L, int idx);
const EVP_MD* get_digest(lua_State* L, int idx);
const EVP_CIPHER* get_cipher(lua_State* L, int idx, const char* def_alg);
BIGNUM *BN_get(lua_State *L, int i);
int openssl_engine(lua_State *L);

int XATTRS_from_ltable(lua_State*L, STACK_OF(X509_ATTRIBUTE) **attributes, int attr);
int XEXTS_from_ltable(lua_State*L, STACK_OF(X509_EXTENSION) *exts, X509V3_CTX* ctx, int extensions);

X509_STORE* skX509_to_store(STACK_OF(X509)* calist, const char* files, const char* dirs);

void to_hex(const char* in, int length, char* out);

int push_x509_name(lua_State* L, X509_NAME *name, int encode);
int openssl_push_asn1type(lua_State* L, const ASN1_TYPE* type);
int openssl_push_asn1object(lua_State* L, const ASN1_OBJECT* obj);
int openssl_push_asn1(lua_State* L, ASN1_STRING* string, int type, int utf8);
int openssl_push_x509_algor(lua_State*L,const X509_ALGOR* alg);

#define PUSH_ASN1_TIME(L, tm)             openssl_push_asn1(L, (ASN1_STRING*)tm, V_ASN1_UTCTIME, 0)
#define PUSH_ASN1_GENERALIZEDTIME(L, tm)  openssl_push_asn1(L, (ASN1_STRING*)tm, V_ASN1_GENERALIZEDTIME, 0)
#define PUSH_ASN1_INTEGER(L, i)           openssl_push_asn1(L, (ASN1_STRING*)i,  V_ASN1_INTEGER, 0)
#define PUSH_ASN1_OCTET_STRING(L, s)      openssl_push_asn1(L, (ASN1_STRING*)s,  V_ASN1_OCTET_STRING, 0)
#define PUSH_ASN1_BIT_STRING(L, s)        openssl_push_asn1(L, (ASN1_STRING*)s,  V_ASN1_BIT_STRING, 0)
#define PUSH_ASN1_STRING(L, s, utf)       openssl_push_asn1(L, (ASN1_STRING*)s,  0,  utf)

int openssl_push_xname(lua_State*L, X509_NAME* xname);
int openssl_new_xname(lua_State*L, X509_NAME* xname, int idx, int utf8);
int openssl_register_xname(lua_State*L);
int openssl_x509_extensions(lua_State* L);

void add_assoc_x509_extension(lua_State*L, const char* key, STACK_OF(X509_EXTENSION)* ext);
int openssl_pushresult(lua_State*L, int result);

int openssl_newvalue(lua_State*L, void*p);
int openssl_freevalue(lua_State*L, void*p);
int openssl_setvalue(lua_State*L, void*p, const char*field);
int openssl_getvalue(lua_State*L, void*p, const char*field);
