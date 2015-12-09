#include "openssl.h"

#include "lua-compat/c-api/compat-5.3.h"

#define luaL_checktable(L, n) luaL_checktype(L, n, LUA_TTABLE)

#if LUA_VERSION_NUM >= 502
#ifndef lua_equal
#define lua_equal( L, a, b) lua_compare( L, a, b, LUA_OPEQ)
#endif
#ifndef lua_lessthan
#define lua_lessthan( L, a, b) lua_compare( L, a, b, LUA_OPLT)
#endif
#define luaG_registerlibfuncs( L, _funcs) luaL_setfuncs( L, _funcs, 0)
#endif

#if LUA_VERSION_NUM >= 503
#ifndef luaL_checkint
#define luaL_checkint(L,n) ((int)luaL_checkinteger(L, (n)))
#endif
#ifndef luaL_optint
#define luaL_optint(L,n,d) ((int)luaL_optinteger(L, (n), (d)))
#endif
#ifndef luaL_checklong
#define luaL_checklong(L,n)	((long)luaL_checkinteger(L, (n)))
#endif
#ifndef luaL_optlong
#define luaL_optlong(L,n,d)	((long)luaL_optinteger(L, (n), (d)))
#endif
#endif

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
  }else if(auxiliar_isclass(L,"openssl.bn",-1)) {           \
  const BIGNUM* bn = CHECK_OBJECT(-1,BIGNUM,"openssl.bn");  \
  if(_type->_name==NULL)  _type->_name = BN_new();          \
  BN_copy(_type->_name, bn);                                \
  }else if(!lua_isnil(L,-1))                                \
  luaL_error(L,"arg #%d must have \"%s\" field string or openssl.bn",n,#_name);   \
  lua_pop(L,1);                                             \
}

static size_t posrelat(ptrdiff_t pos, size_t len)
{
  if (pos >= 0) return (size_t)pos;
  else if (0u - (size_t)pos > len) return 0;
  else return len - ((size_t)-pos) + 1;
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
int  bio_is_der(BIO* bio);
const EVP_MD* get_digest(lua_State* L, int idx);
const EVP_CIPHER* get_cipher(lua_State* L, int idx, const char* def_alg);
BIGNUM *BN_get(lua_State *L, int i);
int openssl_engine(lua_State *L);
int openssl_pkey_is_private(EVP_PKEY* pkey);

void to_hex(const char* in, int length, char* out);

int openssl_push_asn1type(lua_State* L, const ASN1_TYPE* type);
int openssl_push_asn1object(lua_State* L, const ASN1_OBJECT* obj);
int openssl_push_asn1(lua_State* L, ASN1_STRING* string, int type);
int openssl_push_x509_algor(lua_State*L, const X509_ALGOR* alg);
int openssl_push_general_name(lua_State*L, const GENERAL_NAME* name);

#define PUSH_ASN1_TIME(L, tm)             openssl_push_asn1(L, (ASN1_STRING*)tm, V_ASN1_UTCTIME)
#define PUSH_ASN1_INTEGER(L, i)           openssl_push_asn1(L, (ASN1_STRING*)i,  V_ASN1_INTEGER)
#define PUSH_ASN1_OCTET_STRING(L, s)      openssl_push_asn1(L, (ASN1_STRING*)s,  V_ASN1_OCTET_STRING)
#define PUSH_ASN1_STRING(L, s)            openssl_push_asn1(L, (ASN1_STRING*)s, V_ASN1_UNDEF)

int openssl_push_xname_asobject(lua_State*L, X509_NAME* xname);
int openssl_push_bit_string_bitname(lua_State* L, const BIT_STRING_BITNAME* name);

STACK_OF(X509)* openssl_sk_x509_dup(STACK_OF(X509)* sk);
STACK_OF(X509_CRL)* openssl_sk_x509_crl_dup(STACK_OF(X509_CRL)* sk);

int openssl_get_nid(lua_State*L, int idx);
EC_GROUP* openssl_get_ec_group(lua_State* L, int ec_name_idx, int param_enc_idx,
  int conv_form_idx);

int openssl_register_xname(lua_State*L);
int openssl_register_xattribute(lua_State*L);
int openssl_register_xextension(lua_State*L);
int openssl_register_xstore(lua_State*L);
int openssl_register_xalgor(lua_State*L);
int openssl_sk_index(lua_State*L, int i, int num, int idx);

int openssl_pushresult(lua_State*L, int result);

int openssl_newvalue(lua_State*L, void*p);
int openssl_freevalue(lua_State*L, void*p);
int openssl_setvalue(lua_State*L, void*p, const char*field);
int openssl_getvalue(lua_State*L, void*p, const char*field);
int openssl_refrence(lua_State*L, void*p, int op);

int openssl_verify_cb(int preverify_ok, X509_STORE_CTX *xctx);
int openssl_cert_verify_cb(X509_STORE_CTX *xctx, void* u);
void openssl_xstore_free(X509_STORE* ctx);

STACK_OF(X509_ALGOR)* openssl_sk_x509_algor_dup(STACK_OF(X509_ALGOR)*);

#ifdef HAVE_USER_CUSTOME
#include HAVE_USER_CUSTOME
#endif
