/*=========================================================================*\
* xalgor.c
* * x509_algor routines for lua-openssl binding
*
* Author:  george zhao <zhaozg(at)gmail.com>
\*=========================================================================*/

#include "openssl.h"
#include "private.h"
#include "sk.h"
IMP_LUA_SK(X509_ALGOR, x509_algor)

#define MYNAME "x509.algor"

static int openssl_xalgor_gc(lua_State* L)
{
  X509_ALGOR* alg = CHECK_OBJECT(1, X509_ALGOR, "openssl.x509_algor");
  X509_ALGOR_free(alg);
  return 0;
}

static int openssl_xalgor_dup(lua_State* L)
{
  X509_ALGOR* alg = CHECK_OBJECT(1, X509_ALGOR, "openssl.x509_algor");
  X509_ALGOR* ano = X509_ALGOR_dup(alg);
  PUSH_OBJECT(ano, "openssl.x509_algor");
  return 1;
}

#if OPENSSL_VERSION_NUMBER >= 0x10002000L
static int openssl_xalgor_cmp(lua_State* L)
{
  X509_ALGOR* alg = CHECK_OBJECT(1, X509_ALGOR, "openssl.x509_algor");
  X509_ALGOR* ano = CHECK_OBJECT(2, X509_ALGOR, "openssl.x509_algor");
  lua_pushboolean(L, X509_ALGOR_cmp(alg, ano) == 0);
  return 1;
}
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10001000L
static int openssl_xalgor_md(lua_State* L)
{
  X509_ALGOR* alg = CHECK_OBJECT(1, X509_ALGOR, "openssl.x509_algor");
  const EVP_MD* md = get_digest(L, 2);
  X509_ALGOR_set_md(alg, md);
  return 0;
}
#endif

static int openssl_xalgor_get(lua_State* L)
{
  int type;
  void* val;
  ASN1_OBJECT *obj;

  X509_ALGOR* alg = CHECK_OBJECT(1, X509_ALGOR, "openssl.x509_algor");

  X509_ALGOR_get0(&obj, &type, &val, alg);
  if (obj != NULL)
  {
    openssl_push_asn1object(L, obj);
  }
  else
    lua_pushnil(L);
  if (type == V_ASN1_UNDEF)
    lua_pushnil(L);
  else
  {
    PUSH_ASN1_STRING(L, val);
  }

  return 2;
}

static int openssl_xalgor_set(lua_State* L)
{
  int ret = 0;
  X509_ALGOR* alg = CHECK_OBJECT(1, X509_ALGOR, "openssl.x509_algor");
  ASN1_OBJECT* obj = CHECK_OBJECT(2, ASN1_OBJECT, "openssl.asn1_object");
  ASN1_STRING* val = lua_isnoneornil(L, 3) ?
                     NULL : auxiliar_checkgroup(L, "openssl.asn1_group", 3);
  obj = OBJ_dup(obj);
  val = ASN1_STRING_dup(val);
  ret = X509_ALGOR_set0(alg, obj , val->type, val);
  return openssl_pushresult(L, ret);
}

static int openssl_xalgor_tostring(lua_State* L)
{
  int type;
  void* val;
  ASN1_OBJECT *obj;

  X509_ALGOR* alg = CHECK_OBJECT(1, X509_ALGOR, "openssl.x509_algor");

  X509_ALGOR_get0(&obj, &type, &val, alg);
  if (obj != NULL)
  {
    luaL_Buffer B;
    luaL_buffinit(L, &B);

    luaL_addsize(&B, OBJ_obj2txt(luaL_prepbuffer(&B), LUAL_BUFFERSIZE, obj, 0));
    luaL_pushresult(&B);
    return 1;
  }
  return 0;
}

static luaL_Reg xalgor_funcs[] =
{
  {"dup",               openssl_xalgor_dup},
  {"set",               openssl_xalgor_set},
  {"get",               openssl_xalgor_get},
#if OPENSSL_VERSION_NUMBER >= 0x10001000L
  {"md",                openssl_xalgor_md},
#endif
  {"tostring",          openssl_xalgor_tostring},
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
  {"equals",            openssl_xalgor_cmp},
  {"__eq",              openssl_xalgor_cmp},
#endif
  {"__tostring",        auxiliar_tostring},
  {"__gc",              openssl_xalgor_gc},

  {NULL,          NULL},
};

static int openssl_xalgor_new(lua_State*L)
{
  X509_ALGOR* alg = X509_ALGOR_new();
  PUSH_OBJECT(alg, "openssl.x509_algor");
  return 1;
};

static luaL_Reg R[] =
{
  {"new",           openssl_xalgor_new},

  {NULL,          NULL},
};

int openssl_register_xalgor(lua_State*L)
{
  auxiliar_newclass(L, "openssl.x509_algor", xalgor_funcs);
  lua_newtable(L);
  luaL_setfuncs(L, R, 0);

  return 1;
}
