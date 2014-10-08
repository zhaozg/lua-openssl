/*=========================================================================*\
* xexts.c
* * x509 extension routines for lua-openssl binding
*
* Author:  george zhao <zhaozg(at)gmail.com>
\*=========================================================================*/

#include <ctype.h>
#include "openssl.h"
#include "private.h"
#include "sk.h"

#define MYNAME "x509.extension"

static int openssl_xext_totable(lua_State* L, X509_EXTENSION *x, int utf8)
{
  lua_newtable(L);
  openssl_push_asn1object(L, x->object);
  lua_setfield(L, -2, "object");

  PUSH_ASN1_OCTET_STRING(L, x->value);
  lua_setfield(L,-2, "value");

  AUXILIAR_SET(L, -1, "critical", x->critical, boolean);

  switch (x->object->nid) 
  {
  case NID_subject_alt_name:
    {
      int i;
      int n_general_names;
      
      STACK_OF(GENERAL_NAME) *values = X509V3_EXT_d2i(x);

      if (values == NULL)
        break;

       /* Push ret[oid] */
      openssl_push_asn1object(L, x->object);
      lua_newtable(L);
      n_general_names = sk_GENERAL_NAME_num(values);
      for (i = 0; i < n_general_names; i++) {
        GENERAL_NAME *general_name = sk_GENERAL_NAME_value(values, i);
        switch (general_name->type) {
        case GEN_OTHERNAME:
          {
          OTHERNAME *otherName = general_name->d.otherName;

          lua_newtable(L);
          openssl_push_asn1object(L, otherName->type_id);
          PUSH_ASN1_STRING(L, otherName->value->value.asn1_string, utf8);
          lua_settable(L, -3);
          lua_setfield(L, -2, "otherName");

          lua_pushstring(L, "otherName");
          lua_rawseti(L, -2, i+1);
          break;
          }
        case GEN_EMAIL:
          lua_newtable(L);
          PUSH_ASN1_STRING(L, general_name->d.rfc822Name, utf8);
          lua_pushstring(L, "rfc822Name");
          lua_settable(L, -3);

          lua_pushstring(L, "rfc822Name");
          lua_rawseti(L, -2, i+1);
          break;
        case GEN_DNS:
          lua_newtable(L);
          PUSH_ASN1_STRING(L, general_name->d.dNSName, utf8);
          lua_setfield(L, -2, "dNSName");
          lua_pushstring(L, "dNSName");
          lua_rawseti(L, -2, i+1);
          break;
        case GEN_X400:
          lua_newtable(L);
          openssl_push_asn1type(L, general_name->d.x400Address);
          lua_setfield(L, -2, "x400Address");
          lua_pushstring(L, "x400Address");
          lua_rawseti(L, -2, i+1);
          break;
        case GEN_DIRNAME:
          {
            X509_NAME* xn = general_name->d.directoryName;
            lua_newtable(L);
            openssl_push_xname_asobject(L, xn);
            lua_setfield(L, -2, "directoryName");
            lua_pushstring(L, "directoryName");
            lua_rawseti(L, -2, i+1);
          }
          break;
        case GEN_URI:
          lua_newtable(L);
          PUSH_ASN1_STRING(L, general_name->d.uniformResourceIdentifier, utf8);
          lua_setfield(L, -2, "uniformResourceIdentifier");
          lua_pushstring(L, "uniformResourceIdentifier");
          lua_rawseti(L, -2, i+1);
          break;
        case GEN_IPADD:
          lua_newtable(L);
          PUSH_ASN1_OCTET_STRING(L, general_name->d.iPAddress);
          lua_setfield(L, -2, "iPAddress");
          lua_pushstring(L, "iPAddress");
          lua_rawseti(L, -2, i+1);
          break;
        case GEN_EDIPARTY:
          lua_newtable(L);
          lua_newtable(L);
          PUSH_ASN1_STRING(L, general_name->d.ediPartyName->nameAssigner,utf8);
          lua_setfield(L, -2, "nameAssigner");
          PUSH_ASN1_STRING(L, general_name->d.ediPartyName->partyName,utf8);
          lua_setfield(L, -2, "partyName");
          lua_setfield(L, -2, "ediPartyName");

          lua_pushstring(L, "ediPartyName");
          lua_rawseti(L, -2, i+1);
          break;
        case GEN_RID:
          lua_newtable(L);
          openssl_push_asn1object(L, general_name->d.registeredID);
          lua_setfield(L, -2, "registeredID");
          lua_pushstring(L, "registeredID");
          lua_rawseti(L, -2, i+1);
          break;
        }
       }
      lua_settable(L, -3);
    }
  default:
    break;
  }
  return 1;
};

static int openssl_xext_info(lua_State* L)
{
  X509_EXTENSION *x = CHECK_OBJECT(1, X509_EXTENSION, "openssl.x509_extension");
  int utf8 = lua_isnoneornil(L, 2) ? 1 : lua_toboolean(L, 2);
  return openssl_xext_totable(L,x,utf8);
};

static int openssl_xext_dup(lua_State* L)
{
  X509_EXTENSION *x = CHECK_OBJECT(1, X509_EXTENSION, "openssl.x509_extension");
  X509_EXTENSION *d = X509_EXTENSION_dup(x);
  PUSH_OBJECT(d, "openssl.x509_extension");
  return 1;
};

static int openssl_xext_free(lua_State* L)
{
  X509_EXTENSION *x = CHECK_OBJECT(1, X509_EXTENSION, "openssl.x509_extension");
  lua_pushnil(L);
  lua_setmetatable(L, 1);
  X509_EXTENSION_free(x);
  return 0;
};

static int openssl_xext_object(lua_State* L)
{
  X509_EXTENSION *x = CHECK_OBJECT(1, X509_EXTENSION, "openssl.x509_extension");
  ASN1_OBJECT* obj;
  if(lua_isnone(L, 2)){
    obj = X509_EXTENSION_get_object(x);
    PUSH_OBJECT(OBJ_nid2obj(obj->nid), "openssl.asn1_object");
    return 1;
  } else {
    int nid = openssl_get_nid(L, 2);
    int ret;
    obj = OBJ_nid2obj(nid);
    ret = X509_EXTENSION_set_object(x, obj);
    return openssl_pushresult(L, ret);
  }
};

static int openssl_xext_critical(lua_State* L)
{
  X509_EXTENSION *x = CHECK_OBJECT(1, X509_EXTENSION, "openssl.x509_extension");
  if(lua_isnone(L, 2)){
    lua_pushboolean(L, X509_EXTENSION_get_critical(x));
    return 1;
  } else {
    int ret = X509_EXTENSION_set_critical(x, lua_toboolean(L, 2));
    return openssl_pushresult(L, ret);
  }
};

static int openssl_xext_data(lua_State* L)
{
  int ret = 0;
  X509_EXTENSION *x = CHECK_OBJECT(1, X509_EXTENSION, "openssl.x509_extension");
  if(lua_isnone(L, 2)){
    ASN1_STRING *s = X509_EXTENSION_get_data(x);
    PUSH_OBJECT(ASN1_STRING_dup(s),"openssl.asn1_string");
    return 1;
  } else if(lua_isstring(L, 2)) {
    size_t size;
    const char* data = lua_tolstring(L, 2, &size);
    ASN1_STRING* s = ASN1_STRING_type_new(V_ASN1_OCTET_STRING);
    if(ASN1_STRING_set(s, data, size)==1)
    {
      ret = X509_EXTENSION_set_data(x, s);
    }
    ASN1_STRING_free(s);
    return openssl_pushresult(L, ret);
  } else {
    ASN1_STRING *s = CHECK_OBJECT(2, ASN1_STRING, "openssl.asn1_string");
    if(ASN1_STRING_type(s)==V_ASN1_OCTET_STRING)
    {
      int ret;
      ret = X509_EXTENSION_set_data(x, s);
      return openssl_pushresult(L, ret);
    }else{
      luaL_argerror(L,2,"asn1_string type must be octet");
    }
  }
  return 0;
};

static luaL_Reg x509_extension_funs[] =
{
  {"info",          openssl_xext_info},
  {"dup",           openssl_xext_dup},

  /* set and get */
  {"object",        openssl_xext_object},
  {"critical",      openssl_xext_critical},
  {"data",          openssl_xext_data},

  {"__gc",          openssl_xext_free},
  {"__tostring",    auxiliar_tostring},

  { NULL, NULL }
};

static X509_EXTENSION* openssl_new_xextension(lua_State*L, X509_EXTENSION** x, int idx, int utf8)
{
  int nid;
  int critical = 0;
  ASN1_OCTET_STRING* value;

  lua_getfield(L, idx, "object");
  nid = openssl_get_nid(L, -1);
  lua_pop(L, 1);

  lua_getfield(L, idx, "critical");
  critical = lua_isnil(L,-1) ? 0 : lua_toboolean(L, -1);
  lua_pop(L, 1);

  if (nid==NID_undef) {
    lua_pushfstring(L, "%s is not valid object id",lua_tostring(L, -1));
    luaL_argerror(L, idx, lua_tostring(L,-1));
  }
  lua_getfield(L, idx, "value");
  
  luaL_argcheck(L, lua_isstring(L, -1) || auxiliar_isclass(L,"openssl.asn1_string", -1),
    1, "field value must be string or openssl.asn1_string object");
  if(lua_isstring(L, -1)) {
    size_t size;
    const char* data = lua_tolstring(L, -1, &size);
    X509_EXTENSION* y;
    value = ASN1_STRING_type_new(V_ASN1_OCTET_STRING);
    ASN1_STRING_set(value,data, size);
    y = X509_EXTENSION_create_by_NID(x, nid, critical, value);
    ASN1_STRING_free(value);
    return y;
  }else
  {
    value = CHECK_OBJECT(-1, ASN1_STRING, "openssl.asn1_string");
    lua_pop(L, 1);
    luaL_argcheck(L, ASN1_STRING_type(value)==V_ASN1_OCTET_STRING, 1,"field value must be octet type openssl.asn1_string");
    return X509_EXTENSION_create_by_NID(x, nid, critical, value);
  }
}

static int openssl_xext_new(lua_State* L)
{
  X509_EXTENSION *x=NULL;
  int utf8;
  luaL_checktable(L,1);
  utf8 = lua_isnoneornil(L, 2) ? 1 : lua_toboolean(L, 2);

  x = openssl_new_xextension(L, &x, 1, utf8);
  PUSH_OBJECT(x,"openssl.x509_extension");
  return 1;
};

static int openssl_xext_new_sk(lua_State* L)
{
  size_t i;
  X509_EXTENSION *x=NULL;
  STACK_OF(X509_EXTENSION) *exts;
  int utf8 = lua_isnoneornil(L, 2) ? 1 : lua_toboolean(L, 2);
  
  luaL_checktable(L,1);
  exts = sk_X509_EXTENSION_new_null();

  for (i=0; i<lua_objlen(L, 1); i++)
  {
    lua_rawgeti(L,1, i+1);
    x = openssl_new_xextension(L, NULL, lua_gettop(L), utf8);
    sk_X509_EXTENSION_push(exts, x);
  }
  PUSH_OBJECT(exts, "openssl.stack_of_x509_extension");
  return 1;
};


static int openssl_xexts_totable(lua_State*L)
{
  STACK_OF(X509_EXTENSION) *exts = CHECK_OBJECT(1, STACK_OF(X509_EXTENSION), "openssl.stack_of_x509_extension");
  int utf8 = lua_isnoneornil(L, 2) ? 1 : lua_toboolean(L, 2);
  int i;
  int n = sk_X509_EXTENSION_num(exts);
  lua_newtable(L);

  for (i = 0; i < n; i++)
  {
    X509_EXTENSION* ext = sk_X509_EXTENSION_value(exts, i);

    openssl_xext_totable(L, ext, utf8);
    lua_rawseti(L, -2, i+1);
  };
  return 1;
}

static luaL_Reg R[] =
{
  {"new_extension",           openssl_xext_new},
  {"new_sk_extension",        openssl_xext_new_sk},
  {"sktotable",               openssl_xexts_totable},

  {NULL,          NULL},
};

IMP_LUA_SK(X509_EXTENSION, x509_extension)

int openssl_register_xextension(lua_State*L)
{
  auxiliar_newclass(L, "openssl.x509_extension", x509_extension_funs);
  openssl_register_sk_x509_extension(L);
  luaL_register(L, MYNAME, R);
  return 1;
}
