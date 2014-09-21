/*=========================================================================*\
* xattrs.c
* x509 attributes routines for lua-openssl binding
*
* Author:  george zhao <zhaozg(at)gmail.com>
\*=========================================================================*/

#include "openssl.h"
#include "private.h"

#define MYNAME "x509.attribute"

static int openssl_xattr_totable(lua_State*L, X509_ATTRIBUTE *attr, int utf8) {
  lua_newtable(L);
  openssl_push_asn1object(L,attr->object);
  lua_setfield(L, -2, "object");

  AUXILIAR_SET(L, -1, "single", attr->single, boolean);
  if (attr->single)
  {
    openssl_push_asn1type(L, attr->value.single);
    lua_setfield(L, -2, "value");
  }else
  {
    int i;
    lua_newtable(L);
    for(i=0; i<sk_ASN1_TYPE_num(attr->value.set); i++){
      ASN1_TYPE* t = sk_ASN1_TYPE_value(attr->value.set, i);
      openssl_push_asn1type(L, t);
      lua_rawseti(L, -2, i+1);
    }
    lua_setfield(L, -2, "value");
  }
  return 1;
}

static int openssl_xattr_info(lua_State*L) {
  X509_ATTRIBUTE* attr = CHECK_OBJECT(1,X509_ATTRIBUTE, "openssl.x509_attribute");
  int utf8 = lua_isnoneornil(L, 2) ? 0 : lua_toboolean(L, 2);
  return openssl_xattr_totable(L, attr, utf8);
}

static int openssl_xattr_dup(lua_State*L) {
  X509_ATTRIBUTE* attr = CHECK_OBJECT(1,X509_ATTRIBUTE, "openssl.x509_attribute");
  X509_ATTRIBUTE* dup = X509_ATTRIBUTE_dup(attr);
  PUSH_OBJECT(dup,"openssl.x509_attribute");
  return 1;
}

static int openssl_xattr_free(lua_State*L) {
  X509_ATTRIBUTE* attr = CHECK_OBJECT(1,X509_ATTRIBUTE, "openssl.x509_attribute");
  lua_pushnil(L);
  lua_setmetatable(L, 1);
  X509_ATTRIBUTE_free(attr);
  return 0;
}

static luaL_Reg x509_attribute_funs[] =
{
  {"info",          openssl_xattr_info},
  {"dup",           openssl_xattr_dup},
  
  {"__gc",          openssl_xattr_free},
  {"__tostring",    auxiliar_tostring},

  { NULL, NULL }
};

static X509_ATTRIBUTE* openssl_new_xattribute(lua_State*L, X509_ATTRIBUTE** a, int idx, int utf8)
{
  int arttype;
  size_t len;
  int nid;
  const char* data;

  lua_getfield(L, idx, "object");
  nid = openssl_get_nid(L, -1);
  lua_pop(L, 1);

  lua_getfield(L, idx, "type");
  arttype = openssl_get_asn1type(L, -1);
  lua_pop(L, 1);

  lua_getfield(L, idx, "value");
  if(lua_isuserdata(L, -1))
  {
    ASN1_STRING* value = CHECK_OBJECT(-1, ASN1_STRING, "openssl.asn1_string");
    data = ASN1_STRING_data(value);
    len  = ASN1_STRING_length(value);
  }else
    data = luaL_checklstring(L, idx, &len);
  lua_pop(L, 1);

  return X509_ATTRIBUTE_create_by_NID(a, nid, arttype, data, len);
}


static int openssl_xattr_new(lua_State*L) {
  X509_ATTRIBUTE *x=NULL;
  int utf8;
  luaL_checktable(L,1);
  utf8 = lua_isnoneornil(L, 2) ? 1 : lua_toboolean(L, 2);

  x = openssl_new_xattribute(L, &x, 1, utf8);
  PUSH_OBJECT(x,"openssl.x509_attribute");
  return 1;
}

static luaL_Reg R[] =
{
  {"new",         openssl_xattr_new},

  {NULL,          NULL},
};

int openssl_register_xattribute(lua_State*L)
{
  auxiliar_newclass(L, "openssl.x509_attribute", x509_attribute_funs);
  luaL_register(L, MYNAME, R);
  return 0;
}

int openssl_push_xattrs_astable(lua_State*L, STACK_OF(X509_ATTRIBUTE) *attrs, int utf8)
{
  int i;
  int n = sk_X509_ATTRIBUTE_num(attrs);
  lua_newtable(L);

  for (i = 0; i < n; i++)
  {
    X509_ATTRIBUTE* attr = sk_X509_ATTRIBUTE_value(attrs, i);

    openssl_xattr_totable(L, attr, utf8);
    lua_rawseti(L, -2, i+1);
  };
  return 1;
};

int openssl_new_xattrs(lua_State*L, STACK_OF(X509_ATTRIBUTE) *attrs, int idx, int utf8)
{
  size_t i;
  luaL_checktable(L, idx);

  for(i=0; i<lua_rawlen(L, idx); i++)
  {
    X509_ATTRIBUTE* a = NULL;
    lua_rawgeti(L, idx, i+1);
    a = openssl_new_xattribute(L, &a, -1,utf8);
    if(a) {
      sk_X509_ATTRIBUTE_push(attrs,a);
    }
    lua_pop(L,1);
  }
  return 0;
}
