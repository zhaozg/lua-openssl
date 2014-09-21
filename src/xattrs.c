/*=========================================================================*\
* xattrs.c
* x509 attributes routines for lua-openssl binding
*
* Author:  george zhao <zhaozg(at)gmail.com>
\*=========================================================================*/

#include "openssl.h"
#include "private.h"

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

  {"__gc",          openssl_xattr_free},
  {"__tostring",    auxiliar_tostring},

  { NULL, NULL }
};

int openssl_register_xattribute(lua_State*L)
{
  auxiliar_newclass(L, "openssl.x509_attribute", x509_attribute_funs);
  return 0;
}

int openssl_push_x509_attrs(lua_State*L, STACK_OF(X509_ATTRIBUTE) *attrs, int utf8)
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

int XATTRS_from_ltable(lua_State*L,
  STACK_OF(X509_ATTRIBUTE) **attributes,
  int attr)
{
  /* table is in the stack at index 't' */
  lua_pushnil(L);  /* first key */
  while (lua_next(L, attr) != 0)
  {
    /* uses 'key' (at index -2) and 'value' (at index -1) */
    const char * strindex = lua_tostring(L, -2);
    const char * strval = lua_tostring(L, -1);

    if (strindex)
    {
      int nid = OBJ_txt2nid(strindex);
      if (nid != NID_undef)
      {
        if (!X509at_add1_attr_by_NID(attributes, nid,
          MBSTRING_ASC, (unsigned char*)strval, -1))
        {
          luaL_error(L, "attrib: X509at_add1_attr_by_NID %d(%s) -> %s (failed)", nid, strindex, strval);
        }
      }
      else
      {
        luaL_error(L, "attrib: %s is not a recognized name", strindex);
      }
    }
    /* removes 'value'; keeps 'key' for next iteration */
    lua_pop(L, 1);
  }
  return 0;
}
