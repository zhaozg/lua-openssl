/*=========================================================================*\
* xattrs.c
* x509 attributes routines for lua-openssl binding
*
* Author:  george zhao <zhaozg(at)gmail.com>
\*=========================================================================*/

#include "openssl.h"
#include "private.h"
#include "sk.h"

#define MYNAME "x509.attribute"

static int openssl_xattr_totable(lua_State*L, X509_ATTRIBUTE *attr)
{
  lua_newtable(L);
  openssl_push_asn1object(L, attr->object);
  lua_setfield(L, -2, "object");

  AUXILIAR_SET(L, -1, "single", attr->single, boolean);
  if (attr->single)
  {
    openssl_push_asn1type(L, attr->value.single);
    lua_setfield(L, -2, "value");
  }
  else
  {
    int i;
    lua_newtable(L);
    for (i = 0; i < sk_ASN1_TYPE_num(attr->value.set); i++)
    {
      ASN1_TYPE* t = sk_ASN1_TYPE_value(attr->value.set, i);
      openssl_push_asn1type(L, t);
      lua_rawseti(L, -2, i + 1);
    }
    lua_setfield(L, -2, "value");
  }
  return 1;
}

static int openssl_xattr_info(lua_State*L)
{
  X509_ATTRIBUTE* attr = CHECK_OBJECT(1, X509_ATTRIBUTE, "openssl.x509_attribute");
  return openssl_xattr_totable(L, attr);
}

static int openssl_xattr_dup(lua_State*L)
{
  X509_ATTRIBUTE* attr = CHECK_OBJECT(1, X509_ATTRIBUTE, "openssl.x509_attribute");
  X509_ATTRIBUTE* dup = X509_ATTRIBUTE_dup(attr);
  PUSH_OBJECT(dup, "openssl.x509_attribute");
  return 1;
}

static int openssl_xattr_free(lua_State*L)
{
  X509_ATTRIBUTE* attr = CHECK_OBJECT(1, X509_ATTRIBUTE, "openssl.x509_attribute");
  X509_ATTRIBUTE_free(attr);
  return 0;
}

static int openssl_xattr_data(lua_State*L)
{
  X509_ATTRIBUTE* attr = CHECK_OBJECT(1, X509_ATTRIBUTE, "openssl.x509_attribute");
  if (lua_type(L, 2) == LUA_TSTRING)
  {
    int attrtype = luaL_checkint(L, 2);
    size_t size;
    int ret;
    const char *data = luaL_checklstring(L, 3, &size);
    if (attr->single)
      ASN1_TYPE_free((ASN1_TYPE*)attr->value.ptr);
    else
      sk_ASN1_TYPE_pop_free(attr->value.set, ASN1_TYPE_free);
    attr->value.ptr = NULL;

    ret = X509_ATTRIBUTE_set1_data(attr, attrtype, data, size);
    return openssl_pushresult(L, ret);
  }
  else
  {
    int idx = luaL_checkint(L, 2);
    int attrtype = luaL_checkint(L, 3);
    ASN1_STRING *as = (ASN1_STRING *)X509_ATTRIBUTE_get0_data(attr, idx, attrtype, NULL);
    PUSH_ASN1_STRING(L, as);
    return 1;
  }
}

static int openssl_xattr_type(lua_State*L)
{
  X509_ATTRIBUTE* attr = CHECK_OBJECT(1, X509_ATTRIBUTE, "openssl.x509_attribute");
  int loc = luaL_optint(L, 2, 0);
  ASN1_TYPE *type = X509_ATTRIBUTE_get0_type(attr, loc);
  if (type)
  {
    openssl_push_asn1type(L, type);;
    return 1;
  }
  else
    lua_pushnil(L);
  return 1;
}

static int openssl_xattr_object(lua_State*L)
{
  X509_ATTRIBUTE* attr = CHECK_OBJECT(1, X509_ATTRIBUTE, "openssl.x509_attribute");
  if (lua_isnone(L, 2))
  {
    ASN1_OBJECT* obj = X509_ATTRIBUTE_get0_object(attr);
    openssl_push_asn1object(L, obj);
    return 1;
  }
  else
  {
    int nid = openssl_get_nid(L, 2);
    ASN1_OBJECT* obj;
    int ret;
    luaL_argcheck(L, nid != NID_undef, 2, "invalid asn1_object identity");
    obj = OBJ_nid2obj(nid);
    ret = X509_ATTRIBUTE_set1_object(attr, obj);
    return openssl_pushresult(L, ret);
  }
}

static luaL_Reg x509_attribute_funs[] =
{
  {"info",          openssl_xattr_info},
  {"dup",           openssl_xattr_dup},
  /* set or get */
  {"data",          openssl_xattr_data},
  {"type",          openssl_xattr_type},
  {"object",        openssl_xattr_object},

  {"__gc",          openssl_xattr_free},
  {"__tostring",    auxiliar_tostring},

  { NULL, NULL }
};

X509_ATTRIBUTE* openssl_new_xattribute(lua_State*L, X509_ATTRIBUTE** a, int idx, const char* eprefix)
{
  int arttype;
  size_t len = 0;
  int nid;
  const char* data = NULL;

  lua_getfield(L, idx, "object");
  nid = openssl_get_nid(L, -1);
  if (nid == NID_undef)
  {
    if (eprefix)
    {
      luaL_error(L, "%s field object is invalid value", eprefix);
    }
    else
      luaL_argcheck(L, nid != NID_undef, idx, "field object is invalid value");
  }
  lua_pop(L, 1);

  lua_getfield(L, idx, "type");
  arttype = luaL_checkint(L, -1);
  if (arttype == V_ASN1_UNDEF || arttype == 0)
  {
    if (eprefix)
    {
      luaL_error(L, "%s field type is not invalid value", eprefix);
    }
    else
      luaL_argcheck(L, nid != NID_undef, idx, "field type is not invalid value");
  }
  lua_pop(L, 1);

  lua_getfield(L, idx, "value");
  if (lua_isstring(L, -1))
  {
    data = lua_tolstring(L, -1, &len);
  }
  else if (auxiliar_isgroup(L, "openssl.asn1group", -1))
  {
    ASN1_STRING* value = CHECK_GROUP(-1, ASN1_STRING, "openssl.asn1group");
    if (ASN1_STRING_type(value) != arttype)
    {
      if (eprefix)
        luaL_error(L, "%s field value not match type", eprefix);
      else
        luaL_argcheck(L, ASN1_STRING_type(value) == arttype, idx, "field value not match type");
    }
    data = (const char *)ASN1_STRING_data(value);
    len  = ASN1_STRING_length(value);
  }
  else
  {
    if (eprefix)
    {
      luaL_error(L, "%s filed value only accept string or asn1_string", eprefix);
    }
    else
      luaL_argerror(L, idx, "filed value only accept string or asn1_string");
  }
  lua_pop(L, 1);
  if (data)
    return X509_ATTRIBUTE_create_by_NID(a, nid, arttype, data, len);
  return 0;
}


static int openssl_xattr_new(lua_State*L)
{
  X509_ATTRIBUTE *x = NULL;
  luaL_checktable(L, 1);

  x = openssl_new_xattribute(L, &x, 1, NULL);
  PUSH_OBJECT(x, "openssl.x509_attribute");
  return 1;
}

static luaL_Reg R[] =
{
  {"new_attribute",         openssl_xattr_new},

  {NULL,          NULL},
};

IMP_LUA_SK(X509_ATTRIBUTE, x509_attribute)

int openssl_register_xattribute(lua_State*L)
{
  auxiliar_newclass(L, "openssl.x509_attribute", x509_attribute_funs);
  lua_newtable(L);
  luaL_setfuncs(L, R, 0);
  return 1;
}
