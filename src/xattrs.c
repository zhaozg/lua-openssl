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
  int utf8 = lua_isnoneornil(L, 2) ? 1 : lua_toboolean(L, 2);
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

static int openssl_xattr_data(lua_State*L) {
  X509_ATTRIBUTE* attr = CHECK_OBJECT(1,X509_ATTRIBUTE, "openssl.x509_attribute");
  if (lua_isnumber(L, 3)) {
    int idx = luaL_checkint(L, 2);
    int attrtype = openssl_get_asn1type(L, 3);
    ASN1_STRING *as = (ASN1_STRING *)X509_ATTRIBUTE_get0_data(attr, idx, attrtype,NULL);
    PUSH_OBJECT(ASN1_STRING_dup(as), "openssl.asn1_string");
    return 1;
  }else
  {
    int attrtype = openssl_get_asn1type(L, 2);
    size_t size;
    const char *data = luaL_checklstring(L,3, &size);
    int ret = X509_ATTRIBUTE_set1_data(attr,attrtype,data,size);
    return openssl_pushresult(L, ret);
  }
  return 0;
}

static int openssl_xattr_type(lua_State*L) {
  X509_ATTRIBUTE* attr = CHECK_OBJECT(1,X509_ATTRIBUTE, "openssl.x509_attribute");
  int loc = luaL_optint(L, 2, 0);
  ASN1_TYPE *type = X509_ATTRIBUTE_get0_type(attr, loc);
  if(type) {
    openssl_push_asn1type(L, type);;
    return 1;
  }else
    lua_pushnil(L);
  return 1;
}

static int openssl_xattr_object(lua_State*L) {
  X509_ATTRIBUTE* attr = CHECK_OBJECT(1,X509_ATTRIBUTE, "openssl.x509_attribute");
  int attrtype = luaL_checkint(L, 2);
  if(lua_isnone(L,3)){
    ASN1_OBJECT* obj = X509_ATTRIBUTE_get0_object(attr);
    PUSH_OBJECT(OBJ_nid2obj(obj->nid),"openssl.asn1_object");
    return 1;
  }else
  {
    ASN1_OBJECT* obj = CHECK_OBJECT(2,ASN1_OBJECT,"openssl.asn1_object");
    int ret = X509_ATTRIBUTE_set1_object(attr,obj);
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

static X509_ATTRIBUTE* openssl_new_xattribute(lua_State*L, X509_ATTRIBUTE** a, int idx)
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
  luaL_checktable(L,1);

  x = openssl_new_xattribute(L, &x, 1);
  PUSH_OBJECT(x,"openssl.x509_attribute");
  return 1;
}

static int openssl_new_xattrs(lua_State*L)
{
  size_t i;
  int idx = 1;
  STACK_OF(X509_ATTRIBUTE) *attrs  = sk_X509_ATTRIBUTE_new_null();
  luaL_checktable(L, idx);

  for(i=0; i<lua_rawlen(L, idx); i++)
  {
    X509_ATTRIBUTE* a = NULL;
    lua_rawgeti(L, idx, i+1);
    a = openssl_new_xattribute(L, &a, -1);
    if(a) {
      sk_X509_ATTRIBUTE_push(attrs,a);
    }
    lua_pop(L,1);
  }
  PUSH_OBJECT(attrs, "openssl.stack_of_x509_attribute");
  return 1;
}

static luaL_Reg R[] =
{
  {"new_attribute",         openssl_xattr_new},
  {"new_sk_attribute",      openssl_new_xattrs},
  
  {NULL,          NULL},
};

IMP_LUA_SK(X509_ATTRIBUTE, x509_attribute)

int openssl_register_xattribute(lua_State*L)
{
  auxiliar_newclass(L, "openssl.x509_attribute", x509_attribute_funs);
  openssl_register_sk_x509_attribute(L);
  luaL_register(L, MYNAME, R);
  return 1;
}
