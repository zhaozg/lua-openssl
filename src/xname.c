/*=========================================================================*\
* xname.c
* * x509 name routines for lua-openssl binding
*
* Author:  george zhao <zhaozg(at)gmail.com>
\*=========================================================================*/

#include "openssl.h"
#include "compat.h"
#include "private.h"

#define MYNAME "x509.name"

static int openssl_xname_gc(lua_State* L)
{
  X509_NAME* xn = CHECK_OBJECT(1, X509_NAME, "openssl.x509_name");
  lua_pushnil(L);
  lua_setmetatable(L,1);
  X509_NAME_free(xn);
  return 0;
}

static int openssl_xname_oneline(lua_State*L)
{
  X509_NAME* xname = CHECK_OBJECT(1, X509_NAME, "openssl.x509_name");
  char* p = X509_NAME_oneline(xname, NULL, 0);

  lua_pushstring(L, p);;
  OPENSSL_free(p);
  return 1;
};

int push_x509_name(lua_State* L, X509_NAME *name, int encode)
{
  int i;
  int n_entries;
  ASN1_OBJECT *object;
  X509_NAME_ENTRY *entry;
  lua_newtable(L);
  n_entries = X509_NAME_entry_count(name);
  for (i = 0; i < n_entries; i++) {
    entry = X509_NAME_get_entry(name, i);
    object = X509_NAME_ENTRY_get_object(entry);
    lua_newtable(L);
    openssl_push_asn1object(L, object);
    PUSH_ASN1_STRING(L, X509_NAME_ENTRY_get_data(entry), encode);
    lua_settable(L, -3);
    lua_rawseti(L, -2, i+1);
  }
  return 1;
}

static int openssl_xname_info(lua_State*L)
{
  X509_NAME* xn = CHECK_OBJECT(1, X509_NAME, "openssl.x509_name");
  int utf8 = lua_isnoneornil(L, 2) ? 1 : lua_toboolean(L, 2);
  return push_x509_name(L, xn, utf8);
};

static int openssl_xname_dup(lua_State*L)
{
  X509_NAME* xn = CHECK_OBJECT(1, X509_NAME, "openssl.x509_name");
  X509_NAME* dup = X509_NAME_dup(xn);
  PUSH_OBJECT(dup,"openssl.x509_name");
  return 1;
};

static luaL_Reg xname_funcs[] =
{
  {"oneline",           openssl_xname_oneline},
  {"info",              openssl_xname_info},
  {"dup",               openssl_xname_dup},

  {"__tostring",        openssl_xname_oneline},
  {"__gc",              openssl_xname_gc},

  {NULL,          NULL},
};

int openssl_push_xname(lua_State*L, X509_NAME* xname)
{
  X509_NAME* dup = X509_NAME_dup(xname);
  PUSH_OBJECT(dup,"openssl.x509_name");
  return 1;
}

int openssl_new_xname(lua_State*L, X509_NAME* xname, int idx, int utf8)
{
  int i,n;
  luaL_checktable(L, idx);
  luaL_argcheck(L, lua_istable(L,idx) && lua_objlen(L,idx)>0, idx,
    "must be not empty table as array");

  n = lua_objlen(L, idx);
  for (i=0; i<n; i++){
    size_t size;
    const char *key, *value;
    int nid = NID_undef;
    ASN1_OBJECT *obj;
    int ret;
    
    lua_rawgeti(L, idx, i+1);

    lua_pushnil(L);
    while (lua_next(L, -2) != 0) {
      key = luaL_checkstring(L, -2);
      value = luaL_checklstring(L, -1, &size);

      obj = OBJ_txt2obj(key, 0);
      if (!obj) {
        lua_pushfstring(L, "node at %d which key (%s) is not a valid object identity", 
          i+1, key);
        luaL_argerror(L, idx, lua_tostring(L, -1));
      }
      ret = X509_NAME_add_entry_by_OBJ(xname, obj, utf8? MBSTRING_UTF8 : MBSTRING_ASC, (unsigned char*)value, (int)size,-1, 0);
      ASN1_OBJECT_free(obj);
      if (ret!=1)
      {
        lua_pushfstring(L, "node at %d which  %s=%s can't add to X509 name", 
          i+1,key,value);
        luaL_argerror(L, idx, lua_tostring(L, -1));
      }
      lua_pop(L, 1);
    }
  }
  return 0;
}

static int openssl_xname_new(lua_State*L) {
  X509_NAME* xn;
  int utf8;
  luaL_checktable(L,1);
  utf8 = lua_isnoneornil(L, 2) ? 1 : lua_toboolean(L, 2);
  xn = X509_NAME_new();
  openssl_new_xname(L, xn, 1, utf8);
  PUSH_OBJECT(xn,"openssl.x509_name");
  return 1;
};

static luaL_Reg R[] =
{
  {"new",           openssl_xname_new},
                    
  {NULL,          NULL},
};

int openssl_register_xname(lua_State*L)
{
  auxiliar_newclass(L, "openssl.x509_name",xname_funcs);
  luaL_register(L, MYNAME, R);
  return 1;
}
