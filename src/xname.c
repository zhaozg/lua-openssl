/*=========================================================================*\
* xname.c
* * x509 name routines for lua-openssl binding
*
* Author:  george zhao <zhaozg(at)gmail.com>
\*=========================================================================*/

#include "openssl.h"
#include "private.h"

#include "sk.h"

#define MYNAME "x509.name"

static int openssl_xname_gc(lua_State* L)
{
  X509_NAME* xn = CHECK_OBJECT(1, X509_NAME, "openssl.x509_name");
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

static int openssl_xname_hash(lua_State*L)
{
  X509_NAME* xname = CHECK_OBJECT(1, X509_NAME, "openssl.x509_name");
  unsigned long hash = X509_NAME_hash(xname);
  lua_pushnumber(L, hash);
  return 1;
};

static int openssl_xname_digest(lua_State*L)
{
  X509_NAME* xname = CHECK_OBJECT(1, X509_NAME, "openssl.x509_name");
  const EVP_MD* md = get_digest(L, 2);
  unsigned char buf [EVP_MAX_MD_SIZE];
  unsigned int len = sizeof(buf);

  int ret = X509_NAME_digest(xname, md, buf, &len);
  if (ret == 1)
    lua_pushlstring(L, (const char *) buf, len);
  else
    return openssl_pushresult(L, ret);
  return 1;
};

static int openssl_xname_print(lua_State*L)
{
  X509_NAME* xname = CHECK_OBJECT(1, X509_NAME, "openssl.x509_name");
  BIO* bio = load_bio_object(L, 2);
  int indent = luaL_optint(L, 3, 0);
  unsigned long flags = luaL_optinteger(L, 4, 0);

  int ret = X509_NAME_print_ex(bio, xname, indent, flags);
  BIO_free(bio);
  if (ret == 1)
    lua_pushboolean(L, 1);
  else
    return openssl_pushresult(L, ret);
  return 1;
};

static int openssl_push_xname_entry(lua_State* L, X509_NAME_ENTRY* ne)
{
  ASN1_OBJECT* object = X509_NAME_ENTRY_get_object(ne);
  ASN1_STRING *s;
  lua_newtable(L);
  openssl_push_asn1object(L, object);
  s = X509_NAME_ENTRY_get_data(ne);
  PUSH_ASN1_STRING(L, s);
  lua_settable(L, -3);
  return 1;
}

static int openssl_xname_info(lua_State*L)
{
  X509_NAME* name = CHECK_OBJECT(1, X509_NAME, "openssl.x509_name");
  int i;
  int n_entries = X509_NAME_entry_count(name);
  lua_newtable(L);
  for (i = 0; i < n_entries; i++)
  {
    X509_NAME_ENTRY* entry = X509_NAME_get_entry(name, i);
    openssl_push_xname_entry(L, entry);
    lua_rawseti(L, -2, i + 1);
  }
  return 1;
};

static int openssl_xname_cmp(lua_State*L)
{
  X509_NAME* a = CHECK_OBJECT(1, X509_NAME, "openssl.x509_name");
  X509_NAME* b = CHECK_OBJECT(2, X509_NAME, "openssl.x509_name");
  int ret = X509_NAME_cmp(a, b);
  lua_pushboolean(L, ret == 0);
  return 1;
};

static int openssl_xname_dup(lua_State*L)
{
  X509_NAME* xn = CHECK_OBJECT(1, X509_NAME, "openssl.x509_name");
  X509_NAME* dup = X509_NAME_dup(xn);
  PUSH_OBJECT(dup, "openssl.x509_name");
  return 1;
};

static int openssl_xname_i2d(lua_State*L)
{
  X509_NAME* xn = CHECK_OBJECT(1, X509_NAME, "openssl.x509_name");
  unsigned char* out = NULL;
  int len = i2d_X509_NAME(xn, &out);
  if (len > 0)
  {
    lua_pushlstring(L, (const char *)out, len);
    OPENSSL_free(out);
    return 1;
  }
  else
    return openssl_pushresult(L, len);
};

static int openssl_xname_entry_count(lua_State*L)
{
  X509_NAME* xn = CHECK_OBJECT(1, X509_NAME, "openssl.x509_name");
  int len = X509_NAME_entry_count(xn);
  lua_pushinteger(L, len);
  return 1;
};

static int openssl_xname_get_text(lua_State*L)
{
  X509_NAME* xn = CHECK_OBJECT(1, X509_NAME, "openssl.x509_name");
  int nid = openssl_get_nid(L, 2);
  int lastpos = luaL_optint(L, 3, -1);
  X509_NAME_ENTRY *e;
  ASN1_STRING *s;
  if (nid == NID_undef)
    return 0;

  lastpos = X509_NAME_get_index_by_NID(xn, nid, lastpos);
  if (lastpos == -1)
    return 0;

  e = X509_NAME_get_entry(xn, lastpos);
  s = X509_NAME_ENTRY_get_data(e);
  lua_pushlstring(L, (const char *)ASN1_STRING_data(s), ASN1_STRING_length(s));
  lua_pushinteger(L, lastpos);
  return 2;
};

static int openssl_xname_get_entry(lua_State*L)
{
  X509_NAME* xn = CHECK_OBJECT(1, X509_NAME, "openssl.x509_name");
  int lastpos = luaL_checkint(L, 2);
  X509_NAME_ENTRY *e = X509_NAME_get_entry(xn, lastpos);
  if (e)
  {
    return openssl_push_xname_entry(L, e);
  }
  return 0;
};

static int openssl_xname_add_entry(lua_State*L)
{
  X509_NAME* xn = CHECK_OBJECT(1, X509_NAME, "openssl.x509_name");
  int nid = openssl_get_nid(L, 2);
  size_t size;
  const char*value = luaL_checklstring(L, 3, &size);
  int utf8 = lua_isnoneornil(L, 4) ? 1 : lua_toboolean(L, 4);
  int ret;
  if (nid == NID_undef)
  {
    lua_pushfstring(L, "(%s) is not a valid object identity",  lua_tostring(L, 2));
    luaL_argerror(L, 2, lua_tostring(L, -1));
  }
  ret = X509_NAME_add_entry_by_NID(xn, nid, utf8 ? MBSTRING_UTF8 : MBSTRING_ASC, (unsigned char*)value, (int)size, -1, 0);
  if (ret != 1)
  {
    luaL_error(L,  "%s=%s can't add to X509 name",  lua_tostring(L, 2), value);
  };
  return openssl_pushresult(L, ret);
};

static int openssl_xname_delete_entry(lua_State*L)
{
  X509_NAME* xn = CHECK_OBJECT(1, X509_NAME, "openssl.x509_name");
  int loc = luaL_checkint(L, 2);

  X509_NAME_ENTRY *xe = X509_NAME_delete_entry(xn, loc);
  if (xe)
  {
    openssl_push_asn1object(L, X509_NAME_ENTRY_get_object(xe));
    PUSH_ASN1_STRING(L, X509_NAME_ENTRY_get_data(xe));
    X509_NAME_ENTRY_free(xe);
    return 2;
  }
  else
    lua_pushnil(L);

  return 1;
};

static luaL_Reg xname_funcs[] =
{
  {"oneline",           openssl_xname_oneline},
  {"hash",              openssl_xname_hash},
  {"digest",            openssl_xname_digest},
  {"print",             openssl_xname_print},
  {"info",              openssl_xname_info},
  {"dup",               openssl_xname_dup},
  {"i2d",               openssl_xname_i2d},
  {"entry_count",       openssl_xname_entry_count},
  {"get_text",          openssl_xname_get_text},
  {"get_entry",         openssl_xname_get_entry},
  {"add_entry",         openssl_xname_add_entry},
  {"delete_entry",      openssl_xname_delete_entry},
  {"cmp",               openssl_xname_cmp},
  {"tostring",          openssl_xname_oneline},

  {"__eq",              openssl_xname_cmp},
  {"__len",             openssl_xname_entry_count},
  {"__tostring",        auxiliar_tostring},
  {"__gc",              openssl_xname_gc},

  {NULL,          NULL},
};

int openssl_push_xname_asobject(lua_State*L, X509_NAME* xname)
{
  X509_NAME* dup = X509_NAME_dup(xname);
  PUSH_OBJECT(dup, "openssl.x509_name");
  return 1;
}

static int openssl_new_xname(lua_State*L, X509_NAME* xname, int idx, int utf8)
{
  int i, n;
  luaL_checktable(L, idx);
  luaL_argcheck(L, lua_istable(L, idx) && lua_rawlen(L, idx) > 0, idx,
                "must be not empty table as array");

  n = lua_rawlen(L, idx);
  for (i = 0; i < n; i++)
  {
    lua_rawgeti(L, idx, i + 1);
    lua_pushnil(L);

    while (lua_next(L, -2) != 0)
    {
      size_t size;
      const char *value;
      int ret;
      int nid = openssl_get_nid(L, -2);
      value = luaL_checklstring(L, -1, &size);

      if (nid == NID_undef)
      {
        lua_pushfstring(L, "node at %d which key (%s) is not a valid object identity",
                        i + 1, lua_tostring(L, -2));
        luaL_argerror(L, idx, lua_tostring(L, -1));
      }
      ret = X509_NAME_add_entry_by_NID(xname, nid, utf8 ? MBSTRING_UTF8 : MBSTRING_ASC, (unsigned char*)value, (int)size, -1, 0);
      if (ret != 1)
      {
        lua_pushfstring(L, "node at %d which  %s=%s can't add to X509 name",
                        i + 1, lua_tostring(L, -2), value);
        luaL_argerror(L, idx, lua_tostring(L, -1));
      }
      lua_pop(L, 1);
    }
  }
  return 0;
}

static int openssl_xname_new(lua_State*L)
{
  X509_NAME* xn;
  int utf8;
  luaL_checktable(L, 1);
  utf8 = lua_isnoneornil(L, 2) ? 1 : lua_toboolean(L, 2);
  xn = X509_NAME_new();
  openssl_new_xname(L, xn, 1, utf8);
  PUSH_OBJECT(xn, "openssl.x509_name");
  return 1;
};

static int openssl_xname_d2i(lua_State*L)
{
  size_t len;
  const unsigned char* dat = (const unsigned char*)luaL_checklstring(L, 1, &len);
  X509_NAME* xn = d2i_X509_NAME(NULL, &dat, len);
  if (xn)
    PUSH_OBJECT(xn, "openssl.x509_name");
  else
    openssl_pushresult(L, 0);
  return 1;
};

static luaL_Reg R[] =
{
  {"new",           openssl_xname_new},
  {"d2i",           openssl_xname_d2i},

  {NULL,          NULL},
};

IMP_LUA_SK(X509_NAME, x509_name)

int openssl_register_xname(lua_State*L)
{
  auxiliar_newclass(L, "openssl.x509_name", xname_funcs);
  lua_newtable(L);
  luaL_setfuncs(L, R, 0);
  return 1;
}
