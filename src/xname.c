/***
x509_name module for lua-openssl binding, provide x509_name as lua object
Sometime when you make CSR,TS or X509, you maybe need to use this.

@module x509.name
@usage
  name = require('openssl').x509.name
*/
#include "openssl.h"
#include "private.h"

#include "sk.h"

int openssl_push_xname_asobject(lua_State*L, X509_NAME* xname)
{
  const X509_NAME* dup = X509_NAME_dup(xname);
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
      ASN1_OBJECT *obj = openssl_get_asn1object(L, -2, 0);
      const char *value = luaL_checklstring(L, -1, &size);

      int ret = X509_NAME_add_entry_by_OBJ(xname, obj, utf8 ? MBSTRING_UTF8 : MBSTRING_ASC, (unsigned char*)value, (int)size, -1, 0);
      ASN1_OBJECT_free(obj);
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

/***
Create x509_name object

@function new
@tparam table array include name node
@tparam[opt] boolean utf8 encode will be use default
@treturn x509_name mapping to X509_EXTENSION in openssl
@usage
  name = require'openssl'.x509.name
  subject = name.new{
    {C='CN'},
    {O='kkhub.com'},
    {CN='zhaozg'}
  }
*/
static int openssl_xname_new(lua_State*L)
{
  X509_NAME* xn;
  int utf8;
  luaL_checktable(L, 1);
  utf8 = lua_isnone(L, 2) ? 1 : lua_toboolean(L, 2);
  xn = X509_NAME_new();
  openssl_new_xname(L, xn, 1, utf8);
  PUSH_OBJECT(xn, "openssl.x509_name");
  return 1;
};

/***
Create x509_name from der string

@function d2i
@tparam string content DER encoded string
@treturn x509_name mapping to X509_NAME in openssl
*/
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

/***
x509_name infomation table
other field is number type, and value table is alter name.(I not understand clearly)
@table x509_extension_info_table
@tfield asn1_object|object object of x509_name
@tfield boolean|critical true for critical value
@tfield string|value as octet string
*/

/***
openssl.x509_name object
@type x509_name
*/
static int openssl_xname_gc(lua_State* L)
{
  X509_NAME* xn = CHECK_OBJECT(1, X509_NAME, "openssl.x509_name");
  X509_NAME_free(xn);
  return 0;
}

/***
get oneline of x509_name.

@function oneline
@treturn string line, name as oneline text
*/
static int openssl_xname_oneline(lua_State*L)
{
  X509_NAME* xname = CHECK_OBJECT(1, X509_NAME, "openssl.x509_name");
  char* p = X509_NAME_oneline(xname, NULL, 0);

  lua_pushstring(L, p);
  OPENSSL_free(p);
  return 1;
};

/***
get hash code of x509_name

@function hash
@treturn integer hash hash code of x509_name
*/
static int openssl_xname_hash(lua_State*L)
{
  X509_NAME* xname = CHECK_OBJECT(1, X509_NAME, "openssl.x509_name");
  unsigned long hash = X509_NAME_hash(xname);
  lua_pushnumber(L, hash);
  return 1;
};

/***
get digest of x509_name

@function digest
@tparam string|nid|openssl.evp_md md method of digest
@treturn string digest digest value by given alg of x509_name
*/
static int openssl_xname_digest(lua_State*L)
{
  X509_NAME* xname = CHECK_OBJECT(1, X509_NAME, "openssl.x509_name");
  const EVP_MD* md = get_digest(L, 2, NULL);
  unsigned char buf [EVP_MAX_MD_SIZE];
  unsigned int len = sizeof(buf);

  int ret = X509_NAME_digest(xname, md, buf, &len);
  if (ret == 1)
    lua_pushlstring(L, (const char *) buf, len);
  else
    return openssl_pushresult(L, ret);
  return 1;
};

/***
print x509_name to bio object

@function print
@tparam openssl.bio out output bio object
@tparam[opt] integer indent for output
@tparam[opt] integer flags for output
@treturn boolean result, follow by error message
*/
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

static int openssl_push_xname_entry(lua_State* L, X509_NAME_ENTRY* ne, int obj)
{
  ASN1_OBJECT* object = X509_NAME_ENTRY_get_object(ne);
  ASN1_STRING* value = X509_NAME_ENTRY_get_data(ne);
  lua_newtable(L);
  if(obj)
  {
    openssl_push_asn1object(L, object);
    PUSH_ASN1_STRING(L, value);
  }
  else
  {
    lua_pushstring(L, OBJ_nid2sn(OBJ_obj2nid(object)));
    lua_pushlstring(L, (const char*)ASN1_STRING_get0_data(value), ASN1_STRING_length(value));
  }
  lua_settable(L, -3);
  return 1;
}

/***
return x509_name as table

@function info
@tparam[opt=false] boolean asobject table key will use asn1_object or short name of asn1_object
@treturn table names
@see new
*/
static int openssl_xname_info(lua_State*L)
{
  X509_NAME* name = CHECK_OBJECT(1, X509_NAME, "openssl.x509_name");
  int obj = lua_isnone(L, 2) ? 0 : lua_toboolean(L, 2);
  int i, n;
  lua_newtable(L);
  for (i = 0, n = X509_NAME_entry_count(name); i < n; i++)
  {
    X509_NAME_ENTRY* entry = X509_NAME_get_entry(name, i);
    openssl_push_xname_entry(L, entry, obj);
    lua_rawseti(L, -2, i + 1);
  }
  return 1;
};

/***
compare two x509_name

@function cmp
@tparam x509_name another to compare with
@treturn boolean result true for equal or false
@usage
  name1 = name.new({...})
  name2 = name1:dup()
  assert(name1:cmp(name2)==(name1==name2))
*/
static int openssl_xname_cmp(lua_State*L)
{
  X509_NAME* a = CHECK_OBJECT(1, X509_NAME, "openssl.x509_name");
  X509_NAME* b = CHECK_OBJECT(2, X509_NAME, "openssl.x509_name");
  int ret = X509_NAME_cmp(a, b);
  lua_pushboolean(L, ret == 0);
  return 1;
};

/***
make a clone of x509_name
@function dup
@treturn x509_name clone
*/
static int openssl_xname_dup(lua_State*L)
{
  X509_NAME* xn = CHECK_OBJECT(1, X509_NAME, "openssl.x509_name");
  X509_NAME* dup = X509_NAME_dup(xn);
  PUSH_OBJECT(dup, "openssl.x509_name");
  return 1;
};

/***
get DER encoded string of x509_name.

@function i2d
@treturn string der
*/
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

/***
get count in x509_name.

@function entry_count
@treturn integer count of x509_name
*/
static int openssl_xname_entry_count(lua_State*L)
{
  X509_NAME* xn = CHECK_OBJECT(1, X509_NAME, "openssl.x509_name");
  int len = X509_NAME_entry_count(xn);
  lua_pushinteger(L, len);
  return 1;
};

/***
get text by given asn1_object or nid

@function get_text
@tparam string|integer|asn1_object identid for asn1_object
@tparam[opt=-1] number lastpos retrieve the next index after lastpos
@treturn string text and followed by lastpos
*/
static int openssl_xname_get_text(lua_State*L)
{
  X509_NAME* xn = CHECK_OBJECT(1, X509_NAME, "openssl.x509_name");
  ASN1_OBJECT *obj = openssl_get_asn1object(L, 2, 0);
  int lastpos = luaL_optint(L, 3, -1);
  X509_NAME_ENTRY *e;
  ASN1_STRING *s;

  lastpos = X509_NAME_get_index_by_OBJ(xn, obj, lastpos);
  ASN1_OBJECT_free(obj);
  if (lastpos == -1)
    return 0;

  e = X509_NAME_get_entry(xn, lastpos);
  s = X509_NAME_ENTRY_get_data(e);
  lua_pushlstring(L, (const char *)ASN1_STRING_get0_data(s), ASN1_STRING_length(s));
  lua_pushinteger(L, lastpos);
  return 2;
};

/***
get x509 name entry by index
@function get_entry
@tparam integer index start from 0, and less than xn:entry_count()
@tparam[opt=false] boolean asobject table key will use asn1_object or short name of asn1_object
@treturn x509 name entry table
*/
static int openssl_xname_get_entry(lua_State*L)
{
  X509_NAME* xn = CHECK_OBJECT(1, X509_NAME, "openssl.x509_name");
  int lastpos = luaL_checkint(L, 2);
  int obj = lua_isnone(L, 3) ? 0 : lua_toboolean(L, 3);
  X509_NAME_ENTRY *e = X509_NAME_get_entry(xn, lastpos);
  if (e)
  {
    return openssl_push_xname_entry(L, e, obj);
  }
  return 0;
};

/***
add name entry

@function add_entry
@tparam string|integer|asn1_object identid for asn1_object
@tparam string data to add
@tparam[opt] boolean utf8 true for use utf8 default
@treturn boolean result true for success or follow by error message
*/
static int openssl_xname_add_entry(lua_State*L)
{
  X509_NAME* xn = CHECK_OBJECT(1, X509_NAME, "openssl.x509_name");
  ASN1_OBJECT *obj = openssl_get_asn1object(L, 2, 0);
  size_t size;
  const char*value = luaL_checklstring(L, 3, &size);
  int utf8 = lua_isnone(L, 4) ? 1 : lua_toboolean(L, 4);

  int ret = X509_NAME_add_entry_by_OBJ(xn, obj, utf8 ? MBSTRING_UTF8 : MBSTRING_ASC, (unsigned char*)value, (int)size, -1, 0);
  ASN1_OBJECT_free(obj);
  if (ret != 1)
  {
    luaL_error(L,  "%s=%s can't add to X509 name",  lua_tostring(L, 2), value);
  };
  return openssl_pushresult(L, ret);
};

/***
get index by give asn1_object or nid

@function delete_entry
@tparam integer location which name entry to delete
@treturn[1] asn1_object object that delete name entry
@treturn[1] asn1_string value that delete name entry
@treturn[2] nil delete nothing
*/
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

IMP_LUA_SK(X509_NAME, x509_name)

int openssl_register_xname(lua_State*L)
{
  auxiliar_newclass(L, "openssl.x509_name", xname_funcs);
  lua_newtable(L);
  luaL_setfuncs(L, R, 0);
  return 1;
}
