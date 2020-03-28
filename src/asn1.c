/***
openssl.asn1 module for lua-openssl binding.
Provide asn1\_object, asn1\_string, asn1\_object as lua object.
Sometime when you want to custome x509, you maybe need to use this.

@module asn1
@usage
  asn1 = require('openssl').asn1
*/

#include "openssl.h"
#include "private.h"
#include <openssl/asn1.h>

#ifdef WIN32
#define timezone _timezone
#endif

static LuaL_Enumeration asn1_const[] =
{
  /* 0 */
  {"UNIVERSAL",         V_ASN1_UNIVERSAL},
  {"APPLICATION",       V_ASN1_APPLICATION},
  {"CONTEXT_SPECIFIC",  V_ASN1_CONTEXT_SPECIFIC},
  {"PRIVATE",           V_ASN1_PRIVATE},
  /* 4 */
  {"CONSTRUCTED",       V_ASN1_CONSTRUCTED},
  {"PRIMITIVE_TAG",     V_ASN1_PRIMITIVE_TAG},
  {"PRIMATIVE_TAG",     V_ASN1_PRIMATIVE_TAG},
  {"APP_CHOOSE",        V_ASN1_APP_CHOOSE},
  {"OTHER",             V_ASN1_OTHER},
  {"ANY",               V_ASN1_ANY},

  {"NEG",               V_ASN1_NEG},
  /* 11 */

  {"UNDEF",             V_ASN1_UNDEF},
  {"EOC",               V_ASN1_EOC},
  {"BOOLEAN",           V_ASN1_BOOLEAN},
  {"INTEGER",           V_ASN1_INTEGER},
  {"NEG_INTEGER",       V_ASN1_NEG_INTEGER},
  {"BIT_STRING",        V_ASN1_BIT_STRING},
  {"OCTET_STRING",      V_ASN1_OCTET_STRING},
  {"NULL",              V_ASN1_NULL},
  {"OBJECT",            V_ASN1_OBJECT},
  {"OBJECT_DESCRIPTOR", V_ASN1_OBJECT_DESCRIPTOR},
  {"EXTERNAL",          V_ASN1_EXTERNAL},
  {"REAL",              V_ASN1_REAL},
  {"ENUMERATED",        V_ASN1_ENUMERATED},
  {"NEG_ENUMERATED",    V_ASN1_NEG_ENUMERATED},
  {"UTF8STRING",        V_ASN1_UTF8STRING},
  {"SEQUENCE",          V_ASN1_SEQUENCE},
  {"SET",               V_ASN1_SET},
  {"NUMERICSTRING",     V_ASN1_NUMERICSTRING},
  {"PRINTABLESTRING",   V_ASN1_PRINTABLESTRING},
  {"T61STRING",         V_ASN1_T61STRING},
  {"TELETEXSTRING",     V_ASN1_TELETEXSTRING},
  {"VIDEOTEXSTRING",    V_ASN1_VIDEOTEXSTRING},
  {"IA5STRING",         V_ASN1_IA5STRING},
  {"UTCTIME",           V_ASN1_UTCTIME},
  {"GENERALIZEDTIME",   V_ASN1_GENERALIZEDTIME},

  {"GRAPHICSTRING",     V_ASN1_GRAPHICSTRING},
  {"ISO64STRING",       V_ASN1_ISO64STRING},
  {"VISIBLESTRING",     V_ASN1_VISIBLESTRING},
  {"GENERALSTRING",     V_ASN1_GENERALSTRING},
  {"UNIVERSALSTRING",   V_ASN1_UNIVERSALSTRING},
  {"BMPSTRING",         V_ASN1_BMPSTRING},
  /* 43 */
  {NULL,  0}
};

#define CLS_IDX_OFFSET   0
#define CLS_IDX_LENGTH   4

#define TAG_IDX_OFFSET  11
#define TAG_IDX_LENGTH  31

/***
create asn1_type object
@function new_type
*/
static int openssl_asn1type_new(lua_State*L)
{
  ASN1_TYPE* at = ASN1_TYPE_new();
  ASN1_STRING *s = NULL;
  int ret = 1;
  if (lua_isboolean(L, 1))
  {
    int b = lua_toboolean(L, 1);
    ASN1_TYPE_set(at, V_ASN1_BOOLEAN, b ? &b : 0);
  }
  else if (lua_type(L, 1) == LUA_TNUMBER)
  {
    long n = lua_tointeger(L, 1);
    ASN1_INTEGER* ai = ASN1_INTEGER_new();
    ret = ASN1_INTEGER_set(ai, n);
    if (ret == 1)
      ASN1_TYPE_set(at, V_ASN1_INTEGER, ai);
  }
  else if (lua_isstring(L, 1))
  {
    size_t size;
    const char* octet = luaL_checklstring(L, 1, &size);
    ret = ASN1_TYPE_set_octetstring(at, (unsigned char*)octet, size);
  }
  else if ((s = GET_GROUP(1, ASN1_STRING, "openssl.asn1group")) != NULL)
  {
    ret = ASN1_TYPE_set1(at, ASN1_STRING_type(s), s);
  }
  else
    luaL_argerror(L, 1, "only accept boolean, number, string or asn1_string");
  if (ret == 1)
  {
    PUSH_OBJECT(at, "openssl.asn1_type");
  }
  else
    lua_pushnil(L);
  return 1;
}

/***
parse der encoded string
@function get_object
@tparam string der string
@tparam[opt=1] number start offset to parse
@tparam[opt=-i] number stop offset to parse
 this like string.sub()
@treturn[1] number tag
@treturn[1] number class
@treturn[1] number parsed data start offset
@treturn[1] number parsed data stop offset
@treturn[1] boolean true for constructed data
@treturn[2] nil for fail
@treturn[2] string error msg
@treturn[2] number inner error code
*/
static int openssl_get_object(lua_State*L)
{
  size_t l = 0;
  const char* asn1s = luaL_checklstring(L, 1, &l);
  size_t start = posrelat(luaL_optinteger(L, 2, 1), l);
  size_t stop = posrelat(luaL_optinteger(L, 3, l), l);

  const unsigned char *p = (const unsigned char *)asn1s + start - 1;
  long len = 0;
  int tag = 0;
  int class = 0;
  int ret;

  if (start > l)
  {
    lua_pushnil(L);
    openssl_pushargerror(L, 2, "out of range");
    return 2;
  }
  if (start>stop)
  {
    lua_pushnil(L);
    openssl_pushargerror(L, 3, "before of start");
    return 2;
  }

  p = (const unsigned char *)asn1s + start - 1;
  ret = ASN1_get_object(&p, &len, &tag, &class, stop - start + 1);
  if (ret & 0x80)
  {
    lua_pushnil(L);
    lua_pushstring(L, "arg #1 with error encoding");
    lua_pushinteger(L, ret);
    return 3;
  }
  lua_pushinteger(L, tag);
  lua_pushinteger(L, class);
  lua_pushinteger(L, p - (const unsigned char *)asn1s + 1);
  lua_pushinteger(L, p + len - (const unsigned char *)asn1s);

  lua_pushboolean(L, ret & V_ASN1_CONSTRUCTED);
  return 5;
}

/***
do der encode and return encoded string partly head or full
@function put_object
@tparam number tag
@tparam number class
@tparam[opt=nil] number|string length or date to encode, defualt will make
indefinite length constructed
@tparam[opt=nil] boolean constructed or not
@treturn string der encoded string or head when not give data
*/
static int openssl_put_object(lua_State*L)
{
  int tag = luaL_checkint(L, 1);
  int cls = luaL_checkint(L, 2);
  int length = 0;
  int constructed;
  unsigned char *p1, *p2;
  const char* dat = NULL;
  luaL_Buffer B;

  luaL_argcheck(L,
                lua_isnone(L, 3) || lua_type(L, 3) == LUA_TNUMBER || lua_isstring(L, 3), 3,
                "if exist only accept string or number");
  luaL_argcheck(L, lua_isnone(L, 4) || lua_isboolean(L, 4), 4,
                "if exist must be boolean type");

  if (lua_isnone(L, 3))
  {
    /* constructed == 2 for indefinite length constructed */
    constructed = 2;
    length = 0;
  }
  else
  {
    if (lua_type(L, 3) == LUA_TNUMBER)
    {
      length = lua_tointeger(L, 3);
    }
    else if (lua_isstring(L, 3))
    {
      size_t l;
      dat = lua_tolstring(L, 3, &l);
      length = (int)l;
    }

    constructed = lua_isnone(L, 4) ? 0 : lua_toboolean(L, 4);
  }
  luaL_buffinit(L, &B);
  p1 = (unsigned char *)luaL_prepbuffer(&B);
  p2 = p1;

  ASN1_put_object(&p2, constructed, length, tag, cls);
  luaL_addsize(&B, p2 - p1);
  if (dat)
  {
    luaL_addlstring(&B, dat, length);
  }
  luaL_pushresult(&B);
  return 1;
};

/***
make tag, class number to string

@function tostring
@tparam number clsortag which to string
@tparam string range only accept 'class' or 'tag'
*/
static int openssl_asn1_tostring(lua_State*L)
{
  int val = luaL_checkint(L, 1);
  const char* range = luaL_optstring(L, 2, NULL);
  int i;

  if (range == NULL)
  {
    for (i = 0; i < sizeof(asn1_const) / sizeof(LuaL_Enumeration) - 1; i++)
    {
      if (asn1_const[i].val == val)
      {
        lua_pushstring(L, asn1_const[i + CLS_IDX_OFFSET].name);
        return 1;
      }
    }
  }
  else if (strcmp("tag", range) == 0)
  {
    for (i = 0; i < TAG_IDX_LENGTH; i++)
    {
      if (asn1_const[i + TAG_IDX_OFFSET].val == val)
      {
        lua_pushstring(L, asn1_const[i + TAG_IDX_OFFSET].name);
        return 1;
      }
    }
  }
  else if (strcmp("class", range) == 0)
  {
    for (i = 0; i < CLS_IDX_LENGTH; i++)
    {
      if (asn1_const[i + CLS_IDX_OFFSET].val == val)
      {
        lua_pushstring(L, asn1_const[i + CLS_IDX_OFFSET].name);
        return 1;
      }
    }
  }

  return 0;
}

/***
Create asn1_string object

<br/><p> asn1_string object support types:   "integer", "enumerated", "bit", "octet", "utf8",
"numeric", "printable", "t61", "teletex", "videotex", "ia5", "graphics", "iso64",
"visible", "general", "unversal", "bmp", "utctime" </p>

@function new_string
@tparam string data to create new asn1_string
@tparam[opt] string type asn1 string type, defult with 'utf8'
@treturn asn1_string
@see asn1_string
*/
static int openssl_asn1string_new(lua_State* L)
{
  size_t size = 0;
  const char* data = luaL_checklstring(L, 1, &size);
  int type = luaL_checkint(L, 2);
  ASN1_STRING *s = ASN1_STRING_type_new(type);
  ASN1_STRING_set(s, data, size);
  PUSH_OBJECT(s, "openssl.asn1_string");
  return 1;
}

/***
Create asn1_integer object

@function new_integer
@tparam number|bn integer to create new asn1_integer
@treturn asn1_integer
@see asn1_integer
*/
static int openssl_asn1int_new(lua_State* L)
{
  ASN1_INTEGER *ai = ASN1_INTEGER_new();
  if (lua_isinteger(L, 1))
  {
    long v = luaL_checklong(L, 1);
    ASN1_INTEGER_set(ai, v);
  }
  else if (!lua_isnone(L, 1))
  {
    BIGNUM *bn = BN_get(L, 1);
    if(bn!=NULL)
    {
      ai = BN_to_ASN1_INTEGER(bn, ai);
      BN_free(bn);
    }
  }
  PUSH_OBJECT(ai, "openssl.asn1_integer");
  return 1;
}

/***
Create asn1_time object
@function new_generalizedtime
@tparam none|number|string time
@treturn asn1_time
*/
static int openssl_asn1generalizedtime_new(lua_State* L)
{
  ASN1_GENERALIZEDTIME* a = NULL;
  int ret = 1;
  luaL_argcheck(L,
                1,
                lua_isnone(L, 1) || lua_isnumber(L, 1) || lua_isstring(L, 1),
                "must be number, string or none"
               );
  a = ASN1_GENERALIZEDTIME_new();
  if (lua_isnumber(L, 1))
    ASN1_GENERALIZEDTIME_set(a, luaL_checkinteger(L, 1));
  else if (lua_isstring(L, 1))
    ret = ASN1_GENERALIZEDTIME_set_string(a, lua_tostring(L, 1));

  if (ret == 1)
    PUSH_OBJECT(a, "openssl.asn1_time");
  else
    return openssl_pushresult(L, ret);
  return 1;
}

/***
Create asn1_time object
@function new_utctime
@tparam none|number|string time
@treturn asn1_time
*/
static int openssl_asn1utctime_new(lua_State* L)
{
  ASN1_UTCTIME* a = NULL;
  int ret = 1;
  luaL_argcheck(L,
                1,
                lua_isnone(L, 1) || lua_isnumber(L, 1) || lua_isstring(L, 1),
                "must be number, string or none"
               );
  a = ASN1_UTCTIME_new();
  if (lua_isnumber(L, 1))
  {
    time_t t = luaL_checkinteger(L, 1);
    ASN1_TIME_set(a, t);
  }
  else if (lua_isstring(L, 1))
    ret = ASN1_TIME_set_string(a, lua_tostring(L, 1));

  if (ret == 1)
    PUSH_OBJECT(a, "openssl.asn1_time");
  else
    return openssl_pushresult(L, ret);
  return 1;
}

/***
get nid for txt, which can be short name, long name, or numerical oid

@function txt2nid
@tparam string txt which get to nid
@treturn integer nid or nil on fail
*/
static int openssl_txt2nid(lua_State*L)
{
  const char* txt = luaL_checkstring(L, 1);
  int nid = OBJ_txt2nid(txt);
  if (nid != NID_undef)
  {
    lua_pushinteger(L, nid);
  }
  else
    lua_pushnil(L);

  return 1;
}

/***
Create asn1_object object

@function new_object
@tparam string name_or_oid  short name,long name or oid string
@tparam[opt] boolean no_name  true for only oid string, default is false
@treturn asn1_object mapping to ASN1_OBJECT in openssl
@see asn1_object
*/

/***
Create asn1_object object

@function new_object
@tparam integer nid ident to asn1_object
@treturn asn1_object mapping to ASN1_OBJECT in openssl
@see asn1_object
*/

/***
Create asn1_object object

@function new_object
@tparam table options have sn, ln, oid keys to create asn1_object
@treturn asn1_object mapping to ASN1_OBJECT in openssl
@see asn1_object
*/
static int openssl_asn1object_new(lua_State* L)
{
  if (lua_type(L, 1) == LUA_TNUMBER)
  {
    int nid = luaL_checkint(L, 1);
    ASN1_OBJECT* obj = OBJ_nid2obj(nid);
    if (obj)
      PUSH_OBJECT(obj, "openssl.asn1_object");
    else
      lua_pushnil(L);
  }
  else if (lua_isstring(L, 1))
  {
    const char* txt = luaL_checkstring(L, 1);
    int no_name = lua_isnone(L, 2) ? 0 : lua_toboolean(L, 2);

    ASN1_OBJECT* obj = OBJ_txt2obj(txt, no_name);
    if (obj)
      PUSH_OBJECT(obj, "openssl.asn1_object");
    else
      lua_pushnil(L);
  }
  else if (lua_istable(L, 1))
  {
    const char *oid, *sn, *ln;
    ASN1_OBJECT* obj;
    int nid;

    lua_getfield(L, 1, "oid");
    luaL_argcheck(L, lua_isstring(L, -1), 1, "not have oid field or is not string");
    oid = luaL_checkstring(L, -1);
    lua_pop(L, 1);

    lua_getfield(L, 1, "sn");
    luaL_argcheck(L, lua_isstring(L, -1), 1, "not have sn field or is not string");
    sn = luaL_checkstring(L, -1);
    lua_pop(L, 1);

    lua_getfield(L, 1, "ln");
    luaL_argcheck(L, lua_isstring(L, -1), 1, "not have ln field or is not string");
    ln = luaL_checkstring(L, -1);
    lua_pop(L, 1);

    if (OBJ_txt2nid(oid) != NID_undef)
    {
      luaL_argerror(L, 1, "oid already exist");
    }

    if (OBJ_sn2nid(sn) != NID_undef)
    {
      luaL_argerror(L, 1, "sn already exist");
    }

    if (OBJ_ln2nid(ln) != NID_undef)
    {
      luaL_argerror(L, 1, "ln already exist");
    }

    nid = OBJ_create(oid, sn, ln);
    if (nid != NID_undef)
    {
      obj = OBJ_nid2obj(nid);
      PUSH_OBJECT(obj, "openssl.asn1_object");
    }
    else
      luaL_argerror(L, 1, "create object fail");
  }
  else if(lua_isnone(L, 1))
  {
    ASN1_OBJECT* obj = ASN1_OBJECT_new();
    PUSH_OBJECT(obj, "openssl.asn1_object");
  }
  else
    luaL_argerror(L, 1, "need accept paramater or none");

  return 1;
}

/***
convert der encoded asn1type string to object
@function asn1type_di2
@tparam string der
@treturn asn1type object for success, and nil for fail
*/
static int openssl_asn1type_d2i(lua_State*L)
{
  size_t size;
  const unsigned char* data = (const unsigned char*)luaL_checklstring(L, 1, &size);
  ASN1_TYPE* at = d2i_ASN1_TYPE(NULL, &data, size);
  if (at)
  {
    PUSH_OBJECT(at, "openssl.asn1_type");
  }
  else
    lua_pushnil(L);
  return 1;
}

static luaL_Reg R[] =
{
  {"new_object", openssl_asn1object_new},

  {"new_integer", openssl_asn1int_new},
  {"new_string", openssl_asn1string_new},
  {"new_utctime", openssl_asn1utctime_new},
  {"new_generalizedtime", openssl_asn1generalizedtime_new},

  {"new_type", openssl_asn1type_new},
  {"d2i_asn1type", openssl_asn1type_d2i},

  {"get_object", openssl_get_object},
  {"put_object", openssl_put_object},

  {"tostring", openssl_asn1_tostring},
  {"txt2nid",   openssl_txt2nid},

  {NULL, NULL}
};


static int openssl_asn1type_type(lua_State*L)
{
  ASN1_TYPE* at = CHECK_OBJECT(1, ASN1_TYPE, "openssl.asn1_type");
  lua_pushinteger(L, at->type);
  return 1;
}

static int openssl_asn1type_octet(lua_State*L)
{
  ASN1_TYPE* at = CHECK_OBJECT(1, ASN1_TYPE, "openssl.asn1_type");
  if (lua_isnone(L, 2))
  {
    unsigned char* octet;
    int len  = ASN1_TYPE_get_octetstring(at, NULL, 0);
    octet = OPENSSL_malloc(len + 1);
    len = ASN1_TYPE_get_octetstring(at, octet, len + 1);
    if (len >= 0)
      lua_pushlstring(L, (const char *)octet, (size_t)len);
    else
      lua_pushnil(L);
    OPENSSL_free(octet);
    return 1;
  }
  else
  {
    size_t size;
    const char* octet = luaL_checklstring(L, 2, &size);
    int ret = ASN1_TYPE_set_octetstring(at, (unsigned char*)octet, size);
    return openssl_pushresult(L, ret);
  }
}

static int openssl_asn1type_cmp(lua_State*L)
{
  ASN1_TYPE* at = CHECK_OBJECT(1, ASN1_TYPE, "openssl.asn1_type");
  ASN1_TYPE* ot = CHECK_OBJECT(2, ASN1_TYPE, "openssl.asn1_type");
  int ret = ASN1_TYPE_cmp(at, ot);
  lua_pushboolean(L, ret == 0);
  return 1;
}

static int openssl_asn1type_free(lua_State*L)
{
  ASN1_TYPE* at = CHECK_OBJECT(1, ASN1_TYPE, "openssl.asn1_type");
  ASN1_TYPE_free(at);
  return 0;
}

static int openssl_asn1type_asn1string(lua_State*L)
{
  ASN1_TYPE* at = CHECK_OBJECT(1, ASN1_TYPE, "openssl.asn1_type");
  if (at->type != V_ASN1_BOOLEAN && at->type != V_ASN1_OBJECT)
  {
    ASN1_STRING* as = ASN1_STRING_dup(at->value.asn1_string);
    PUSH_OBJECT(as, "openssl.asn1_string");
    return 1;
  }
  return 0;
}

static int openssl_asn1type_i2d(lua_State*L)
{
  ASN1_TYPE* at = CHECK_OBJECT(1, ASN1_TYPE, "openssl.asn1_type");
  unsigned char* out = NULL;
  int len = i2d_ASN1_TYPE(at, &out);
  if (len > 0)
    lua_pushlstring(L, (const char *)out, (size_t)len);
  else
    lua_pushnil(L);
  OPENSSL_free(out);
  return 1;
}

static int openssl_asn1type_info(lua_State* L)
{
  ASN1_TYPE* type = CHECK_OBJECT(1, ASN1_TYPE, "openssl.asn1_type");

  lua_newtable(L);
  switch (type->type)
  {
  case V_ASN1_BMPSTRING:
  {
#if OPENSSL_VERSION_NUMBER > 0x10000000L
    char *value = OPENSSL_uni2asc(type->value.bmpstring->data, type->value.bmpstring->length);
    AUXILIAR_SET(L, -1, "value", value, string);
    OPENSSL_free(value);
#else
    AUXILIAR_SETLSTR(L, -1, "value",
                     (const char*)type->value.bmpstring->data, type->value.bmpstring->length);
#endif
    AUXILIAR_SET(L, -1, "type", "bmp", string);
  }
  break;

  case V_ASN1_OCTET_STRING:
    AUXILIAR_SETLSTR(L, -1, "value",
                     (const char *)type->value.octet_string->data, type->value.octet_string->length);
    AUXILIAR_SET(L, -1, "type", "octet", string);
    break;

  case V_ASN1_BIT_STRING:
    AUXILIAR_SETLSTR(L, -1, "value",
                     (const char *)type->value.bit_string->data, type->value.bit_string->length);

    AUXILIAR_SET(L, -1, "type", "bit", string);
    break;

  default:
  {
    int i;
    unsigned char* dat = NULL;

    lua_pushinteger(L, type->type);
    lua_setfield(L, -2, "type");

    AUXILIAR_SET(L, -1, "format", "der", string);
    i = i2d_ASN1_TYPE(type, &dat);
    if (i > 0)
    {
      AUXILIAR_SETLSTR(L, -1, "value", (const char *)dat, i);
      OPENSSL_free(dat);
    }
  }
  }
  return 1;
}

int openssl_push_asn1type(lua_State* L, const ASN1_TYPE* type)
{
  lua_newtable(L);
  switch (type->type)
  {
  case V_ASN1_BMPSTRING:
  {
#if OPENSSL_VERSION_NUMBER > 0x10000000L
    char *value = OPENSSL_uni2asc(type->value.bmpstring->data, type->value.bmpstring->length);
    AUXILIAR_SET(L, -1, "value", value, string);
    OPENSSL_free(value);
#else
    AUXILIAR_SETLSTR(L, -1, "value",
                     (const char*)type->value.bmpstring->data, type->value.bmpstring->length);
#endif
  }
  break;

  case V_ASN1_OCTET_STRING:
    AUXILIAR_SETLSTR(L, -1, "value",
                     (const char *)type->value.octet_string->data, type->value.octet_string->length);
    break;

  case V_ASN1_BIT_STRING:
    AUXILIAR_SETLSTR(L, -1, "value",
                     (const char *)type->value.bit_string->data, type->value.bit_string->length);
    break;

  default:
  {
    int i;
    unsigned char* dat = NULL;

    AUXILIAR_SET(L, -1, "format", "der", string);
    i = i2d_ASN1_TYPE((ASN1_TYPE*)type, &dat);
    if (i > 0)
    {
      AUXILIAR_SETLSTR(L, -1, "value", (const char *)dat, i);
      OPENSSL_free(dat);
    }
  }
  }
  lua_pushinteger(L, type->type);
  lua_setfield(L, -2, "type");
  return 1;
}

static luaL_Reg asn1type_funcs[] =
{
  {"type",      openssl_asn1type_type},
  {"octet",     openssl_asn1type_octet},
  {"cmp",       openssl_asn1type_cmp},
  {"info",      openssl_asn1type_info},

  {"i2d",       openssl_asn1type_i2d},
  {"asn1string", openssl_asn1type_asn1string},

  {"__tostring", auxiliar_tostring},
  {"__eq",      openssl_asn1type_cmp},
  {"__gc",      openssl_asn1type_free },

  {NULL,        NULL}
};

/***
openssl.asn1_object object
@type asn1_object
*/
/***
get nid of asn1_object.

@function nid
@treturn integer nid of asn1_object
*/
static int openssl_asn1object_nid(lua_State* L)
{
  ASN1_OBJECT* o = CHECK_OBJECT(1, ASN1_OBJECT, "openssl.asn1_object");
  lua_pushinteger(L, OBJ_obj2nid(o));
  return 1;
}

/***
get name of asn1_object.

@function name
@treturn string short name and followed by long name of asn1_object
*/
static int openssl_asn1object_name(lua_State* L)
{
  ASN1_OBJECT* o = CHECK_OBJECT(1, ASN1_OBJECT, "openssl.asn1_object");
  int nid = OBJ_obj2nid(o);
  lua_pushstring(L, OBJ_nid2sn(nid));
  lua_pushstring(L, OBJ_nid2ln(nid));
  return 2;
}

/***
get long name of asn1_object.

@function ln
@treturn string long name of asn1_object
*/
static int openssl_asn1object_ln(lua_State* L)
{
  ASN1_OBJECT* o = CHECK_OBJECT(1, ASN1_OBJECT, "openssl.asn1_object");
  const char* s = OBJ_nid2ln(OBJ_obj2nid(o));
  if (s != NULL)
    lua_pushstring(L, s);
  else
    lua_pushnil(L);
  return 1;
}

/***
get short name of asn1_object.
@function sn
@treturn string short name of asn1_object
*/
static int openssl_asn1object_sn(lua_State* L)
{
  ASN1_OBJECT* o = CHECK_OBJECT(1, ASN1_OBJECT, "openssl.asn1_object");
  const char* s = OBJ_nid2sn(OBJ_obj2nid(o));
  if (s != NULL)
    lua_pushstring(L, s);
  else
    lua_pushnil(L);
  return 1;
}

/***
get text of asn1_object.

@function txt
@tparam[opt] boolean no_name true for only oid or name, default with false
@treturn string long or short name, even oid of asn1_object
*/
static int openssl_asn1object_txt(lua_State* L)
{
  ASN1_OBJECT* o = CHECK_OBJECT(1, ASN1_OBJECT, "openssl.asn1_object");
  int no_name = lua_isnone(L, 2) ? 0 : lua_toboolean(L, 2);

  luaL_Buffer B;
  luaL_buffinit(L, &B);

  luaL_addsize(&B, OBJ_obj2txt(luaL_prepbuffer(&B), LUAL_BUFFERSIZE, o, no_name));
  luaL_pushresult(&B);
  return 1;
}

/***
compare two asn1_objects, if equals return true

@function equals
@tparam asn1_object another to compre
@treturn boolean true if equals
*/
static int openssl_asn1object_equals(lua_State* L)
{
  ASN1_OBJECT* o = CHECK_OBJECT(1, ASN1_OBJECT, "openssl.asn1_object");
  ASN1_OBJECT* a = CHECK_OBJECT(2, ASN1_OBJECT, "openssl.asn1_object");

  lua_pushboolean(L, OBJ_cmp(o, a) == 0);
  return 1;
}

/***
get data of asn1_object

@function data
@treturn string asn1_object data
*/
static int openssl_asn1object_data(lua_State* L)
{
  ASN1_OBJECT* s = CHECK_OBJECT(1, ASN1_OBJECT, "openssl.asn1_object");
  BIO* bio = BIO_new(BIO_s_mem());
  BUF_MEM *buf;

  i2a_ASN1_OBJECT(bio, s);
  BIO_get_mem_ptr(bio, &buf);
  lua_pushlstring(L, buf->data, buf->length);
  BIO_free(bio);
  return 1;
}

static int openssl_asn1object_free(lua_State* L)
{
  ASN1_OBJECT* s = CHECK_OBJECT(1, ASN1_OBJECT, "openssl.asn1_object");
  ASN1_OBJECT_free(s);
  return 0;
}

/***
make a clone of asn1_object

@function dup
@treturn asn1_object clone for self
*/
static int openssl_asn1object_dup(lua_State* L)
{
  ASN1_OBJECT* o = CHECK_OBJECT(1, ASN1_OBJECT, "openssl.asn1_object");
  ASN1_OBJECT* a = OBJ_dup(o);

  PUSH_OBJECT(a, "openssl.asn1_object");
  return 1;
}

/***
read der in to asn1_object

@function d2i
@treturn boolean
*/
static int openssl_asn1object_d2i(lua_State* L)
{
  size_t l;
  ASN1_OBJECT* o = CHECK_OBJECT(1, ASN1_OBJECT, "openssl.asn1_object");
  const unsigned char* p = (const unsigned char*) luaL_checklstring(L, 2, &l);

  lua_pushboolean(L, d2i_ASN1_OBJECT(&o, &p, l)!=NULL);
  return 1;
}

/***
get der encoded of asn1_object

@function i2d
@treturn string
*/
static int openssl_asn1object_i2d(lua_State* L)
{
  ASN1_OBJECT* o = CHECK_OBJECT(1, ASN1_OBJECT, "openssl.asn1_object");
  int ret = i2d_ASN1_OBJECT(o, NULL);
  if (ret > 0)
  {
    unsigned char *p, *O;
    p = O = OPENSSL_malloc(ret);
    ret = i2d_ASN1_OBJECT(o, &p);
    if (ret>0)
      lua_pushlstring(L, (const char*)O, ret);
    OPENSSL_free(O);
  }
  if (ret==0)
    lua_pushnil(L);
  return 1;
}

static luaL_Reg asn1obj_funcs[] =
{
  {"nid",         openssl_asn1object_nid},
  {"name",        openssl_asn1object_name},
  {"ln",          openssl_asn1object_ln},
  {"sn",          openssl_asn1object_sn},
  {"txt",         openssl_asn1object_txt},
  {"dup",         openssl_asn1object_dup},
  {"data",        openssl_asn1object_data},
  {"equals",      openssl_asn1object_equals},
  {"d2i",         openssl_asn1object_d2i},
  {"i2d",         openssl_asn1object_i2d},

  {"__eq",        openssl_asn1object_equals},
  {"__gc",        openssl_asn1object_free},
  {"__tostring",  auxiliar_tostring},

  {NULL,    NULL}
};

/***
openssl.asn1_integer object
@type asn1_integer
*/
static int openssl_asn1int_bn(lua_State *L)
{
  ASN1_INTEGER *ai = CHECK_OBJECT(1, ASN1_INTEGER, "openssl.asn1_integer");
  if (lua_isnone(L, 2))
  {
    BIGNUM* B = ASN1_INTEGER_to_BN(ai, NULL);
    PUSH_OBJECT(B, "openssl.bn");
    return 1;
  }
  else
  {
    BIGNUM* B = BN_get(L, 2);
    BN_to_ASN1_INTEGER(B, ai);
    BN_free(B);
    return 0;
  }
}

/***
openssl.asn1_string object
@type asn1_string
*/

/***
@function set
*/
static int openssl_asn1group_set(lua_State *L)
{
  ASN1_STRING *s = CHECK_GROUP(1, ASN1_STRING, "openssl.asn1group");
  int ret = 1;

  switch (s->type)
  {
  case V_ASN1_INTEGER:
  {
    ASN1_INTEGER *ai = CHECK_OBJECT(1, ASN1_INTEGER, "openssl.asn1_integer");
    long v = luaL_checklong(L, 2);
    ret = ASN1_INTEGER_set(ai, v);
    return openssl_pushresult(L, ret);
  }
  case V_ASN1_UTCTIME:
  case V_ASN1_GENERALIZEDTIME:
  {
    ASN1_TIME *a = CHECK_OBJECT(1, ASN1_TIME, "openssl.asn1_time");
    if (lua_type(L, 2) == LUA_TNUMBER)
    {
      time_t t = luaL_checkinteger(L, 2);
      ASN1_TIME_set(a, t);
    }
    else if (lua_isstring(L, 2))
    {
      ret = ASN1_TIME_set_string(a, lua_tostring(L, 2));
    }
    else
      luaL_error(L, "only accpet number or string");
    return openssl_pushresult(L, ret);
  }
  default:
    break;
  }
  return 0;
}

static time_t ASN1_TIME_get(ASN1_TIME* time, time_t off)
{
  struct tm t;
  const char* str = (const char*) time->data;
  size_t i = 0;

  memset(&t, 0, sizeof(t));

  if (time->type == V_ASN1_UTCTIME)  /* two digit year */
  {
    t.tm_year = (str[i++] - '0') * 10;
    t.tm_year += (str[i++] - '0');
    if (t.tm_year < 70)
      t.tm_year += 100;
  }
  else if (time->type == V_ASN1_GENERALIZEDTIME)    /* four digit year */
  {
    t.tm_year = (str[i++] - '0') * 1000;
    t.tm_year += (str[i++] - '0') * 100;
    t.tm_year += (str[i++] - '0') * 10;
    t.tm_year += (str[i++] - '0');
    t.tm_year -= 1900;
  }
  t.tm_mon = (str[i++] - '0') * 10;
  t.tm_mon += (str[i++] - '0') - 1; // -1 since January is 0 not 1.
  t.tm_mday = (str[i++] - '0') * 10;
  t.tm_mday += (str[i++] - '0');
  t.tm_hour = (str[i++] - '0') * 10;
  t.tm_hour += (str[i++] - '0');
  t.tm_min = (str[i++] - '0') * 10;
  t.tm_min += (str[i++] - '0');
  t.tm_sec = (str[i++] - '0') * 10;
  t.tm_sec += (str[i++] - '0');

  /* Note: we did not adjust the time based on time zone information */
  return mktime(&t) + off;
}

/***
@function get
*/
static int openssl_asn1group_get(lua_State *L)
{
  ASN1_STRING *s = CHECK_GROUP(1, ASN1_STRING, "openssl.asn1group");
  switch (s->type)
  {
  case V_ASN1_INTEGER:
  {
    ASN1_INTEGER *ai = CHECK_OBJECT(1, ASN1_INTEGER, "openssl.asn1_integer");
    long v = ASN1_INTEGER_get(ai);
    lua_pushinteger(L, v);
    return 1;
  }
  case V_ASN1_UTCTIME:
  case V_ASN1_GENERALIZEDTIME:
  {
    ASN1_TIME *at = CHECK_OBJECT(1, ASN1_TIME, "openssl.asn1_time");
    time_t offset = timezone;
    time_t get = ASN1_TIME_get(at, -offset);
    lua_pushnumber(L, (lua_Number) get);
    return 1;
  }
  default:
    break;
  }
  return 0;
}

/***
@function i2d
*/
static int openssl_asn1group_i2d(lua_State *L)
{
  ASN1_STRING *s = CHECK_GROUP(1, ASN1_STRING, "openssl.asn1group");
  switch (s->type)
  {
  case V_ASN1_INTEGER:
  {
    ASN1_INTEGER *ai = (ASN1_INTEGER *)s;
    unsigned char* out = NULL;
    int len = i2d_ASN1_INTEGER(ai, &out);
    if (len > 0)
    {
      lua_pushlstring(L, (const char *)out, len);
      OPENSSL_free(out);
      return 1;
    }
    else
      return openssl_pushresult(L, len);
    break;
  }
  case V_ASN1_UTCTIME:
  {
    ASN1_TIME *a = (ASN1_TIME *)s;
    unsigned char* out = NULL;
    int len = i2d_ASN1_TIME(a, &out);
    if (len > 0)
    {
      lua_pushlstring(L, (const char *) out, len);
      OPENSSL_free(out);
      return 1;
    }
    return openssl_pushresult(L, len);
  }
  case V_ASN1_GENERALIZEDTIME:
  {
    ASN1_GENERALIZEDTIME *a = (ASN1_GENERALIZEDTIME *) s;
    unsigned char* out = NULL;
    int len = i2d_ASN1_GENERALIZEDTIME(a, &out);
    if (len > 0)
    {
      lua_pushlstring(L, (const char *) out, len);
      OPENSSL_free(out);
      return 1;
    }
    return openssl_pushresult(L, len);
  }
  default:
    break;
  };
  return 0;
}

/***
@function d2i
*/
static int openssl_asn1group_d2i(lua_State *L)
{
  ASN1_STRING *s = CHECK_GROUP(1, ASN1_STRING, "openssl.asn1group");
  switch (s->type)
  {
  case V_ASN1_INTEGER:
  {
    size_t len;
    ASN1_INTEGER *ai = (ASN1_INTEGER *) s;
    const unsigned char* der = (const unsigned char*)luaL_checklstring(L, 2, &len);
    ai = d2i_ASN1_INTEGER(&ai, &der, (long) len);
    if (ai == NULL)
      return openssl_pushresult(L, -1);
    else
      lua_pushvalue(L, 1);
    return 1;
  }
  case V_ASN1_UTCTIME:
  {
    size_t len;
    ASN1_TIME *a = (ASN1_TIME *) s;
    const char* der = luaL_checklstring(L, 2, &len);
    a = d2i_ASN1_TIME(&a, (const unsigned char **)&der, len);
    if (a == NULL)
      return openssl_pushresult(L, -1);
    else
      lua_pushvalue(L, 1);
    return 1;
  }
  case V_ASN1_GENERALIZEDTIME:
  {
    size_t len;
    ASN1_GENERALIZEDTIME *a = (ASN1_GENERALIZEDTIME *) s;
    const char* der = luaL_checklstring(L, 2, &len);
    a = d2i_ASN1_GENERALIZEDTIME(&a, (const unsigned char **)&der, len);
    if (a == NULL)
      return openssl_pushresult(L, -1);
    lua_pushvalue(L, 1);
    return 1;
  }
  default:
    break;
  };
  return 0;
}

/***
get type of asn1_string

@function type
@treturn string type of asn1_string
@see new_string
*/
static int openssl_asn1group_type(lua_State* L)
{
  ASN1_STRING* s = CHECK_GROUP(1, ASN1_STRING, "openssl.asn1group");
  int type = ASN1_STRING_type(s);
  int i;
  lua_pushinteger(L, type);
  for (i = 0; i < TAG_IDX_LENGTH; i++)
  {
    if (type == asn1_const[i + TAG_IDX_OFFSET].val)
    {
      lua_pushstring(L, asn1_const[i + TAG_IDX_OFFSET].name);
      return 2;
    }
  }
  return 1;
}

/***
get length two asn1_string

@function length
@treturn integer length of asn1_string
@usage
  local astr = asn1.new_string('ABCD')
  print('length:',#astr)
  print('length:',astr:length())
  assert(#astr==astr:length,"must equals")
*/
static int openssl_asn1group_length(lua_State* L)
{
  ASN1_STRING* s = CHECK_GROUP(1, ASN1_STRING, "openssl.asn1group");
  lua_pushinteger(L, ASN1_STRING_length(s));
  return 1;
}

/***
get data of asn1_string

@function data
@treturn string raw data of asn1_string
*/

/***
set data of asn1_string

@function data
@tparam string data set to asn1_string
@treturn boolean success if value set true, or follow by errmsg
@treturn string fail error message
*/
static int openssl_asn1group_data(lua_State* L)
{
  ASN1_STRING* s = CHECK_GROUP(1, ASN1_STRING, "openssl.asn1group");
  if (lua_isnone(L, 2))
    lua_pushlstring(L, (const char*)ASN1_STRING_get0_data(s), ASN1_STRING_length(s));
  else
  {
    size_t l;
    const char*data = luaL_checklstring(L, 2, &l);
    int ret = ASN1_STRING_set(s, data, l);
    lua_pushboolean(L, ret);
  }
  return 1;
}

/***
compare two asn1_string, if equals return true

@function equals
@tparam asn1_string another to compre
@treturn boolean true if equals
@usage
  local obj = astr:dup()
  assert(obj==astr, "must equals")
*/
static int openssl_asn1group_eq(lua_State* L)
{
  ASN1_STRING* s = CHECK_GROUP(1, ASN1_STRING, "openssl.asn1group");
  ASN1_STRING* ss = CHECK_GROUP(2, ASN1_STRING, "openssl.asn1group");
  if (s->type == ss->type && ASN1_STRING_cmp(s, ss) == 0)
    lua_pushboolean(L, 1);
  else
    lua_pushboolean(L, 0);
  return 1;
}

static int openssl_asn1group_free(lua_State* L)
{
  ASN1_STRING* s = CHECK_GROUP(1, ASN1_STRING, "openssl.asn1group");
  switch (s->type)
  {
  case V_ASN1_INTEGER:
    ASN1_INTEGER_free(s);
    break;
  case V_ASN1_GENERALIZEDTIME:
    ASN1_GENERALIZEDTIME_free(s);
    break;
  case V_ASN1_UTCTIME:
    ASN1_TIME_free(s);
    break;
  default:
    ASN1_STRING_free(s);
    break;
  }

  return 0;
}

/***
convert asn1_string to lua string

@function __tostring
@treturn string result format match with type:data
*/
static int openssl_asn1group_tostring(lua_State* L)
{
  ASN1_STRING* s = CHECK_GROUP(1, ASN1_STRING, "openssl.asn1group");
  if (s)
  {
    int type = ASN1_STRING_type(s);

    switch (type)
    {
    case V_ASN1_INTEGER:
    case V_ASN1_BIT_STRING:
    {
      BIGNUM *bn = BN_bin2bn((const unsigned char*)ASN1_STRING_get0_data(s), ASN1_STRING_length(s), NULL);
      char* str = BN_bn2hex(bn);
      lua_pushstring(L, str);
      BN_free(bn);
      OPENSSL_free(str);
      return 1;
    }
    default:
      lua_pushlstring(L, (const char*)ASN1_STRING_get0_data(s), ASN1_STRING_length(s));
      return 1;
    }
  }
  return 0;
}

/***
get data as printable encode string

@function toprint
@treturn string printable encoded string
*/
static int openssl_asn1group_toprint(lua_State* L)
{
  ASN1_STRING* s = CHECK_GROUP(1, ASN1_STRING, "openssl.asn1group");
  unsigned long flags = luaL_optint(L, 2, 0);
  BIO* out = BIO_new(BIO_s_mem());
  BUF_MEM *mem;
  switch (s->type)
  {
  case V_ASN1_UTCTIME:
  {
    ASN1_TIME *a = (ASN1_TIME *) s;
    ASN1_TIME_print(out, a);
    break;
  }
  case V_ASN1_GENERALIZEDTIME:
  {
    ASN1_GENERALIZEDTIME *a = (ASN1_GENERALIZEDTIME *) s;
    ASN1_GENERALIZEDTIME_print(out, a);
    break;
  }
  default:
    ASN1_STRING_print_ex(out, s, flags);
  }


  BIO_get_mem_ptr(out, &mem);
  lua_pushlstring(L, mem->data, mem->length);
  BIO_free(out);
  return 1;
}

/***
get data as utf8 encode string

@function toutf8
@treturn string utf8 encoded string
*/
static int openssl_asn1group_toutf8(lua_State* L)
{
  ASN1_STRING* s = CHECK_GROUP(1, ASN1_STRING, "openssl.asn1group");
  unsigned char* out = NULL;
  int len =  ASN1_STRING_to_UTF8(&out, s);
  if (out)
  {
    lua_pushlstring(L, (const char*)out, len);
    OPENSSL_free(out);
  }
  return 1;
}

/***
duplicate a new asn1_string

@function dup
@treturn asn1_string clone for self
*/
static int openssl_asn1group_dup(lua_State* L)
{
  ASN1_STRING* s = CHECK_GROUP(1, ASN1_STRING, "openssl.asn1group");
  openssl_push_asn1(L, s, s->type);
  return 1;
}

static int openssl_asn1time_check(lua_State* L)
{
  ASN1_TIME *a = CHECK_OBJECT(1, ASN1_TIME, "openssl.asn1_time");
  int ret = ASN1_TIME_check(a);
  return openssl_pushresult(L, ret);
}

static int openssl_asn1time_adj(lua_State* L)
{
  ASN1_TIME *a = CHECK_OBJECT(1, ASN1_TIME, "openssl.asn1_time");
  time_t t = luaL_checkinteger(L, 2);
  int offset_day = luaL_optint(L, 3, 0);
  long offset_sec = luaL_optlong(L, 4, 0);

  ASN1_TIME_adj(a, t, offset_day, offset_sec);
  return 0;
}

static luaL_Reg asn1str_funcs[] =
{
  /* asn1string */
  {"length",    openssl_asn1group_length},
  {"type",      openssl_asn1group_type},
  {"data",      openssl_asn1group_data},

  {"dup",       openssl_asn1group_dup},

  {"toutf8",    openssl_asn1group_toutf8},
  {"toprint",   openssl_asn1group_toprint},
  {"tostring",  openssl_asn1group_tostring},

  {"__len",     openssl_asn1group_length},
  {"__tostring",auxiliar_tostring},

  {"__eq",      openssl_asn1group_eq},
  {"__gc",      openssl_asn1group_free},

  {"set", openssl_asn1group_set},
  {"get", openssl_asn1group_get},
  {"i2d", openssl_asn1group_i2d},
  {"d2i", openssl_asn1group_d2i},

  /* asn1int */
  {"bn",  openssl_asn1int_bn},

  /* asn1time,asn1generalizedtime */
  {"adj", openssl_asn1time_adj},
  {"check", openssl_asn1time_check},

  {NULL, NULL}
};

int luaopen_asn1(lua_State *L)
{
  tzset();
  auxiliar_newclass(L, "openssl.asn1_object", asn1obj_funcs);
  auxiliar_newclass(L, "openssl.asn1_type", asn1type_funcs);

  auxiliar_newclass(L, "openssl.asn1_string", asn1str_funcs);
  auxiliar_newclass(L, "openssl.asn1_integer", asn1str_funcs);
  auxiliar_newclass(L, "openssl.asn1_time", asn1str_funcs);

  auxiliar_add2group(L, "openssl.asn1_time", "openssl.asn1group");
  auxiliar_add2group(L, "openssl.asn1_string", "openssl.asn1group");
  auxiliar_add2group(L, "openssl.asn1_integer", "openssl.asn1group");

  lua_newtable(L);
  luaL_setfuncs(L, R, 0);

  auxiliar_enumerate(L, -1, asn1_const);

  return 1;
}

ASN1_OBJECT* openssl_get_asn1object(lua_State*L, int idx, int nil)
{
  ASN1_OBJECT *obj = NULL;
  if (lua_type(L, idx) == LUA_TNUMBER)
  {
    obj = OBJ_nid2obj(luaL_checkint(L, idx));
  }
  else if (lua_isstring(L, idx))
  {
    obj = OBJ_txt2obj(lua_tostring(L, idx), 0);
  }
  else if (auxiliar_getclassudata(L, "openssl.asn1_object", idx)!=NULL)
  {
    ASN1_OBJECT *in = CHECK_OBJECT(idx, ASN1_OBJECT, "openssl.asn1_object");
    obj = OBJ_dup(in);
  }

  if(nil!=0)
    return obj;

  if(obj==NULL)
  {
    lua_pushfstring(L, "%s is invalid asn1_object or object id", lua_tostring(L, idx));
    luaL_argerror(L, idx, lua_tostring(L, -1));
  }
  return obj;
}

int openssl_push_asn1object(lua_State* L, const ASN1_OBJECT* obj)
{
  ASN1_OBJECT* dup = OBJ_dup(obj);
  PUSH_OBJECT(dup, "openssl.asn1_object");
  return 1;
}

int openssl_push_asn1(lua_State* L, const ASN1_STRING* string, int type)
{
  if (string == NULL)
  {
    lua_pushnil(L);
    return 1;
  }
  if ((string->type & V_ASN1_GENERALIZEDTIME) == V_ASN1_GENERALIZEDTIME && type == V_ASN1_UTCTIME)
    type = V_ASN1_GENERALIZEDTIME;
  else if ((string->type & V_ASN1_UTCTIME) == V_ASN1_UTCTIME && type == V_ASN1_GENERALIZEDTIME)
    type = V_ASN1_UTCTIME;
  else if (type == V_ASN1_UNDEF)
    type = string->type;
  if ((string->type & type) != type)
  {
    luaL_error(L, "need asn1_string type mismatch");
    return 0;
  }

  switch (type)
  {
  case V_ASN1_INTEGER:
  {
    ASN1_INTEGER*dup = ASN1_INTEGER_dup((ASN1_INTEGER*) string);
    PUSH_OBJECT(dup, "openssl.asn1_integer");
    return 1;
  }
  case V_ASN1_UTCTIME:
  case V_ASN1_GENERALIZEDTIME:
  {
    ASN1_TIME* dup = (ASN1_TIME*) ASN1_STRING_dup(string);
    PUSH_OBJECT(dup, "openssl.asn1_time");
    return 1;
  }
  case V_ASN1_OCTET_STRING:
  case V_ASN1_BIT_STRING:
  default:
  {
    ASN1_STRING* dup =  ASN1_STRING_dup(string);
    PUSH_OBJECT(dup, "openssl.asn1_string");
    return 1;
  }
  }

}
