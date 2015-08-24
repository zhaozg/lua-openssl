/*=========================================================================*\
* asn1.c
* asn1 routines for lua-openssl binding
*
* Author:  george zhao <zhaozg(at)gmail.com>
\*=========================================================================*/
#include "openssl.h"
#include "private.h"

#define MYNAME    "asn1"
#define MYVERSION MYNAME " library for " LUA_VERSION " / Nov 2014 / "\
  "based on OpenSSL " SHLIB_VERSION_NUMBER


static int openssl_asn1type_new(lua_State*L)
{
  ASN1_TYPE* at = ASN1_TYPE_new();
  int ret = 1;
  if (lua_isboolean(L, 1))
  {
    int b = lua_toboolean(L, 1);
    ASN1_TYPE_set(at, V_ASN1_BOOLEAN, b ? &b : 0);
  }
  else if (lua_isnumber(L, 1))
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
  else if (auxiliar_isclass(L, "openssl.asn1_string", 1))
  {
    ASN1_STRING* s = CHECK_OBJECT(1, ASN1_STRING, "openssl.asn1_string");
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
      lua_pushlstring(L, octet, (size_t)len);
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
  lua_pushnil(L);
  lua_setmetatable(L, 1);
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
    lua_pushlstring(L, out, (size_t)len);
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

static luaL_reg asn1type_funcs[] =
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

static int openssl_asn1string_type(lua_State* L)
{
  ASN1_STRING* s = CHECK_OBJECT(1, ASN1_STRING, "openssl.asn1_string");
  int type = ASN1_STRING_type(s);
  lua_pushinteger(L, type);

  return 1;
}

static int openssl_asn1string_length(lua_State* L)
{
  ASN1_STRING* s = CHECK_OBJECT(1, ASN1_STRING, "openssl.asn1_string");
  lua_pushinteger(L, ASN1_STRING_length(s));
  return 1;
}

static int openssl_asn1string_data(lua_State* L)
{
  ASN1_STRING* s = CHECK_OBJECT(1, ASN1_STRING, "openssl.asn1_string");
  if (lua_isnone(L, 2))
    lua_pushlstring(L, (const char*)ASN1_STRING_data(s), ASN1_STRING_length(s));
  else
  {
    size_t l;
    const char*data = luaL_checklstring(L, 2, &l);
    int ret = ASN1_STRING_set(s, data, l);
    lua_pushboolean(L, ret);
  }
  return 1;
}

static int openssl_asn1string_eq(lua_State* L)
{
  ASN1_STRING* s = CHECK_OBJECT(1, ASN1_STRING, "openssl.asn1_string");
  ASN1_STRING* ss = CHECK_OBJECT(2, ASN1_STRING, "openssl.asn1_string");
  if (ASN1_STRING_cmp(s, ss) == 0)
    lua_pushboolean(L, 1);
  else
    lua_pushboolean(L, 0);
  return 1;
}

static int openssl_asn1string_free(lua_State* L)
{
  ASN1_STRING* s = CHECK_OBJECT(1, ASN1_STRING, "openssl.asn1_string");
  ASN1_STRING_free(s);
  return 0;
}

static int openssl_asn1string_tostring(lua_State* L)
{
  ASN1_STRING* s = CHECK_OBJECT(1, ASN1_STRING, "openssl.asn1_string");
  if (s)
  {
    int type = ASN1_STRING_type(s);

    switch (type)
    {
    case V_ASN1_INTEGER:
    case V_ASN1_BIT_STRING:
    {
      BIGNUM *bn = BN_bin2bn((const unsigned char*)ASN1_STRING_data(s), ASN1_STRING_length(s), NULL);
      char* s = BN_bn2hex(bn);
      lua_pushstring(L, s);
      OPENSSL_free(s);
      break;
    }
    default:
      lua_pushlstring(L, (const char*)ASN1_STRING_data(s), ASN1_STRING_length(s));
      break;
    }
    return 1;
  }
  return 0;
}

static int openssl_asn1string_print(lua_State* L)
{
  ASN1_STRING* s = CHECK_OBJECT(1, ASN1_STRING, "openssl.asn1_string");
  unsigned long flags = luaL_optint(L, 2, 0);
  BIO* out = BIO_new(BIO_s_mem());
  BUF_MEM *mem;

  BIO_get_mem_ptr(out, &mem);
  ASN1_STRING_print_ex(out, s, flags);
  lua_pushlstring(L, mem->data, mem->length);
  BIO_free(out);
  return 1;
}

static int openssl_asn1string_toutf8(lua_State* L)
{
  ASN1_STRING* s = CHECK_OBJECT(1, ASN1_STRING, "openssl.asn1_string");
  unsigned char* out = NULL;
  int len =  ASN1_STRING_to_UTF8(&out, s);
  if (out)
  {
    lua_pushlstring(L, (const char*)out, len);
    OPENSSL_free(out);
  }
  return 1;
}

static int openssl_asn1string_dup(lua_State* L)
{
  ASN1_STRING* s = CHECK_OBJECT(1, ASN1_STRING, "openssl.asn1_string");
  ASN1_STRING* ss = ASN1_STRING_dup(s);
  PUSH_OBJECT(ss, "openssl.asn1_string");
  return 1;
}

static luaL_reg asn1str_funcs[] =
{
  {"length",    openssl_asn1string_length},
  {"type",      openssl_asn1string_type },
  {"data",      openssl_asn1string_data },

  {"dup",       openssl_asn1string_dup  },

  {"toutf8",    openssl_asn1string_toutf8 },
  {"print",     openssl_asn1string_print },

  {"__len",     openssl_asn1string_length },
  {"__tostring", openssl_asn1string_tostring },
  {"__eq",      openssl_asn1string_eq },
  {"__gc",      openssl_asn1string_free },

  {NULL,        NULL}
};

/*** asn1_object routines ***/
static int openssl_asn1object_nid(lua_State* L)
{
  ASN1_OBJECT* o = CHECK_OBJECT(1, ASN1_OBJECT, "openssl.asn1_object");
  lua_pushinteger(L, o->nid);
  return 1;
}

static int openssl_asn1object_name(lua_State* L)
{
  ASN1_OBJECT* o = CHECK_OBJECT(1, ASN1_OBJECT, "openssl.asn1_object");
  lua_pushstring(L, o->sn);
  lua_pushstring(L, o->ln);
  return 2;
}

static int openssl_asn1object_ln(lua_State* L)
{
  ASN1_OBJECT* o = CHECK_OBJECT(1, ASN1_OBJECT, "openssl.asn1_object");
  lua_pushstring(L, o->ln);
  return 1;
}

static int openssl_asn1object_sn(lua_State* L)
{
  ASN1_OBJECT* o = CHECK_OBJECT(1, ASN1_OBJECT, "openssl.asn1_object");
  lua_pushstring(L, o->sn);
  return 1;
}

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

static int openssl_asn1object_equals(lua_State* L)
{
  ASN1_OBJECT* o = CHECK_OBJECT(1, ASN1_OBJECT, "openssl.asn1_object");
  ASN1_OBJECT* a = CHECK_OBJECT(2, ASN1_OBJECT, "openssl.asn1_object");

  lua_pushboolean(L, OBJ_cmp(o, a) == 0);
  return 1;
}

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

static int openssl_asn1object_dup(lua_State* L)
{
  ASN1_OBJECT* o = CHECK_OBJECT(1, ASN1_OBJECT, "openssl.asn1_object");
  ASN1_OBJECT* a = OBJ_dup(o);

  PUSH_OBJECT(a, "openssl.asn1_object");
  return 1;
}

static luaL_reg asn1obj_funcs[] =
{
  {"nid",         openssl_asn1object_nid},
  {"name",        openssl_asn1object_name},
  {"ln",          openssl_asn1object_ln},
  {"sn",          openssl_asn1object_sn},
  {"txt",         openssl_asn1object_txt},
  {"dup",         openssl_asn1object_dup},
  {"data",        openssl_asn1object_data},

  {"__eq",        openssl_asn1object_equals},
  {"__gc",        openssl_asn1object_free},
  {"__tostring",  auxiliar_tostring},

  {NULL,    NULL}
};


static int openssl_asn1object_new(lua_State* L)
{
  if (lua_isnumber(L, 1))
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

    if ( OBJ_sn2nid(sn) != NID_undef)
    {
      luaL_argerror(L, 1, "sn already exist");
    }

    if ( OBJ_ln2nid(ln) != NID_undef)
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
  else
    luaL_argerror(L, 1, "need accept paramater");

  return 1;
}

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

static int openssl_get_object(lua_State*L)
{
  size_t l = 0;
  const char* asn1s = luaL_checklstring(L, 1, &l);
  size_t off = posrelat(luaL_optinteger(L, 2, 1), l);
  size_t length = posrelat(luaL_optinteger(L, 3, -1), l);
  if (off < 1) off = 1;
  if (length > l) length = l;

  const unsigned char *p = asn1s + off -1;
  long len = 0;
  int tag = 0;
  int class = 0;

  int ret = ASN1_get_object(&p, &len, &tag, &class, length - off + 1);
  if (ret & 0x80)
  {
    lua_pushnil(L);
    lua_pushstring(L, "arg 1 with error encoding");
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

static int openssl_put_object(lua_State*L)
{
  int tag = luaL_checkint(L, 1);
  int cls = luaL_checkint(L, 2);
  int length;
  int constructed;
  unsigned char *p1, *p2;
  const char* dat = NULL;
  luaL_Buffer B;

  luaL_argcheck(L,
    lua_isnoneornil(L, 3) || lua_isnumber(L, 3) || lua_isstring(L, 3), 3,
    "if exist only accept string or number");
  luaL_argcheck(L, lua_isnoneornil(L, 4) || lua_isboolean(L, 4), 4, 
    "if exist must be boolean type");

  if (lua_isnoneornil(L, 3))
  {
    /* constructed == 2 for indefinite length constructed */
    constructed = 2;
    length = 0;
  } else
  {
    if (lua_isnumber(L, 3))
    {
      length = lua_tointeger(L, 3);
    } else if (lua_isstring(L, 3))
    {
      size_t l;
      dat = lua_tolstring(L, 3, &l);
      length = (int)l;
    }

    constructed = lua_isnoneornil(L, 4) ? 0 : lua_toboolean(L, 4);
  }
  luaL_buffinit(L, &B);
  p1 = luaL_prepbuffer(&B);
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

static LuaL_Enum asn1_const[] =
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

static int openssl_asn1_tostring(lua_State*L)
{
  int val = luaL_checkint(L, 1);
  const char* range = luaL_optstring(L, 2, NULL);
  int i;

  if (range == NULL)
  {
    for (i = 0; i < sizeof(asn1_const)/sizeof(LuaL_Enum) -1; i++)
    {
      if (asn1_const[i].val == val)
      {
        lua_pushstring(L, asn1_const[i + CLS_IDX_OFFSET].name);
        return 1;
      }
    }
  } else if (strcmp("tag", range) == 0)
  {
    for (i = 0; i < TAG_IDX_LENGTH; i++)
    {
      if (asn1_const[i + TAG_IDX_OFFSET].val == val)
      {
        lua_pushstring(L, asn1_const[i + TAG_IDX_OFFSET].name);
        return 1;
      }
    }
  } else if (strcmp("class", range) == 0)
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

static luaL_reg R[] =
{
  {"new_string", openssl_asn1string_new},
  {"new_object", openssl_asn1object_new},
  {"new_type", openssl_asn1type_new},
  {"d2i_asn1type", openssl_asn1type_d2i},

  {"get_object", openssl_get_object},
  {"put_object", openssl_put_object},

  {"tostring", openssl_asn1_tostring},

  {"txt2nid",   openssl_txt2nid},


  {NULL, NULL}
};

int luaopen_asn1(lua_State *L)
{
  int i;

  auxiliar_newclass(L, "openssl.asn1_object", asn1obj_funcs);
  auxiliar_newclass(L, "openssl.asn1_string", asn1str_funcs);
  auxiliar_newclass(L, "openssl.asn1_type",   asn1type_funcs);

  lua_newtable(L);
  luaL_setfuncs(L, R, 0);

  lua_pushliteral(L, "version");    /** version */
  lua_pushliteral(L, MYVERSION);
  lua_settable(L, -3);

  for (i = 0; i < sizeof(asn1_const) / sizeof(LuaL_Enum) - 1; i++)
  {
    LuaL_Enum e = asn1_const[i];
    lua_pushinteger(L, e.val);
    lua_setfield(L, -2, e.name);
  }

  return 1;
}

int openssl_get_nid(lua_State*L, int idx)
{
  if (lua_isnumber(L, idx))
  {
    return luaL_checkint(L, idx);
  }
  else if (lua_isstring(L, idx))
  {
    int nid = NID_undef;
    ASN1_OBJECT* obj = OBJ_txt2obj(lua_tostring(L, idx), 0);
    if (obj)
    {
      nid = OBJ_obj2nid(obj);
      ASN1_OBJECT_free(obj);
    }
    return nid;
  }
  else if (lua_isuserdata(L, idx))
  {
    ASN1_OBJECT* obj = CHECK_OBJECT(idx, ASN1_OBJECT, "openssl.asn1_object");
    int nid = obj->nid;
    ASN1_OBJECT_free(obj);
    return nid;
  }
  else
  {
    luaL_checkany(L, idx);
    luaL_argerror(L, idx, "not accept paramater");
  }
  return NID_undef;
}

int openssl_push_asn1object(lua_State* L, const ASN1_OBJECT* obj)
{
  luaL_Buffer B;
  luaL_buffinit(L, &B);

  luaL_addsize(&B, OBJ_obj2txt(luaL_prepbuffer(&B), LUAL_BUFFERSIZE, obj, 0));
  luaL_pushresult(&B);
  return 1;
}

int openssl_push_asn1(lua_State* L, ASN1_STRING* string, int type, int utf8)
{
  if (type && ((string->type & type) != type))
  {
    luaL_error(L, "need asn1_string type mismatch");
    return 0;
  }

  switch (type)
  {
  case V_ASN1_INTEGER:
  {
    ASN1_INTEGER *ai = (ASN1_INTEGER *)string;
    BIGNUM *bn = ASN1_INTEGER_to_BN(ai, NULL);
    char *tmp = BN_bn2hex(bn);
    lua_pushstring(L, tmp);
    BN_free(bn);
    OPENSSL_free(tmp);
    return 1;
  }
  case V_ASN1_UTCTIME:
  case V_ASN1_GENERALIZEDTIME:
  {
    char *tmp;
    long size;
    ASN1_TIME *tm = (ASN1_TIME*)string;
    BIO *out = BIO_new(BIO_s_mem());
    ASN1_TIME_print(out, tm);
    size = BIO_get_mem_data(out, &tmp);
    lua_pushlstring(L, tmp, size);
    BIO_free(out);
    return 1;
  }
  case V_ASN1_OCTET_STRING:
  case V_ASN1_BIT_STRING:
  {
    lua_pushlstring(L, (char*)ASN1_STRING_data(string), ASN1_STRING_length(string));
    return 1;
  }
  default:
  {
    int len;
    unsigned char *data;
    if (utf8)
    {
      len = ASN1_STRING_to_UTF8(&data, string);
      if (len >= 0)
      {
        lua_pushlstring(L, (char*)data, len);
        OPENSSL_free(data);
      }
      else
        lua_pushnil(L);
    }
    else
    {
      lua_pushlstring(L, (char*)ASN1_STRING_data(string), ASN1_STRING_length(string));
    }
    return 1;
  }
  }

  return 0;
};
