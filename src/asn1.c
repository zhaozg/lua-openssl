/*=========================================================================*\
* asn1.c
* asn1 routines for lua-openssl binding
*
* Author:  george zhao <zhaozg(at)gmail.com>
\*=========================================================================*/
#include "openssl.h"

#define MYNAME    "asn1"
#define MYVERSION MYNAME " library for " LUA_VERSION " / Nov 2014 / "\
  "based on OpenSSL " SHLIB_VERSION_NUMBER
#define MYTYPE      "asn1"


static const char* hex_tab = "0123456789abcdef";

void to_hex(const char* in, int length, char* out)
{
  int i;
  for (i = 0; i < length; i++) {
    out[i*2] = hex_tab[(in[i] >> 4) & 0xF];
    out[i*2+1] = hex_tab[(in[i]) & 0xF];
  }
  out[i*2] = '\0';
}

/*** asn1_string routines ***/
const static char* asTypes[] =
{
  "integer",
  "enumerated",
  "bit",
  "octet",
  "utf8",

  "numeric",
  "printable",
  "t61",

  "teletex",
  "videotex",
  "ia5",
  "graphics",
  "iso64",
  "visible",
  "general",
  "unversal",
  "bmp",

  "utctime",

  NULL,
};

const int isTypes[] =
{
  V_ASN1_INTEGER,
  V_ASN1_ENUMERATED,
  V_ASN1_BIT_STRING,
  V_ASN1_OCTET_STRING,
  V_ASN1_UTF8STRING,

  V_ASN1_NUMERICSTRING,
  V_ASN1_PRINTABLESTRING,
  V_ASN1_T61STRING,

  V_ASN1_TELETEXSTRING,
  V_ASN1_VIDEOTEXSTRING,
  V_ASN1_IA5STRING,
  V_ASN1_GRAPHICSTRING,
  V_ASN1_ISO64STRING,
  V_ASN1_VISIBLESTRING,
  V_ASN1_GENERALSTRING,
  V_ASN1_UNIVERSALSTRING,
  V_ASN1_BMPSTRING,

  V_ASN1_UTCTIME,
  0
};

static const char* asn1_typestring(int type){
  int i;
  for (i = 0; isTypes[i] && isTypes[i] != type; i++);
  if (isTypes[i])
    return asTypes[i];
  else
    return "unknown";
}

static int openssl_ans1string_type(lua_State* L)
{
  ASN1_STRING* s = CHECK_OBJECT(1, ASN1_STRING, "openssl.asn1_string");
  int type = ASN1_STRING_type(s);
  int i;
  for (i = 0; isTypes[i] && isTypes[i] != type; i++);
  if (isTypes[i])
    lua_pushstring(L, asTypes[i]);
  else
    lua_pushstring(L, "unknown");

  return 1;
}

static int openssl_ans1string_length(lua_State* L)
{
  ASN1_STRING* s = CHECK_OBJECT(1, ASN1_STRING, "openssl.asn1_string");
  lua_pushinteger(L, ASN1_STRING_length(s));
  return 1;
}

static int openssl_ans1string_data(lua_State* L)
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

static int openssl_ans1string_eq(lua_State* L)
{
  ASN1_STRING* s = CHECK_OBJECT(1, ASN1_STRING, "openssl.asn1_string");
  ASN1_STRING* ss = CHECK_OBJECT(2, ASN1_STRING, "openssl.asn1_string");
  if (ASN1_STRING_cmp(s, ss) == 0)
    lua_pushboolean(L, 1);
  else
    lua_pushboolean(L, 0);
  return 1;
}

static int openssl_ans1string_free(lua_State* L)
{
  ASN1_STRING* s = CHECK_OBJECT(1, ASN1_STRING, "openssl.asn1_string");
  ASN1_STRING_free(s);
  return 0;
}

static int openssl_ans1string_tostring(lua_State* L)
{
  ASN1_STRING* s = CHECK_OBJECT(1, ASN1_STRING, "openssl.asn1_string");
  if (s)
  {
    int type = ASN1_STRING_type(s);
    int i;
    for (i = 0; isTypes[i] && isTypes[i] != type; i++);

    if (isTypes[i])
      lua_pushstring(L, asTypes[i]);
    else
      lua_pushstring(L, "unknown");
    lua_pushstring(L, ":");
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


    lua_concat(L, 3);
    return 1;
  }
  return 0;
}

static int openssl_ans1string_print(lua_State* L)
{
  ASN1_STRING* s = CHECK_OBJECT(1, ASN1_STRING, "openssl.asn1_string");
  unsigned long flags = luaL_optint(L,2,0);
  BIO* out = BIO_new(BIO_s_mem());
  BUF_MEM *mem;

  BIO_get_mem_ptr(out, &mem);
  ASN1_STRING_print_ex(out,s,flags);
  lua_pushlstring(L,mem->data,mem->length);
  BIO_free(out);
  return 1;
}

static int openssl_ans1string_toutf8(lua_State* L)
{
  ASN1_STRING* s = CHECK_OBJECT(1, ASN1_STRING, "openssl.asn1_string");
  unsigned char* out = NULL;
  int len =  ASN1_STRING_to_UTF8(&out, s);
  lua_pushlstring(L, (const char*)out, len);
  OPENSSL_free(out);
  return 1;
}

static int openssl_ans1string_dup(lua_State* L)
{
  ASN1_STRING* s = CHECK_OBJECT(1, ASN1_STRING, "openssl.asn1_string");
  ASN1_STRING* ss = ASN1_STRING_dup(s);
  PUSH_OBJECT(ss, "openssl.asn1_string");
  return 1;
}

static luaL_reg asn1str_funcs[] =
{
  {"length",    openssl_ans1string_length},
  {"type",      openssl_ans1string_type },
  {"data",      openssl_ans1string_data },

  {"dup",       openssl_ans1string_dup  },
  {"equals",    openssl_ans1string_eq  },
  
  {"toutf8",    openssl_ans1string_toutf8 },
  {"print",     openssl_ans1string_print },

  {"__len",     openssl_ans1string_length },
  {"__tostring",openssl_ans1string_tostring },
  {"__eq",      openssl_ans1string_eq },
  {"__gc",      openssl_ans1string_free },

  {NULL,        NULL}
};

/*** asn1_object routines ***/
static int openssl_ans1object_nid(lua_State* L)
{
  ASN1_OBJECT* o = CHECK_OBJECT(1, ASN1_OBJECT, "openssl.asn1_object");
  lua_pushinteger(L, o->nid);
  return 1;
}

static int openssl_ans1object_name(lua_State* L)
{
  ASN1_OBJECT* o = CHECK_OBJECT(1, ASN1_OBJECT, "openssl.asn1_object");
  lua_pushstring(L, o->sn);
  lua_pushstring(L, o->ln);
  return 2;
}

static int openssl_ans1object_ln(lua_State* L)
{
  ASN1_OBJECT* o = CHECK_OBJECT(1, ASN1_OBJECT, "openssl.asn1_object");
  lua_pushstring(L, o->sn);
  return 1;
}

static int openssl_ans1object_sn(lua_State* L)
{
  ASN1_OBJECT* o = CHECK_OBJECT(1, ASN1_OBJECT, "openssl.asn1_object");
  lua_pushstring(L, o->ln);
  return 1;
}

static int openssl_ans1object_txt(lua_State* L)
{
  ASN1_OBJECT* o = CHECK_OBJECT(1, ASN1_OBJECT, "openssl.asn1_object");
  int no_name = lua_isnoneornil(L, 2) ? 0 : lua_toboolean(L, 2);

  luaL_Buffer B;
  luaL_buffinit(L, &B);

  luaL_addsize(&B, OBJ_obj2txt(luaL_prepbuffer(&B), LUAL_BUFFERSIZE, o, 0));
  luaL_pushresult(&B);
  return 1;
}

static int openssl_ans1object_equals(lua_State* L)
{
  ASN1_OBJECT* o = CHECK_OBJECT(1, ASN1_OBJECT, "openssl.asn1_object");
  ASN1_OBJECT* a = CHECK_OBJECT(2, ASN1_OBJECT, "openssl.asn1_object");
  
  lua_pushboolean(L,OBJ_cmp(o,a)==0);
  return 1;
}

static int openssl_ans1object_data(lua_State* L)
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

static int openssl_ans1object_free(lua_State* L)
{
  ASN1_OBJECT* s = CHECK_OBJECT(1, ASN1_OBJECT, "openssl.asn1_object");
  ASN1_OBJECT_free(s);
  return 0;
}

static int openssl_ans1object_dup(lua_State* L)
{
  ASN1_OBJECT* o = CHECK_OBJECT(1, ASN1_OBJECT, "openssl.asn1_object");
  ASN1_OBJECT* a = OBJ_dup(o);

  PUSH_OBJECT(a, "openssl.asn1_object");
  return 1;
}

static luaL_reg asn1obj_funcs[] =
{
  {"nid",         openssl_ans1object_nid},
  {"name",        openssl_ans1object_name},
  {"ln",          openssl_ans1object_ln},
  {"sn",          openssl_ans1object_sn},
  {"txt",         openssl_ans1object_txt},
  {"dup",         openssl_ans1object_dup},
  {"data",        openssl_ans1object_data},

  {"__eq",        openssl_ans1object_equals},
  {"__gc",        openssl_ans1object_free},
  {"__tostring",  auxiliar_tostring},

  {NULL,    NULL}
};

static luaL_reg R[] =
{
  {NULL,    NULL}
};

LUALIB_API int luaopen_asn1(lua_State *L)
{
  auxiliar_newclass(L, "openssl.asn1_object", asn1obj_funcs);
  auxiliar_newclass(L, "openssl.asn1_string", asn1str_funcs);

  luaL_newmetatable(L, MYTYPE);
  lua_setglobal(L, MYNAME);
  luaL_register(L, MYNAME, R);
  lua_pushvalue(L, -1);
  lua_setmetatable(L, -2);
  lua_pushliteral(L, "version");    /** version */
  lua_pushliteral(L, MYVERSION);
  lua_settable(L, -3);
  lua_pushliteral(L, "__index");
  lua_pushvalue(L, -2);
  lua_settable(L, -3);
  return 1;
}

int openssl_get_nid(lua_State*L, int idx) {
  if (lua_isnumber(L,idx)){
    return luaL_checkint(L, idx);
  }else if(lua_isstring(L, idx)) {
    return OBJ_txt2nid(lua_tostring(L, idx));
  }else if(lua_isuserdata(L, idx)) {
    ASN1_OBJECT* obj = CHECK_OBJECT(idx, ASN1_OBJECT, "openssl.asn1_object");
    int nid = obj->nid;
    ASN1_OBJECT_free(obj);
    return nid;
  }
  return NID_undef;
}

int openssl_get_asn1type(lua_State*L, int idx) {
  if (lua_isnumber(L, idx)) {
    return luaL_checkint(L, idx);
  }else if(lua_isstring(L, idx))
  {
    int i;
    const char* st = lua_tostring(L, idx);
    for (i = 0; stricmp(st, asTypes[i]); i++);
    return isTypes[i];
  }else if(lua_isuserdata(L, idx))
  {
    ASN1_TYPE* atype = CHECK_OBJECT(idx, ASN1_TYPE, "openssl.asn1_type");
    return atype->type;
  }
  return 0;
}

int openssl_push_asn1object(lua_State* L, const ASN1_OBJECT* obj)
{
  luaL_Buffer B;
  luaL_buffinit(L, &B);

  luaL_addsize(&B, OBJ_obj2txt(luaL_prepbuffer(&B), LUAL_BUFFERSIZE, obj, 0));
  luaL_pushresult(&B);
  return 1;
}

int openssl_push_asn1type(lua_State* L, ASN1_TYPE* type)
{
  int itype = type->type;
  int i;
  for (i = 0; isTypes[i] && isTypes[i] != itype; i++);

  lua_pushfstring(L, "%s:",isTypes[i] ? asTypes[i] : "unknown");
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
      AUXILIAR_SET(L, -1, "type", "bmpstring", string);
    }
    break;

  case V_ASN1_OCTET_STRING:
    AUXILIAR_SETLSTR(L, -1, "value",
      (const char *)type->value.octet_string->data, type->value.octet_string->length);
    AUXILIAR_SET(L, -1, "type", "octet_string", string);
    break;

  case V_ASN1_BIT_STRING:
    AUXILIAR_SETLSTR(L, -1, "value",
      (const char *)type->value.bit_string->data, type->value.bit_string->length);

    AUXILIAR_SET(L, -1, "type", "bit_string", string);
    break;

  default:
    AUXILIAR_SET(L, -1, "type", type->type, integer);
    AUXILIAR_SET(L, -1, "format", "der", string);

    {
      unsigned char* dat = NULL;
      int i = i2d_ASN1_TYPE(type, &dat);
      if (i > 0)
      {
        AUXILIAR_SETLSTR(L, -1, "value", (const char *)dat, i);
        OPENSSL_free(dat);
      }
    }
  }
  return 1;
}

int openssl_push_asn1(lua_State* L, ASN1_STRING* string, int type, int utf8)
{
  if(type && string->type!=type)
  {
    luaL_error(L, "need %s asn1, but get %s",asn1_typestring(type),asn1_typestring(string->type));
    return 0;
  }

  switch(string->type){
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
      if (utf8) {
        len = ASN1_STRING_to_UTF8(&data, string);
        if (len >= 0) {
          lua_pushlstring(L, (char*)data, len);
          OPENSSL_free(data);
        }else
          lua_pushnil(L);
      } else {
        lua_pushlstring(L, (char*)ASN1_STRING_data(string), ASN1_STRING_length(string));
      }
      return 1;
    }
  }

  return 0;
};
/*
static unsigned char *generic_asn1(char *value, X509V3_CTX *ctx, long *ext_len)
{
  ASN1_TYPE *typ;
  unsigned char *ext_der = NULL;
  typ = ASN1_generate_v3(value, ctx);
  if (typ == NULL)
    return NULL;
  *ext_len = i2d_ASN1_TYPE(typ, &ext_der);
  ASN1_TYPE_free(typ);
  return ext_der;
}
*/