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

static int openssl_asn1type_new(lua_State*L) {
  ASN1_TYPE* at = ASN1_TYPE_new();
  int ret = 1;
  if (lua_isboolean(L, 1)) {
    int b = lua_toboolean(L, 1);
    ASN1_TYPE_set(at, V_ASN1_BOOLEAN, (void*)b);
  }else if(lua_isnumber(L, 1)) {
    long n = lua_tointeger(L, 1);
    ASN1_INTEGER* ai = ASN1_INTEGER_new();
    ret = ASN1_INTEGER_set(ai, n);
    if(ret==1)
      ASN1_TYPE_set(at, V_ASN1_INTEGER, ai);
  }else if (lua_isstring(L, 1)) {
    size_t size;
    const char* octet = luaL_checklstring(L, 1, &size);
    ret = ASN1_TYPE_set_octetstring(at, (unsigned char*)octet, size);
  }else if(auxiliar_isclass(L, "openssl.asn1_string", 1)) {
    ASN1_STRING* s = CHECK_OBJECT(1, ASN1_STRING, "openssl.asn1_string");
    ret = ASN1_TYPE_set1(at,ASN1_STRING_type(s), s);
  }else
    luaL_argerror(L, 1, "only accept boolean, number, string or asn1_string");
  if (ret==1)
  {
    PUSH_OBJECT(at,"openssl.asn1_type");
  }else
    lua_pushnil(L);
  return 1;
}

static int openssl_asn1type_type(lua_State*L) {
  ASN1_TYPE* at = CHECK_OBJECT(1, ASN1_TYPE, "openssl.asn1_type");
  int type = at->type;
  int i;
  for (i = 0; isTypes[i] && isTypes[i] != type; i++);
  if (isTypes[i])
    lua_pushstring(L, asTypes[i]);
  else
    lua_pushstring(L, "unknown");
  lua_pushinteger(L, type);
  return 2;
}

static int openssl_asn1type_octet(lua_State*L) {
  ASN1_TYPE* at = CHECK_OBJECT(1, ASN1_TYPE, "openssl.asn1_type");
  if(lua_isnone(L, 2)) {
    unsigned char* octet;
    int len  = ASN1_TYPE_get_octetstring(at, NULL, 0);
    octet = OPENSSL_malloc(len+1);
    len = ASN1_TYPE_get_octetstring(at, octet, len+1);
    if(len>=0)
      lua_pushlstring(L, octet, len);
    else
      lua_pushnil(L);
    OPENSSL_free(octet);
    return 1;
  } else {
    size_t size;
    const char* octet = luaL_checklstring(L, 2, &size);
    int ret = ASN1_TYPE_set_octetstring(at, (unsigned char*)octet, size);
    return openssl_pushresult(L, ret);
  }
}

static int openssl_asn1type_cmp(lua_State*L) {
  ASN1_TYPE* at = CHECK_OBJECT(1, ASN1_TYPE, "openssl.asn1_type");
  ASN1_TYPE* ot = CHECK_OBJECT(2, ASN1_TYPE, "openssl.asn1_type");
  int ret = ASN1_TYPE_cmp(at,ot);
  lua_pushboolean(L, ret==0);
  return 1;
}

static int openssl_asn1type_free(lua_State*L) {
  ASN1_TYPE* at = CHECK_OBJECT(1, ASN1_TYPE, "openssl.asn1_type");
  lua_pushnil(L);
  lua_setmetatable(L, 1);
  ASN1_TYPE_free(at);
  return 0;
}

static int openssl_asn1type_asn1string(lua_State*L) {
  ASN1_TYPE* at = CHECK_OBJECT(1, ASN1_TYPE, "openssl.asn1_type");
  if(at->type != V_ASN1_BOOLEAN && at->type!=V_ASN1_OBJECT)
  {
    ASN1_STRING* as = ASN1_STRING_dup(at->value.asn1_string);
    PUSH_OBJECT(as,"openssl.asn1_string");
    return 1;
  }
  return 0;
}

static int openssl_asn1type_i2d(lua_State*L) {
  ASN1_TYPE* at = CHECK_OBJECT(1, ASN1_TYPE, "openssl.asn1_type");
  unsigned char* out = NULL;
  int len = i2d_ASN1_TYPE(at,&out);
  if(len>0)
    lua_pushlstring(L, out, len);
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

      for (i = 0; isTypes[i] && isTypes[i] != type->type; i++);
      lua_pushstring(L, isTypes[i] ? asTypes[i] : "unknown");
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

      for (i = 0; isTypes[i] && isTypes[i] != type->type; i++);
      lua_pushstring(L, isTypes[i] ? asTypes[i] : "unknown");
      lua_setfield(L, -2, "type");

      AUXILIAR_SET(L, -1, "format", "der", string);
      i = i2d_ASN1_TYPE((ASN1_TYPE*)type, &dat);
      if (i > 0)
      {
        AUXILIAR_SETLSTR(L, -1, "value", (const char *)dat, i);
        OPENSSL_free(dat);
      }
    }
  }
  return 1;
}

static int openssl_asn1type_d2i(lua_State*L) {
  size_t size;
  const char* data = luaL_checklstring(L, 1, &size);
  ASN1_TYPE* at = d2i_ASN1_TYPE(NULL, &data, size);
  if(at) {
    PUSH_OBJECT(at,"openssl.asn1_type");
  }else 
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
  {"asn1string",openssl_asn1type_asn1string},
  
  {"__tostring",auxiliar_tostring},
  {"__eq",      openssl_asn1type_cmp},
  {"__gc",      openssl_asn1type_free },

  {NULL,        NULL}
};

static int openssl_ans1string_new(lua_State* L)
{
  size_t size = 0;
  const char* data = luaL_checklstring(L, 1, &size);
  int type = auxiliar_checkoption(L, 2, "utf8", asTypes, isTypes);
  ASN1_STRING *s = ASN1_STRING_type_new(type);
  ASN1_STRING_set(s, data, size);
  PUSH_OBJECT(s, "openssl.asn1_string");
  return 1;
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
  lua_pushstring(L, o->ln);
  return 1;
}

static int openssl_ans1object_sn(lua_State* L)
{
  ASN1_OBJECT* o = CHECK_OBJECT(1, ASN1_OBJECT, "openssl.asn1_object");
  lua_pushstring(L, o->sn);
  return 1;
}

static int openssl_ans1object_txt(lua_State* L)
{
  ASN1_OBJECT* o = CHECK_OBJECT(1, ASN1_OBJECT, "openssl.asn1_object");
  int no_name = lua_isnone(L, 2) ? 0 : lua_toboolean(L, 2);

  luaL_Buffer B;
  luaL_buffinit(L, &B);

  luaL_addsize(&B, OBJ_obj2txt(luaL_prepbuffer(&B), LUAL_BUFFERSIZE, o, no_name));
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
  else if(lua_isstring(L, 1)) 
  {
    const char* txt = luaL_checkstring(L, 1);
    int no_name = lua_isnone(L, 2) ? 0 : lua_toboolean(L, 2);

    ASN1_OBJECT* obj = OBJ_txt2obj(txt, no_name);
    if (obj)
      PUSH_OBJECT(obj, "openssl.asn1_object");
    else
      lua_pushnil(L);
  }
  else if(lua_istable(L, 1))
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

    if(OBJ_txt2nid(oid)!=NID_undef) {
      luaL_argerror(L,1,"oid already exist");
    }

    if( OBJ_sn2nid(sn)!=NID_undef) {
      luaL_argerror(L,1,"sn already exist");
    }

    if( OBJ_ln2nid(ln)!=NID_undef) {
      luaL_argerror(L,1,"ln already exist");
    }

    nid = OBJ_create(oid, sn, ln);
    if (nid!=NID_undef){
      obj = OBJ_nid2obj(nid);
      PUSH_OBJECT(obj, "openssl.asn1_object");
    }
    else
      luaL_argerror(L,1,"create object fail");
  }else
    luaL_argerror(L, 1, "need accept paramater");

  return 1;
}

static int openssl_txt2nid(lua_State*L) {
  const char* txt = luaL_checkstring(L, 1);
  int nid = OBJ_txt2nid(txt);
  if(nid!=NID_undef) {
    lua_pushinteger(L, nid);
  }else
    lua_pushnil(L);

  return 1;
}

static luaL_reg R[] =
{
  {"new_string",    openssl_ans1string_new},
  {"new_object",    openssl_asn1object_new},
  {"new_type",      openssl_asn1type_new},
  {"d2i_asn1type",  openssl_asn1type_d2i},

  {"txt2nid",       openssl_txt2nid},

  {NULL,            NULL}
};

LUALIB_API int luaopen_asn1(lua_State *L)
{
  auxiliar_newclass(L, "openssl.asn1_object", asn1obj_funcs);
  auxiliar_newclass(L, "openssl.asn1_string", asn1str_funcs);
  auxiliar_newclass(L, "openssl.asn1_type",   asn1type_funcs);

  luaL_register(L, MYNAME, R);

  lua_pushliteral(L, "version");    /** version */
  lua_pushliteral(L, MYVERSION);
  lua_settable(L, -3);

  return 1;
}

int openssl_get_nid(lua_State*L, int idx) {
  if (lua_isnumber(L,idx)){
    return luaL_checkint(L, idx);
  }else if(lua_isstring(L, idx)) {
    int nid = NID_undef;
    ASN1_OBJECT* obj = OBJ_txt2obj(lua_tostring(L, idx), 0);
    if(obj) {
      nid = OBJ_obj2nid(obj);
      ASN1_OBJECT_free(obj);
    }
    return nid;
  }else if(lua_isuserdata(L, idx)) {
    ASN1_OBJECT* obj = CHECK_OBJECT(idx, ASN1_OBJECT, "openssl.asn1_object");
    int nid = obj->nid;
    ASN1_OBJECT_free(obj);
    return nid;
  }else{
    luaL_checkany(L, idx);
    luaL_argerror(L, idx, "not accept paramater");
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
