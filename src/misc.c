/*=========================================================================*\
* misc.h
* misc routines for lua-openssl binding
*
* Author:  george zhao <zhaozg(at)gmail.com>
\*=========================================================================*/
#include "openssl.h"
#include "private.h"
const char* format[] =
{
  "auto",
  "der",
  "pem",
  "smime",
  NULL
};

BIO* load_bio_object(lua_State* L, int idx)
{
  BIO* bio = NULL;
  if (lua_isstring(L, idx))
  {
    size_t l = 0;
    const char* ctx = lua_tolstring(L, idx, &l);
    /* read only */
    bio = (BIO*)BIO_new_mem_buf((void*)ctx, l);
    /* read write
    BIO_set_close(bio, BIO_NOCLOSE);
    bio = BIO_new(BIO_s_mem());
    BIO_write(bio,(void*)ctx, l);
    BIO_set_close(bio, BIO_CLOSE);
    */
  }
  else if (auxiliar_isclass(L, "openssl.bio", idx))
  {
    bio = CHECK_OBJECT(idx, BIO, "openssl.bio");
    CRYPTO_add(&bio->references, 1, CRYPTO_LOCK_BIO);
  }
  else
    luaL_argerror(L, idx, "only support string or openssl.bio");
  return bio;
}

int  bio_is_der(BIO* bio)
{
  byte head[1];
  int len = BIO_read(bio, head, sizeof(head));
  BIO_reset(bio);
  if (len == sizeof(head) && head[0] == 0x30)
  {
    return 1;
  }

  return 0;
}

const EVP_MD* get_digest(lua_State* L, int idx)
{
  const EVP_MD* md = NULL;
  if (lua_isstring(L, idx))
    md = EVP_get_digestbyname(lua_tostring(L, idx));
  else if (lua_isnumber(L, idx))
    md = EVP_get_digestbynid(lua_tointeger(L, idx));
  else if (auxiliar_isclass(L, "openssl.asn1_object", idx))
    md = EVP_get_digestbyobj(CHECK_OBJECT(1, ASN1_OBJECT, "openssl.asn1_object"));
  else if (auxiliar_isclass(L, "openssl.evp_digest", idx))
    md = CHECK_OBJECT(idx, EVP_MD, "openssl.evp_digest");
  else
  {
    luaL_error(L, "argument #1 must be a string, NID number or asn1_object identity digest method");
  }

  return md;
}

const EVP_CIPHER* get_cipher(lua_State*L, int idx, const char* def_alg)
{
  const EVP_CIPHER* cipher = NULL;
  if (lua_isstring(L, idx))
    cipher = EVP_get_cipherbyname(lua_tostring(L, idx));
  else if (lua_isnumber(L, idx))
    cipher = EVP_get_cipherbynid(lua_tointeger(L, idx));
  else if (auxiliar_isclass(L, "openssl.asn1_object", idx))
    cipher = EVP_get_cipherbyobj(CHECK_OBJECT(1, ASN1_OBJECT, "openssl.asn1_object"));
  else if (auxiliar_isclass(L, "openssl.evp_cipher", idx))
    cipher = CHECK_OBJECT(idx, EVP_CIPHER, "openssl.evp_cipher");
  else if (lua_isnoneornil(L, idx) && def_alg)
    cipher = EVP_get_cipherbyname(def_alg);
  else
    luaL_argerror(L, idx, "must be a string, NID number or asn1_object identity cipher method");
  if (cipher == NULL)
    luaL_argerror(L, idx, "not valid cipher alg");

  return cipher;
}

BIGNUM *BN_get(lua_State *L, int i)
{
  BIGNUM *x = BN_new();
  switch (lua_type(L, i))
  {
  case LUA_TNUMBER:
    BN_set_word(x, lua_tointeger(L, i));
    break;
  case LUA_TSTRING:
  {
    const char *s = lua_tostring(L, i);
    if (s[0] == 'X' || s[0] == 'x') BN_hex2bn(&x, s + 1);
    else BN_dec2bn(&x, s);
    break;
  }
  case LUA_TUSERDATA:
    BN_copy(x, CHECK_OBJECT(i, BIGNUM, "openssl.bn"));
  }
  return x;
}

void openssl_add_method_or_alias(const OBJ_NAME *name, void *arg)
{
  lua_State *L = (lua_State *)arg;
  int i = lua_rawlen(L, -1);
  lua_pushstring(L, name->name);
  lua_rawseti(L, -2, i + 1);
}

void openssl_add_method(const OBJ_NAME *name, void *arg)
{
  if (name->alias == 0)
  {
    openssl_add_method_or_alias(name, arg);
  }
}

int openssl_pushresult(lua_State*L, int result)
{
  if (result == 1)
  {
    lua_pushboolean(L, 1);
    return 1;
  }
  else
  {
    unsigned long val = ERR_get_error();
    lua_pushnil(L);
    if (val)
    {
      lua_pushstring(L, ERR_reason_error_string(val));
      lua_pushinteger(L, val);
    }
    else
    {
      lua_pushstring(L, "UNKNOWN ERROR");
      lua_pushnil(L);
    }
    return 3;
  }
}

static const char* hex_tab = "0123456789abcdef";

void to_hex(const char* in, int length, char* out)
{
  int i;
  for (i = 0; i < length; i++)
  {
    out[i * 2] = hex_tab[(in[i] >> 4) & 0xF];
    out[i * 2 + 1] = hex_tab[(in[i]) & 0xF];
  }
  out[i * 2] = '\0';
}

int openssl_push_bit_string_bitname(lua_State* L, const BIT_STRING_BITNAME* name)
{
  lua_newtable(L);
  lua_pushinteger(L, name->bitnum);
  lua_setfield(L, -2, "bitnum");
  lua_pushstring(L, name->lname);
  lua_setfield(L, -2, "lname");
  lua_pushstring(L, name->sname);
  lua_setfield(L, -2, "sname");
  return 1;
}

int openssl_sk_index(lua_State*L, int i, int num, int idx)
{
  int ret = i;
  if (i < 0)
    ret = num + i;
  else
    ret = i - 1;

  luaL_argcheck(L, ret >= 0 && ret < num, idx, "out of range");
  return ret;
}
