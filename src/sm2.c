#include "openssl.h"
#include "private.h"

#if (OPENSSL_VERSION_NUMBER >= 0x10101007L) && !defined(OPENSSL_NO_SM2)

#  include <openssl/sm2.h>

#define MYNAME    "sm2"
#define MYVERSION MYNAME " library for " LUA_VERSION " / Nov 2018 / "\
    "based on OpenSSL " SHLIB_VERSION_NUMBER

/***
SM2 function in lua, OpenSSL support SM2/SM3/SM4 from version version 1.1.1

@module sm2
@usage
  sm2 = require('openssl').sm2
*/

/***
compute SM2 digest with userid

@function compute_userid_digest
@tparam ec_key SM2 key or SM2 public key
@tparam[opt='1234567812345678'] string userId default is `1234567812345678`
@tparam[opt='sm3'] evp_md|string|nid digest digest alg identity
@treturn string result binary string
*/
static LUA_FUNCTION(openssl_sm2_compute_userid_digest)
{
  const EC_KEY *key = CHECK_OBJECT(1, EC_KEY, "openssl.ec_key");
  const char *user_id = luaL_optstring(L, 2, SM2_DEFAULT_USERID);
  const EVP_MD *md = get_digest(L, 3, "sm3");
  uint8_t dgst[EVP_MAX_MD_SIZE];

  int ret = SM2_compute_userid_digest(dgst, md, user_id, key);
  if (ret==1)
  {
    lua_pushlstring(L, (const char*)dgst, EVP_MD_size(md));
    return 1;
  }
  return openssl_pushresult(L, ret);
}

/***
do SM2 sign, input message will be do digest

@function do_sign
@tparam ec_key sm2key
@tparam string msg data to be sign
@tparam[opt='1234567812345678'] string userId default is `1234567812345678`
@tparam[opt='sm3'] evp_md|string|nid digest digest alg identity, default use sm3
@treturn string result binary signature string
*/
static LUA_FUNCTION(openssl_sm2_do_sign)
{
  const EC_KEY *key = CHECK_OBJECT(1, EC_KEY, "openssl.ec_key");
  size_t msg_len = 0;
  const uint8_t* msg = (const uint8_t*)luaL_checklstring(L, 2, &msg_len);
  const char *user_id = luaL_optstring(L, 3, SM2_DEFAULT_USERID);
  const EVP_MD *md = get_digest(L, 4, "sm3");
  int ret = 0;

  ECDSA_SIG *sig = SM2_do_sign(key, md, user_id, msg, (int)msg_len);
  if(sig!=NULL)
  {
    uint8_t* p = NULL;
    int len = i2d_ECDSA_SIG(sig, &p);
    if (len>0)
    {
      lua_pushlstring(L, (const char*)p, len);
      OPENSSL_free(p);
      ret = 1;
    }
    ECDSA_SIG_free(sig);
  }
  return ret;
}

/***
do SM2 verify, input message will be do digest

@function	do_verify
@tparam ec_key sm2key
@tparam string msg data to be signed
@tparam string signature
@tparam[opt='1234567812345678'] string userId default is `1234567812345678`
@tparam[opt='sm3'] evp_md|string|nid digest digest alg identity, default use sm3
@treturn boolean true for verified, false for invalid signature
@return nil for error, and followed by error message
*/
static LUA_FUNCTION(openssl_sm2_do_verify)
{
  const EC_KEY *key = CHECK_OBJECT(1, EC_KEY, "openssl.ec_key");
  size_t msg_len = 0;
  const uint8_t* msg = (const uint8_t*)luaL_checklstring(L, 2, &msg_len);
  size_t sig_len = 0;
  const uint8_t* signature = (const uint8_t*)luaL_checklstring(L, 3, &sig_len);
  const char *user_id = luaL_optstring(L, 4, SM2_DEFAULT_USERID);
  const EVP_MD *md = get_digest(L, 5, "sm3");
  int ret = 0;

  ECDSA_SIG *sig = d2i_ECDSA_SIG(NULL, &signature, sig_len);
  if(sig!=NULL)
  {
    ret = SM2_do_verify(key, md, sig, user_id, msg, msg_len);
    if (ret==-1)
    {
      ret = openssl_pushresult(L, ret);
    }
    else
    {
      lua_pushboolean(L, ret);
      ret = 1;
    }
  }
  else
  {
    lua_pushnil(L);
    lua_pushstring(L, "Invalid signature data");
    ret = 2;
  }
  return ret;
}

#define SM2_SIG_MAX_LEN 72
/***
do SM2 sign, input is SM3 digest result

@function sign
@tparam ec_key sm2key
@tparam string digest result of SM3 digest to be signed
@tparam[opt='sm3'] evp_md|string|nid digest digest alg identity, default is sm3
@treturn string signature
*/
static LUA_FUNCTION(openssl_sm2_sign)
{
  EC_KEY *eckey = CHECK_OBJECT(1, EC_KEY, "openssl.ec_key");
  size_t dgstlen = 0;
  const uint8_t *dgst = (const uint8_t*)luaL_checklstring(L, 2, &dgstlen);
  const EVP_MD* md = get_digest(L, 3, "sm3");
  uint8_t sig[SM2_SIG_MAX_LEN] = {0};
  unsigned int siglen = sizeof(sig);

  int ret = SM2_sign(EVP_MD_type(md), dgst, dgstlen, sig, &siglen, eckey);
  if (ret==1)
  {
    lua_pushlstring(L, (const char*)sig, siglen);
  }
  else
    ret = openssl_pushresult(L, ret);
  return ret;
}

/***
do SM2 verify, input msg is sm3 digest result

@function verify
@tparam ec_key sm2key
@tparam string digest result of SM3 digest to be signed
@tparam string signature
@tparam[opt='sm3'] evp_md|string|nid digest digest alg identity, default is sm3
@treturn boolean true for verified, false for invalid signature
@return nil for error, and followed by error message
*/
static LUA_FUNCTION(openssl_sm2_verify)
{
  EC_KEY *eckey = CHECK_OBJECT(1, EC_KEY, "openssl.ec_key");
  size_t dgstlen = 0;
  const uint8_t *dgst = (const uint8_t*)luaL_checklstring(L, 2, &dgstlen);
  size_t siglen = 0;
  const uint8_t *sig = (const uint8_t*)luaL_checklstring(L, 3, &siglen);
  const EVP_MD* md = get_digest(L, 4, "sm3");
  int type = EVP_MD_type(md);

  int ret = SM2_verify(type, dgst, (int)dgstlen, sig, (int)siglen, eckey);
  if(ret==-1)
    ret = openssl_pushresult(L, ret);
  else
  {
    lua_pushboolean(L, ret);
    ret = 1;
  }
  return ret;
}

/***
get SM2 encrypt result size

@function ciphersize
@tparam ec_key sm2key
@tparam number size of data to be encrypted
@tparam[opt='sm3'] evp_md|string|nid digest digest alg identity, default is sm3
@treturn number size of cipher data
@return nil for error, and followed by error message
*/
static LUA_FUNCTION(openssl_sm2_ciphertext_size)
{
  EC_KEY *eckey = CHECK_OBJECT(1, EC_KEY, "openssl.ec_key");
  int msg_len = luaL_checkinteger(L, 2);
  const EVP_MD* md = get_digest(L, 3, "sm3");

  size_t size = SM2_ciphertext_size(eckey, md, msg_len);
  lua_pushinteger(L, size);
  return 1;
}

/***
get SM2 decrypt result size

@function plainsize
@tparam ec_key sm2key
@tparam number size of data to be decrypted
@tparam[opt='sm3'] evp_md|string|nid digest digest alg identity, default is sm3
@treturn number size of plain data
@return nil for error, and followed by error message
*/
static LUA_FUNCTION(openssl_sm2_plaintext_size)
{
  EC_KEY *eckey = CHECK_OBJECT(1, EC_KEY, "openssl.ec_key");
  int msg_len = luaL_checkinteger(L, 2);
  const EVP_MD* md = get_digest(L, 3, "sm3");

  size_t size = SM2_plaintext_size(eckey, md, msg_len);
  lua_pushinteger(L, size);
  return 1;
}

/***
do SM2 encrypt

@function encrypt
@tparam ec_key sm2key
@tparam string data_to_encrypt
@tparam[opt='sm3'] evp_md|string|nid digest digest alg identity, default is sm3
@treturn string cipher data
@return nil for error, and followed by error message
*/
static LUA_FUNCTION(openssl_sm2_encrypt)
{
  EC_KEY *eckey = CHECK_OBJECT(1, EC_KEY, "openssl.ec_key");
  size_t msglen = 0;
  const uint8_t *msg = (const uint8_t*)luaL_checklstring(L, 2, &msglen);
  const EVP_MD* md = get_digest(L, 3, "sm3");
  size_t clen = SM2_ciphertext_size(eckey, md, msglen);
  uint8_t* ciphertext = OPENSSL_malloc(clen);

  int ret = SM2_encrypt(eckey, md, msg, msglen, ciphertext, &clen);
  if(ret==1)
  {
    lua_pushlstring(L, (const char*)ciphertext, clen);
  }
  else
  {
    ret = openssl_pushresult(L, ret);
  }
  OPENSSL_free(ciphertext);
  return ret;
}
/***
do SM2 decrypt

@function decrypt
@tparam ec_key sm2key
@tparam string data_to_decrypt
@tparam[opt='sm3'] evp_md|string|nid digest digest alg identity, default is sm3
@treturn string plain data
@return nil for error, and followed by error message
*/
static LUA_FUNCTION(openssl_sm2_decrypt)
{
  EC_KEY *eckey = CHECK_OBJECT(1, EC_KEY, "openssl.ec_key");
  size_t msglen = 0;
  const uint8_t *msg = (const uint8_t*)luaL_checklstring(L, 2, &msglen);
  const EVP_MD* md = get_digest(L, 3, "sm3");
  size_t plen = SM2_plaintext_size(eckey, md, msglen);
  uint8_t* plaintext = OPENSSL_malloc(plen);

  int ret = SM2_decrypt(eckey, md, msg, msglen, plaintext, &plen);
  if(ret==1)
  {
    lua_pushlstring(L, (const char*)plaintext, plen);
  }
  else
  {
    ret = openssl_pushresult(L, ret);
  }
  OPENSSL_free(plaintext);
  return ret;
}

static luaL_Reg R[] =
{
  {"compute_userid_digest", openssl_sm2_compute_userid_digest},
  {"do_sign",               openssl_sm2_do_sign},
  {"do_verify",             openssl_sm2_do_verify},
  {"sign",                  openssl_sm2_sign},
  {"verify",                openssl_sm2_verify},

  {"ciphersize",            openssl_sm2_ciphertext_size},
  {"plainsize",             openssl_sm2_plaintext_size},
  {"encrypt",               openssl_sm2_encrypt},
  {"decrypt",               openssl_sm2_decrypt},

  { NULL, NULL }
};

int luaopen_sm2(lua_State *L)
{
  lua_newtable(L);
  luaL_setfuncs(L, R, 0);
  lua_pushliteral(L, "version");
  lua_pushliteral(L, MYVERSION);
  lua_settable(L, -3);
  lua_pushliteral(L, "default_userid");
  lua_pushliteral(L, SM2_DEFAULT_USERID);
  lua_settable(L, -3);

  return 1;
}

#endif
