/*=========================================================================*\
* pkcs12.c
* PKCS12 routines for lua-openssl binding
*
* Author:  george zhao <zhaozg(at)gmail.com>
\*=========================================================================*/
#include "openssl.h"
#include "private.h"

#define MYNAME    "pkcs12"
#define MYVERSION MYNAME " library for " LUA_VERSION " / Nov 2014 / "\
  "based on OpenSSL " SHLIB_VERSION_NUMBER
#define MYTYPE      "pkcs12"

static LUA_FUNCTION(openssl_pkcs12_export)
{
  X509 * cert = CHECK_OBJECT(1, X509, "openssl.x509");
  EVP_PKEY *priv_key = CHECK_OBJECT(2, EVP_PKEY, "openssl.evp_pkey");
  char * pass = (char*)luaL_checkstring(L, 3);
  int top = lua_gettop(L);

  BIO * bio_out = NULL;
  PKCS12 * p12 = NULL;
  const char * friendly_name = NULL;
  STACK_OF(X509) *ca = NULL;

  if (top > 3)
  {
    if (lua_isstring(L, 4))
      friendly_name = lua_tostring(L, 4);
    else if (lua_isuserdata(L, 4))
      ca = CHECK_OBJECT(4, STACK_OF(X509), "openssl.stack_of_x509");
    else
      luaL_argerror(L, 4, "must be string as friendly_name or openssl.stack_of_x509 object as cacets");

    if (top > 4)
      ca = CHECK_OBJECT(5, STACK_OF(X509), "openssl.stack_of_x509");
  }

  if (cert && !X509_check_private_key(cert, priv_key))
  {
    luaL_error(L, "private key does not correspond to cert");
  }

  /* end parse extra config */

  /*PKCS12 *PKCS12_create(char *pass, char *name, EVP_PKEY *pkey, X509 *cert, STACK_OF(X509) *ca,
                                     int nid_key, int nid_cert, int iter, int mac_iter, int keytype);*/

  p12 = PKCS12_create(pass, (char*)friendly_name, priv_key, cert, ca, 0, 0, 0, 0, 0);
  if (!p12)
    luaL_error(L, "PKCS12_careate failed,pleases get more error info");

  bio_out = BIO_new(BIO_s_mem());
  if (i2d_PKCS12_bio(bio_out, p12))
  {
    BUF_MEM *bio_buf;

    BIO_get_mem_ptr(bio_out, &bio_buf);
    lua_pushlstring(L, bio_buf->data, bio_buf->length);
    BIO_free(bio_out);
    PKCS12_free(p12);
    return 1;
  }
  PKCS12_free(p12);

  return 0;
}

static LUA_FUNCTION(openssl_pkcs12_read)
{
  const char *pass, *zp12;
  size_t zp12_len;
  PKCS12 * p12 = NULL;
  EVP_PKEY * pkey = NULL;
  X509 * cert = NULL;
  STACK_OF(X509) * ca = NULL;
  BIO * bio_in = NULL;
  int base64 = 0;
  int olb64 = 0;
  BIO * b64 = NULL;

  zp12 = luaL_checklstring(L, 1, &zp12_len);
  pass = luaL_checkstring(L, 2);
  if (!lua_isnoneornil(L, 3))
    base64 = auxiliar_checkboolean(L, 3);
  if (!lua_isnoneornil(L, 4))
    olb64 = auxiliar_checkboolean(L, 4);

  bio_in = BIO_new(BIO_s_mem());
  BIO_write(bio_in, (void*)zp12, zp12_len);
  BIO_set_close(bio_in, BIO_NOCLOSE);
  if (base64)
  {
    if ((b64 = BIO_new(BIO_f_base64())) == NULL)
      return 0;
    if (olb64) BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio_in = BIO_push(b64, bio_in);
  }

  if (d2i_PKCS12_bio(bio_in, &p12) && PKCS12_parse(p12, pass, &pkey, &cert, &ca))
  {
    lua_newtable(L);

    AUXILIAR_SETOBJECT(L, cert, "openssl.x509" , -1, "cert");
    AUXILIAR_SETOBJECT(L, pkey, "openssl.evp_pkey" , -1, "pkey");
    AUXILIAR_SETOBJECT(L, ca, "openssl.stack_of_x509" , -1, "extracerts");

    return 1;
  }
  return 0;
}

static luaL_reg R[] =
{
  {"read",    openssl_pkcs12_read },
  {"export",    openssl_pkcs12_export  },

  {NULL,    NULL}
};

LUALIB_API int luaopen_pkcs12(lua_State *L)
{
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

