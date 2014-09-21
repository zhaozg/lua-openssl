/*=========================================================================*\
* ots.c
* timestamp module for lua-openssl binding
*
* Author:  george zhao <zhaozg(at)gmail.com>
\*=========================================================================*/
#include "openssl.h"
#include "private.h"
#include <stdint.h>

#define MYNAME    "ts"
#define MYVERSION MYNAME " library for " LUA_VERSION " / Nov 2014 / "\
  "based on OpenSSL " SHLIB_VERSION_NUMBER
#define MYTYPE      "ts"

#ifdef OPENSSL_HAVE_TS

#include <openssl/ts.h>

static ASN1_INTEGER *tsa_serial_cb(TS_RESP_CTX *ctx, void *data)
{
  lua_State *L = (lua_State*) data;
  ASN1_INTEGER *serial = NULL;

  lua_rawgeti(L, LUA_REGISTRYINDEX, (int)(intptr_t)ctx);
  if (lua_isnil(L, -1))
  {
    TS_RESP_CTX_set_status_info(ctx, TS_STATUS_REJECTION,
                                "could not generate serial number");

    return NULL;
  }

  if (lua_pcall(L, 0, 1, 0) == 0)
  {
    lua_Integer i = luaL_checkinteger(L, -1);
    serial = ASN1_INTEGER_new();
    ASN1_INTEGER_set(serial, (long)i);
    return serial;
  }
  TS_RESP_CTX_set_status_info(ctx, TS_STATUS_REJECTION,
                              "could not generate serial number");

  return NULL;

  /* Acquire an exclusive lock for the serial file. */
  /*********************************************************
   * Merge server id and serial number                     *
   * example : server_id = 0x0F , serial = 2               *
   *           result = 0x0F2                              *
   * Modification made by JOUVE <opentsa@jouve-hdi.com>    *
   *********************************************************/
}

/*  openssl.ts_resp_ctx_newsign(x509 signer, evp_pkey pkey, string def_policy, table options[, stack_of_x509 certs=nil] ) -> ts_resp_ctx {{{1
*/

static LUA_FUNCTION(openssl_ts_resp_ctx_new)
{
  X509 *signer =   CHECK_OBJECT(1, X509, "openssl.x509");
  EVP_PKEY *pkey = CHECK_OBJECT(2, EVP_PKEY, "openssl.evp_pkey");
  STACK_OF(X509) *certs = lua_isnoneornil(L, 3) ? NULL : CHECK_OBJECT(3, STACK_OF(X509), "openssl.stack_of_x509");
  const char* def_policy = luaL_optstring(L, 4, "1.1.2");
  int options = 5;

  ASN1_OBJECT *oid = NULL;
  char buffer[1024];

  TS_RESP_CTX* ctx = TS_RESP_CTX_new();

  if (!X509_check_private_key(signer, pkey))
  {
    lua_pushnil(L);
    lua_pushstring(L, "signer cert don't match with privatekey");
    return 2;
  }
  if (!TS_RESP_CTX_set_signer_cert(ctx, signer))
  {
    lua_pushnil(L);
    lua_pushstring(L, "signer cert don't support timestamp sign");
    return 2;
  }
  TS_RESP_CTX_set_signer_key(ctx, pkey);
  if (certs) TS_RESP_CTX_set_certs(ctx, certs);

  oid = OBJ_txt2obj(def_policy, 0);
  if (oid)
  {
    TS_RESP_CTX_set_def_policy(ctx, oid);
    OBJ_obj2txt(buffer, sizeof(buffer), oid, 0);
  }

  if (lua_isnoneornil(L, 5))
  {
    lua_newtable(L);
    lua_replace(L, 5);
  }

  luaL_checktype(L, options, LUA_TTABLE);

  lua_getfield(L, options, "digest");
  if (lua_isnil(L, -1))
  {
    lua_pop(L, 1);
    //set default digets
    lua_newtable(L);
    lua_pushstring(L, "md5");
    lua_rawseti(L, -2, 1);
    lua_pushstring(L, "sha1");
    lua_rawseti(L, -2, 2);
    //lua_setfield(L,-2,"digest");
  }

  if (lua_istable(L, -1))
  {
    int i;
    int len = lua_objlen(L, -1);
    for (i = 1; i <= len; i++)
    {
      const char* p;
      const EVP_MD *md_obj;
      lua_rawgeti(L, -1, i);
      p = lua_tostring(L, -1);
      md_obj = EVP_get_digestbyname(p);
      TS_RESP_CTX_add_md(ctx, md_obj);
      lua_pop(L, 1);
    }
  }
  lua_pop(L, 1);

  lua_getfield(L, options, "policy");
  if (lua_isnil(L, -1))
  {
    lua_pop(L, 1);
    //set default policy
    lua_newtable(L);
    lua_pushstring(L, "1.1.3");
    lua_rawseti(L, -2, 1);
    lua_pushstring(L, "1.1.4");
    lua_rawseti(L, -2, 2);
    //lua_setfield(L,-2,"policy");
  }

  if (lua_istable(L, -1))
  {
    int i;
    int len = lua_objlen(L, -1);
    for (i = 1; i <= len; i++)
    {
      ASN1_OBJECT *oid = NULL;
      char buffer[1024];

      const char* p;
      lua_rawgeti(L, -1, i);
      p = lua_tostring(L, -1);

      oid = OBJ_txt2obj(p, 0);
      if (oid)
      {
        if (TS_RESP_CTX_add_policy(ctx, oid))
          OBJ_obj2txt(buffer, sizeof(buffer), oid, 0);
      }
      lua_pop(L, 1);
    }
  }
  lua_pop(L, 1);


  lua_getfield(L, options, "accuracy");
  if (lua_istable(L, -1))
  {
    int secs, millisecs, microsecs;
    lua_getfield(L, -1, "seconds");
    secs = lua_tointeger(L, -1);
    lua_pop(L, 1);
    lua_getfield(L, -1, "millisecs");
    millisecs = lua_tointeger(L, -1);
    lua_pop(L, 1);
    lua_getfield(L, -1, "microsecs");
    microsecs = lua_tointeger(L, -1);
    lua_pop(L, 1);
    TS_RESP_CTX_set_accuracy(ctx, secs, millisecs, microsecs);
  }
  lua_pop(L, 1);


  lua_getfield(L, options, "precision");
  if (!lua_isnil(L, -1))
  {
    int precision = lua_tointeger(L, -1);
    TS_RESP_CTX_set_clock_precision_digits(ctx, precision);
  }
  lua_pop(L, 1);


  lua_getfield(L, options, "ordering");
  if (!lua_isnil(L, -1))
  {
    if (lua_toboolean(L, -1))
      TS_RESP_CTX_add_flags(ctx, TS_ORDERING);
  }
  lua_pop(L, 1);

  lua_getfield(L, options, "inc_name");
  if (!lua_isnil(L, -1))
  {
    if (lua_toboolean(L, -1))
      TS_RESP_CTX_add_flags(ctx, TS_TSA_NAME);
  }
  lua_pop(L, 1);

  lua_getfield(L, options, "ess_ids");
  if (!lua_isnil(L, -1))
  {
    if (lua_toboolean(L, -1))
      TS_RESP_CTX_add_flags(ctx, TS_ESS_CERT_ID_CHAIN);
  }
  lua_pop(L, 1);

  if (lua_isfunction(L, 6))
  {
    lua_pushvalue(L, 6);
    lua_rawseti(L, LUA_REGISTRYINDEX, (int)(intptr_t)ctx);
    TS_RESP_CTX_set_serial_cb(ctx, tsa_serial_cb, L);
  }

  PUSH_OBJECT(ctx, "openssl.ts_resp_ctx");
  return 1;
}

static LUA_FUNCTION(openssl_ts_sign)
{
  TS_RESP_CTX *ctx = CHECK_OBJECT(1, TS_RESP_CTX, "openssl.ts_resp_ctx");
  BIO *bio = NULL;
  TS_RESP * resp;
  if (lua_isstring(L, 2))
  {
    bio = load_bio_object(L, 2);
  }
  else
  {
    TS_REQ *req = CHECK_OBJECT(2, TS_REQ, "openssl.ts_req");
    bio = BIO_new(BIO_s_mem());
    i2d_TS_REQ_bio(bio, req);
  }

  resp  = TS_RESP_create_response(ctx, bio);
  if (resp)
  {
    PUSH_OBJECT(resp, "openssl.ts_resp");
  }
  else
    lua_pushnil(L);
  BIO_free(bio);

  return 1;
}

static LUA_FUNCTION(openssl_ts_resp_ctx_gc)
{
  TS_RESP_CTX *ctx = CHECK_OBJECT(1, TS_RESP_CTX, "openssl.ts_resp_ctx");
  TS_RESP_CTX_free(ctx);
  return 0;
}

static LUA_FUNCTION(openssl_ts_req_new)
{
  size_t l;
  const char* hash = luaL_checklstring(L, 1, &l);
  const char* hash_alg = luaL_checkstring(L, 2);
  int option = lua_gettop(L) > 2 ? 3 : 0;
  TS_REQ *ts_req;

  if (option > 0)
    luaL_checktype(L, option, LUA_TTABLE);

  ts_req = TS_REQ_new();
  if (ts_req != NULL)
  {
    X509_ALGOR *algo = X509_ALGOR_new();
    TS_REQ_set_version(ts_req, 1);
    if (algo != NULL)
    {
      algo->algorithm = OBJ_txt2obj(hash_alg, 0);
      algo->parameter = ASN1_TYPE_new();
      if (algo->algorithm && algo->parameter)
      {

        TS_MSG_IMPRINT *msg_imprint = TS_MSG_IMPRINT_new();
        algo->parameter->type = V_ASN1_NULL;

        if (msg_imprint != NULL)
        {
          if (TS_MSG_IMPRINT_set_algo(msg_imprint, algo))
          {
            if (TS_MSG_IMPRINT_set_msg(msg_imprint, (unsigned char*)hash, l))
            {
              if (TS_REQ_set_msg_imprint(ts_req, msg_imprint))
              {
                if (option > 0)
                {
                  lua_getfield(L, option, "version");
                  if (!lua_isnil(L, -1))
                  {
                    int version = luaL_optint(L, -1, 1);
                    TS_REQ_set_version(ts_req, version);
                  }
                  lua_pop(L, 1);

                  lua_getfield(L, option, "policy");
                  if (!lua_isnil(L, -1))
                  {
                    const char* policy = luaL_checkstring(L, -1);
                    ASN1_OBJECT *policy_obj = OBJ_txt2obj(policy, 0);
                    if (policy_obj)
                    {
                      TS_REQ_set_policy_id(ts_req, policy_obj);
                    }
                  }
                  lua_pop(L, 1);

                  lua_getfield(L, option, "nonce");
                  if (!lua_isnil(L, -1))
                  {
                    int nonce = lua_tointeger(L, -1);
                    ASN1_INTEGER *asn_nonce = ASN1_INTEGER_new();
                    ASN1_INTEGER_set(asn_nonce, nonce);
                    TS_REQ_set_nonce(ts_req, asn_nonce);
                  }
                  lua_pop(L, 1);

                  lua_getfield(L, option, "cert_req");
                  if (!lua_isnil(L, -1))
                  {
                    TS_REQ_set_cert_req(ts_req, lua_tointeger(L, -1));
                  }
                  lua_pop(L, 1);
                }
                PUSH_OBJECT(ts_req, "openssl.ts_req");
                return 1;
              }
            }
          }
        }
        if (msg_imprint)
        {
          TS_MSG_IMPRINT_free(msg_imprint);
          msg_imprint = NULL;
        }
      }

    }

    if (algo)
    {
      X509_ALGOR_free(algo);
      algo = NULL;
    }
  }
  if (ts_req)
  {
    TS_REQ_free(ts_req);
    ts_req = NULL;

  }
  return 0;
}

static LUA_FUNCTION(openssl_ts_req_gc)
{
  TS_REQ *req = CHECK_OBJECT(1, TS_REQ, "openssl.ts_req");
  TS_REQ_free(req);
  return 0;
}


static LUA_FUNCTION(openssl_ts_req_to_verify_ctx)
{
  TS_REQ *req = CHECK_OBJECT(1, TS_REQ, "openssl.ts_req");
  TS_VERIFY_CTX *ctx = TS_REQ_to_TS_VERIFY_CTX(req, NULL);
  PUSH_OBJECT(ctx, "openssl.ts_verify_ctx");
  return 1;
}

static LUA_FUNCTION(openssl_ts_req_parse)
{
  TS_REQ *req = CHECK_OBJECT(1, TS_REQ, "openssl.ts_req");
  BIO* bio = BIO_new(BIO_s_mem());

  lua_newtable(L);
#if 0
  typedef struct TS_req_st
  {
    ASN1_INTEGER *version;
    TS_MSG_IMPRINT *msg_imprint;
    ASN1_OBJECT *policy_id;   /* OPTIONAL */
    ASN1_INTEGER *nonce;    /* OPTIONAL */
    ASN1_BOOLEAN cert_req;    /* DEFAULT FALSE */
    STACK_OF(X509_EXTENSION) *extensions; /* [0] OPTIONAL */
  } TS_REQ;
#endif
  PUSH_ASN1_INTEGER(L, req->version);
  lua_setfield(L, -2, "version");

  AUXILIAR_SET(L, -1, "cert_req", req->cert_req, boolean);

  if (req->policy_id){
    openssl_push_asn1object(L, req->policy_id);
    lua_setfield(L, -2, "policy_id");
  }
  if (req->nonce){
    PUSH_ASN1_INTEGER(L, req->nonce);
    lua_setfield(L, -2, "nonce");
  }
  lua_newtable(L);
  {
    ASN1_OCTET_STRING *os = req->msg_imprint->hashed_msg;
    AUXILIAR_SETLSTR(L, -1, "content", (const char*)os->data, os->length);
    openssl_push_x509_algor(L, req->msg_imprint->hash_algo);
    lua_setfield(L, -2, "hash_algo");
  }
  lua_setfield(L, -2, "msg_imprint");


  if (req->extensions)
  {
    AUXILIAR_SETOBJECT(L, req->extensions, "openssl.stack_of_x509_extension", -1, "extensions");
  }


  BIO_free(bio);

  return 1;
}

static LUA_FUNCTION(openssl_ts_req_i2d)
{
  TS_REQ *req = CHECK_OBJECT(1, TS_REQ, "openssl.ts_req");

  BIO *bio = BIO_new(BIO_s_mem());

  if (i2d_TS_REQ_bio(bio, req))
  {
    BUF_MEM *bptr = NULL;
    BIO_get_mem_ptr(bio, &bptr);
    lua_pushlstring(L, bptr->data, bptr->length);
    BIO_free(bio);
    return 1;
  }
  BIO_free(bio);
  return 0;
}

static LUA_FUNCTION(openssl_ts_req_d2i)
{
  size_t l;
  const char* buf = luaL_checklstring(L, 1, &l);

  TS_REQ *req = d2i_TS_REQ(NULL, (const byte**)&buf, l);
  PUSH_OBJECT(req, "openssl.ts_req");
  return 1;
}
//////////////////////////////////////////////////////////////////////////

static LUA_FUNCTION(openssl_ts_resp_gc)
{
  TS_RESP *res = CHECK_OBJECT(1, TS_RESP, "openssl.ts_resp");
  TS_RESP_free(res);
  return 0;
}

static LUA_FUNCTION(openssl_ts_resp_i2d)
{
  TS_RESP *res = CHECK_OBJECT(1, TS_RESP, "openssl.ts_resp");

  BIO *bio = BIO_new(BIO_s_mem());

  if (i2d_TS_RESP_bio(bio, res))
  {
    BUF_MEM *bptr = NULL;
    BIO_get_mem_ptr(bio, &bptr);
    lua_pushlstring(L, bptr->data, bptr->length);
    BIO_free(bio);
    return 1;
  }
  return 0;
}

static LUA_FUNCTION(openssl_ts_resp_parse)
{
  TS_RESP *res = CHECK_OBJECT(1, TS_RESP, "openssl.ts_resp");

  BIO* bio = BIO_new(BIO_s_mem());
  lua_newtable(L);

  {
    lua_newtable(L);
    PUSH_ASN1_INTEGER(L, res->status_info->status);
    lua_setfield(L, -2, "status");

    if (res->status_info->failure_info)
    {
      PUSH_ASN1_BIT_STRING(L, res->status_info->failure_info);
      lua_setfield(L, -2, "failure_info");
    }

    if (res->status_info->text)
    {
      STACK_OF(ASN1_UTF8STRING) * sk = res->status_info->text;
      int i = 0, n = 0;
      lua_newtable(L);
      n = SKM_sk_num(ASN1_UTF8STRING, sk);
      for (i = 0; i < n; i++)
      {
        ASN1_UTF8STRING *x =  SKM_sk_value(ASN1_UTF8STRING, sk, i);
        lua_pushlstring(L, (const char*)x->data, x->length);
        lua_rawseti(L, -2, i + 1);
      }
      lua_setfield(L, -2, "text");
    }

    lua_setfield(L, -2, "status_info");
  }


  if (res->token)
  {
    AUXILIAR_SETOBJECT(L, PKCS7_dup(res->token), "openssl.pkcs7", -1, "token");
  }


  if (res->tst_info)
  {
    TS_TST_INFO *info = res->tst_info;
    lua_newtable(L);
    if (info->version){
      PUSH_ASN1_INTEGER(L, info->version);
      lua_setfield(L, -2, "version");
    }
    if (info->serial){
      PUSH_ASN1_INTEGER(L, info->serial);
      lua_setfield(L, -2, "serial");
    }
    if (info->nonce){
      PUSH_ASN1_INTEGER(L, info->nonce);
      lua_setfield(L, -2, "nonce");
    }
    if (info->time){
      PUSH_ASN1_GENERALIZEDTIME(L, info->time);
      lua_setfield(L, -2, "time");
    }
    if (info->policy_id){
      openssl_push_asn1object(L, info->policy_id);
      lua_setfield(L, -2, "policy_id");
    }

    AUXILIAR_SET(L, -1, "ordering", info->ordering, boolean);

    if (info->msg_imprint)
    {
      ASN1_OCTET_STRING *os = info->msg_imprint->hashed_msg;
      lua_newtable(L);

      AUXILIAR_SETLSTR(L, -1, "content", (const char*)os->data, os->length);
      openssl_push_x509_algor(L, info->msg_imprint->hash_algo);
      lua_setfield(L, -2, "hash_algo");

      lua_setfield(L, -2, "msg_imprint");
    }

    if (info->accuracy)
    {
      lua_newtable(L);
      PUSH_ASN1_INTEGER(L, info->accuracy->micros);
      lua_setfield(L, -2, "micros");
      PUSH_ASN1_INTEGER(L, info->accuracy->millis);
      lua_setfield(L, -2, "millis");
      PUSH_ASN1_INTEGER(L, info->accuracy->seconds);
      lua_setfield(L, -2, "seconds");

      lua_setfield(L, -2, "accuracy");
    }
    if (info->tsa){
      openssl_push_xname_asobject(L, info->tsa->d.dirn);
      lua_setfield(L, -2, "tsa");
    }


    if (info->extensions)
    {
      AUXILIAR_SETOBJECT(L, info->extensions, "openssl.stack_of_x509_extension", -1, "extensions");
    }

    lua_setfield(L, -2, "tst_info");
  }

  BIO_free(bio);

  return 1;
}

static LUA_FUNCTION(openssl_ts_resp_d2i)
{
  size_t len;
  const unsigned char* buf = (const unsigned char*)luaL_checklstring(L, 1, &len);
  const unsigned char** p = &buf;
  TS_RESP *res = d2i_TS_RESP(NULL, p, len);
  if (res)
  {
    PUSH_OBJECT(res, "openssl.ts_resp");
  }
  else
    lua_pushnil(L);
  return 1;
}

static LUA_FUNCTION(openssl_ts_resp_tst_info)
{
  TS_RESP *resp = CHECK_OBJECT(1, TS_RESP, "openssl.ts_resp");
  TS_TST_INFO *info = resp->tst_info;
  BIO *bio = BIO_new(BIO_s_mem());
  BUF_MEM *bio_buf;
  i2d_TS_TST_INFO_bio(bio, info);


  BIO_get_mem_ptr(bio, &bio_buf);
  lua_pushlstring(L, bio_buf->data, bio_buf->length);
  BIO_free(bio);
  return 1;
}


//////////////////////////////////////////////////////////////////////////
static X509_STORE* Stack2Store(STACK_OF(X509)* sk)
{
  X509_STORE *store = NULL;
  int i;

  /* Creating the X509_STORE object. */
  store = X509_STORE_new();
  /* Setting the callback for certificate chain verification. */
  X509_STORE_set_verify_cb(store, NULL);

  for (i = 0; i < sk_X509_num(sk); i++)
  {
    X509_STORE_add_cert(store, sk_X509_value(sk, i));
  };

  return store;
}

/*  openssl.ts_verify_ctx_new(
  openssl.ts_req  --tsa request object
  |string,  --der encode tsa request
  |{source=raw dat,digest=md value}
  ,
  openssl.stack_of_x509|openssl.x509 --ca certificate
  openssl.stack_of_x509|openssl.x509 --others certificate
  )
*/

static LUA_FUNCTION(openssl_ts_verify_ctx_new)
{
  TS_VERIFY_CTX *ctx = NULL;

  if (auxiliar_isclass(L, "openssl.ts_req", 1))
  {
    TS_REQ* req = CHECK_OBJECT(1, TS_REQ, "openssl.ts_req");
    ctx = TS_REQ_to_TS_VERIFY_CTX(req, NULL);
  }
  else if (lua_isstring(L, 1))
  {
    BIO* bio = load_bio_object(L, 1);
    TS_REQ* req = d2i_TS_REQ_bio(bio, NULL);
    ctx = TS_REQ_to_TS_VERIFY_CTX(req, NULL);
    BIO_free(bio);
  }
  else if (lua_istable(L, 1))
  {
    ctx = TS_VERIFY_CTX_new();
    TS_VERIFY_CTX_init(ctx);
    ctx->flags = TS_VFY_VERSION;
    lua_getfield(L, 1, "digest");
    if (!lua_isnil(L, -1))
    {
      size_t l;
      const char*data = luaL_checklstring(L, -1, &l);
      ctx->flags |= TS_VFY_IMPRINT;
      ctx->imprint_len = l;
      ctx->imprint = (unsigned char*)data;

    }
    lua_pop(L, 1);

    lua_getfield(L, 1, "source");
    if (!lua_isnil(L, -1))
    {
      ctx->flags |= TS_VFY_DATA;
      ctx->data = load_bio_object(L, -1);
    }
    lua_pop(L, 1);
  }
  if (ctx)
  {
    if (lua_type(L, 2) == LUA_TUSERDATA)
    {
      if (auxiliar_isclass(L, "openssl.stack_of_x509", 2))
      {
        STACK_OF(X509) *cas = CHECK_OBJECT(2, STACK_OF(X509), "openssl.stack_of_x509");
        ctx->store = Stack2Store(cas);
      }
      else if (auxiliar_isclass(L, "openssl.x509", 2))
      {
        X509* x = auxiliar_checkclass(L, "openssl.x509", 2);
        ctx->store = X509_STORE_new();
        X509_STORE_add_cert(ctx->store, x);
        CRYPTO_add(&x->references, 1, CRYPTO_LOCK_X509);
      }
      else
      {
        luaL_argerror(L, 2, "must be a object of openssl.stack_of_x509 or openssl.x509");
      }
      ctx->flags |= TS_VFY_SIGNER;
      ctx->flags |= TS_VFY_SIGNATURE;

      if (!lua_isnoneornil(L, 3))
      {
        if (auxiliar_isclass(L, "openssl.stack_of_x509", 3))
        {
          ctx->certs = sk_X509_dup(CHECK_OBJECT(3, STACK_OF(X509), "openssl.stack_of_x509"));
        }
        else if (auxiliar_isclass(L, "openssl.x509", 3))
        {
          X509* x = auxiliar_checkclass(L, "openssl.x509", 3);
          ctx->certs = sk_X509_new_null();
          sk_X509_push(ctx->certs, x);
          CRYPTO_add(&x->references, 1, CRYPTO_LOCK_X509);
        }
        else
        {
          luaL_argerror(L, 3, "must be a object of openssl.stack_of_x509 or openssl.x509");
        }
      }
    }
    else
      luaL_argerror(L, 2, "must be a object of openssl.stack_of_x509 or openssl.x509");

    PUSH_OBJECT(ctx, "openssl.ts_verify_ctx");
  }
  else
    lua_pushnil(L);
  return 1;
}

static LUA_FUNCTION(openssl_ts_verify_ctx_gc)
{
  TS_VERIFY_CTX *ctx = CHECK_OBJECT(1, TS_VERIFY_CTX, "openssl.ts_verify_ctx");
  TS_VERIFY_CTX_free(ctx);
  //void TS_VERIFY_CTX_cleanup(TS_VERIFY_CTX *ctx);
  return 0;
}

static LUA_FUNCTION(openssl_ts_verify_ctx_response)
{
  TS_VERIFY_CTX *ctx = CHECK_OBJECT(1, TS_VERIFY_CTX, "openssl.ts_verify_ctx");
  TS_RESP *response = CHECK_OBJECT(2, TS_RESP, "openssl.ts_resp");
  int ret = TS_RESP_verify_response(ctx, response);
  lua_pushboolean(L, ret);
  return 1;
}

static LUA_FUNCTION(openssl_ts_verify_ctx_token)
{
  TS_VERIFY_CTX *ctx = CHECK_OBJECT(1, TS_VERIFY_CTX, "openssl.ts_verify_ctx");
  PKCS7 *token = CHECK_OBJECT(2, PKCS7, "openssl.pkcs7");
  int ret = TS_RESP_verify_token(ctx, token);
  lua_pushboolean(L, ret);
  return 1;
}

//////////////////////////////////////////////////////////////////////////
static luaL_Reg ts_req_funs[] =
{
  {"__tostring", auxiliar_tostring},
  {"parse", openssl_ts_req_parse},
  {"i2d", openssl_ts_req_i2d},
  {"__gc", openssl_ts_req_gc},
  {"to_verify_ctx", openssl_ts_req_to_verify_ctx},

  { NULL, NULL }
};

static luaL_Reg ts_resp_funs[] =
{
  {"__tostring", auxiliar_tostring},
  {"i2d", openssl_ts_resp_i2d},
  {"parse", openssl_ts_resp_parse},
  {"__gc", openssl_ts_resp_gc},
  {"tst_info", openssl_ts_resp_tst_info},

  { NULL, NULL }
};

static luaL_Reg ts_resp_ctx_funs[] =
{
  {"__tostring", auxiliar_tostring},
  {"__gc", openssl_ts_resp_ctx_gc},
  {"sign", openssl_ts_sign},

  { NULL, NULL }
};

static luaL_Reg ts_verify_ctx_funs[] =
{
  {"__tostring",  auxiliar_tostring},
  {"__gc",    openssl_ts_verify_ctx_gc},
  {"verify_response",   openssl_ts_verify_ctx_response},
  {"verify_token",    openssl_ts_verify_ctx_token},

  { NULL, NULL }
};

static luaL_reg R[] =
{
  {"req_new",   openssl_ts_req_new  },
  {"req_d2i",   openssl_ts_req_d2i  },
  {"resp_d2i",    openssl_ts_resp_d2i },
  {"resp_ctx_new",    openssl_ts_resp_ctx_new },
  {"verify_ctx_new",  openssl_ts_verify_ctx_new },

  {NULL,    NULL}
};

LUALIB_API int luaopen_ts(lua_State *L)
{
  auxiliar_newclass(L, "openssl.ts_req",   ts_req_funs);
  auxiliar_newclass(L, "openssl.ts_resp",    ts_resp_funs);
  auxiliar_newclass(L, "openssl.ts_resp_ctx",  ts_resp_ctx_funs);
  auxiliar_newclass(L, "openssl.ts_verify_ctx",  ts_verify_ctx_funs);

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

#endif
