/*=========================================================================*\
* ots.c
* timestamp module for lua-openssl binding
*
* Author:  george zhao <zhaozg(at)gmail.com>
\*=========================================================================*/
#include "openssl.h"
#include "private.h"
#include <stdint.h>
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
#include <openssl/ts.h>

#define MYNAME    "ts"
#define MYVERSION MYNAME " library for " LUA_VERSION " / Nov 2014 / "\
  "based on OpenSSL " SHLIB_VERSION_NUMBER

static int openssl_ts_req_dup(lua_State*L)
{
  TS_REQ* req = CHECK_OBJECT(1, TS_REQ, "openssl.ts_req");
  req = TS_REQ_dup(req);
  PUSH_OBJECT(req, "openssl.ts_req");
  return 1;
}

static int openssl_ts_req_cert_req(lua_State *L)
{
  TS_REQ* req = CHECK_OBJECT(1, TS_REQ, "openssl.ts_req");
  if (lua_isnone(L, 2))
  {
    lua_pushboolean(L, TS_REQ_get_cert_req(req));
    return 1;
  }
  else
  {
    int cert_req = auxiliar_checkboolean(L, 2);
    int ret = TS_REQ_set_cert_req(req, cert_req);
    return openssl_pushresult(L, ret);
  }
}

static int openssl_ts_req_nonce(lua_State*L)
{
  TS_REQ* req = CHECK_OBJECT(1, TS_REQ, "openssl.ts_req");
  if (lua_isnone(L, 2))
  {
    const ASN1_INTEGER* ai = TS_REQ_get_nonce(req);
    BIGNUM *bn;
    PUSH_ASN1_INTEGER(L, ai);
    bn = ASN1_INTEGER_to_BN(ai, NULL);
    PUSH_OBJECT(bn, "openssl.bn");
    return 2;
  }
  else
  {
    BIGNUM *bn = BN_get(L, 2);
    ASN1_INTEGER *ai = BN_to_ASN1_INTEGER(bn, NULL);
    int ret = TS_REQ_set_nonce(req, ai);
    ASN1_INTEGER_free(ai);
    BN_free(bn);
    return openssl_pushresult(L, ret);
  }
}

static int openssl_ts_req_policy_id(lua_State*L)
{
  TS_REQ* req = CHECK_OBJECT(1, TS_REQ, "openssl.ts_req");
  if (lua_isnone(L, 2))
  {
    ASN1_OBJECT* obj = TS_REQ_get_policy_id(req);
    openssl_push_asn1object(L, obj);
    ASN1_OBJECT_free(obj);
    return 1;
  }
  else
  {
    int nid = openssl_get_nid(L, 2);
    ASN1_OBJECT* obj;
    int ret;
    luaL_argcheck(L, nid != NID_undef, 2, "must be asn1_object object identified");
    obj = OBJ_nid2obj(nid);
    ret = TS_REQ_set_policy_id(req, obj);
    return openssl_pushresult(L, ret);
  }
}

static int openssl_ts_req_version(lua_State*L)
{
  TS_REQ* req = CHECK_OBJECT(1, TS_REQ, "openssl.ts_req");
  if (lua_isnone(L, 2))
  {
    lua_pushinteger(L, TS_REQ_get_version(req));
    return 1;
  }
  else
  {
    long v = luaL_checkinteger(L, 2);
    int ret = TS_REQ_set_version(req, v);
    return openssl_pushresult(L, ret);
  }
}

static int openssl_ts_req_msg_imprint(lua_State*L)
{
  TS_REQ* req = CHECK_OBJECT(1, TS_REQ, "openssl.ts_req");
  if (lua_isnone(L, 2))
  {
    TS_MSG_IMPRINT * msg = TS_REQ_get_msg_imprint(req);
    if (msg)
    {
      ASN1_OCTET_STRING *s = TS_MSG_IMPRINT_get_msg(msg);
      X509_ALGOR *a = TS_MSG_IMPRINT_get_algo(msg);
      PUSH_ASN1_OCTET_STRING(L, s);
      openssl_push_x509_algor(L, a);
      ASN1_OCTET_STRING_free(s);
      X509_ALGOR_free(a);
      return 2;
    }
    return 1;
  }
  else
  {
    size_t size;
    const char* data = luaL_checklstring(L, 2, &size);
    const EVP_MD* md = lua_isnoneornil(L, 3)
                       ? EVP_get_digestbyname("sha1")
                       : get_digest(L, 3);
    TS_MSG_IMPRINT *msg = TS_MSG_IMPRINT_new();
    int ret = TS_MSG_IMPRINT_set_msg(msg, (unsigned char*)data, size);
    if (ret == 1)
    {
      X509_ALGOR* alg = X509_ALGOR_new();
      X509_ALGOR_set_md(alg, md);
      if (ret == 1)
      {
        ret = TS_MSG_IMPRINT_set_algo(msg, alg);
        if (ret == 1)
          ret = TS_REQ_set_msg_imprint(req, msg);
      }
      X509_ALGOR_free(alg);
    }
    TS_MSG_IMPRINT_free(msg);

    return openssl_pushresult(L, ret);
  }
};

static LUA_FUNCTION(openssl_ts_req_new)
{
  TS_REQ *ts_req = TS_REQ_new();
  long version = luaL_optinteger(L, 1, 1);

  int ret = TS_REQ_set_version(ts_req, version);
  if (ret == 1)
  {
    PUSH_OBJECT(ts_req, "openssl.ts_req");
    return 1;
  }
  TS_REQ_free(ts_req);
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

static LUA_FUNCTION(openssl_ts_req_read)
{
  BIO *in = load_bio_object(L, 1);
  TS_REQ *ts_req = d2i_TS_REQ_bio(in, NULL);
  BIO_free(in);
  if (ts_req)
  {
    PUSH_OBJECT(ts_req, "openssl.ts_req");
    return 1;
  }
  return 0;
}

static LUA_FUNCTION(openssl_ts_req_export)
{
  TS_REQ *ts_req = CHECK_OBJECT(1, TS_REQ, "openssl.ts_req");
  unsigned char *data = NULL;
  int len = i2d_TS_REQ(ts_req, &data);
  if (len > 0)
  {
    lua_pushlstring(L, (const char*)data, (size_t)len);
    OPENSSL_free(data);
    return 1;
  }
  return 0;
}

static LUA_FUNCTION(openssl_ts_req_info)
{
  TS_REQ *req = CHECK_OBJECT(1, TS_REQ, "openssl.ts_req");

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

  if (req->policy_id)
  {
    openssl_push_asn1object(L, req->policy_id);
    lua_setfield(L, -2, "policy_id");
  }
  if (req->nonce)
  {
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
    lua_pushstring(L, "extensions");
    openssl_sk_x509_extension_totable(L, req->extensions);
    lua_rawset(L, -3);
  }

  return 1;
}

static luaL_Reg ts_req_funs[] =
{
  {"dup",           openssl_ts_req_dup},
  {"cert_req",      openssl_ts_req_cert_req},
  {"msg_imprint",   openssl_ts_req_msg_imprint},
  {"nonce",         openssl_ts_req_nonce},
  {"policy_id",     openssl_ts_req_policy_id},
  {"version",       openssl_ts_req_version},
  {"info",          openssl_ts_req_info},
  {"export",        openssl_ts_req_export},

  {"to_verify_ctx", openssl_ts_req_to_verify_ctx},

  {"__tostring",    auxiliar_tostring},
  {"__gc",          openssl_ts_req_gc},

  { NULL, NULL }
};

/***********************************************************/
static ASN1_INTEGER *tsa_serial_cb(TS_RESP_CTX *ctx, void *data)
{
  lua_State *L = (lua_State*) data;
  ASN1_INTEGER *serial = NULL;

  lua_rawgetp(L, LUA_REGISTRYINDEX, ctx);
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

/**************************************************************/
static LUA_FUNCTION(openssl_ts_resp_gc)
{
  TS_RESP *res = CHECK_OBJECT(1, TS_RESP, "openssl.ts_resp");
  TS_RESP_free(res);
  return 0;
}

static LUA_FUNCTION(openssl_ts_resp_dup)
{
  TS_RESP *res = CHECK_OBJECT(1, TS_RESP, "openssl.ts_resp");
  res = TS_RESP_dup(res);
  PUSH_OBJECT(res, "openssl.ts_resp");
  return 1;
}

static LUA_FUNCTION(openssl_ts_resp_export)
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

static int openssl_push_ts_accuracy(lua_State*L, const TS_ACCURACY* accuracy)
{
  lua_newtable(L);
  PUSH_ASN1_INTEGER(L, accuracy->micros);
  lua_setfield(L, -2, "micros");
  PUSH_ASN1_INTEGER(L, accuracy->millis);
  lua_setfield(L, -2, "millis");
  PUSH_ASN1_INTEGER(L, accuracy->seconds);
  lua_setfield(L, -2, "seconds");

  return 1;
}

static int openssl_push_ts_msg_imprint(lua_State*L, TS_MSG_IMPRINT* imprint)
{
  X509_ALGOR* alg = TS_MSG_IMPRINT_get_algo(imprint);
  ASN1_STRING* str =  TS_MSG_IMPRINT_get_msg(imprint);
  lua_newtable(L);
  if (alg)
  {
    openssl_push_x509_algor(L, alg);
    lua_setfield(L, -2, "algo");
  }
  if (str)
  {
    PUSH_ASN1_OCTET_STRING(L, str);
    lua_setfield(L, -2, "msg");
  }

  return 1;
};

static int openssl_push_ts_tst_info(lua_State*L, TS_TST_INFO* info)
{
  lua_newtable(L);
  if (info->version)
  {
    PUSH_ASN1_INTEGER(L, info->version);
    lua_setfield(L, -2, "version");
  }
  if (info->policy_id)
  {
    openssl_push_asn1object(L, info->policy_id);
    lua_setfield(L, -2, "policy_id");
  }
  if (info->msg_imprint)
  {
    openssl_push_ts_msg_imprint(L, info->msg_imprint);
    lua_setfield(L, -2, "msg_imprint");
  }
  if (info->serial)
  {
    PUSH_ASN1_INTEGER(L, info->serial);
    lua_setfield(L, -2, "serial");
  }
  if (info->time)
  {
    openssl_push_asn1(L, info->time, V_ASN1_GENERALIZEDTIME);
    lua_setfield(L, -2, "time");
  }
  if (info->accuracy)
  {
    openssl_push_ts_accuracy(L, info->accuracy);
    lua_setfield(L, -2, "accuracy");
  }

  AUXILIAR_SET(L, -1, "ordering", info->ordering, boolean);

  if (info->nonce)
  {
    PUSH_ASN1_INTEGER(L, info->nonce);
    lua_setfield(L, -2, "nonce");
  }
  if (info->tsa)
  {
    openssl_push_general_name(L, info->tsa);
    lua_setfield(L, -2, "tsa");
  }
  if (info->extensions)
  {
    lua_pushstring(L, "extensions");
    openssl_sk_x509_extension_totable(L, info->extensions);
    lua_rawset(L, -3);
  }
  return 1;
}

static LUA_FUNCTION(openssl_ts_resp_tst_info)
{
  TS_RESP *resp = CHECK_OBJECT(1, TS_RESP, "openssl.ts_resp");
  TS_TST_INFO *info = resp->tst_info;
  if (info)
    openssl_push_ts_tst_info(L, info);
  else
    lua_pushnil(L);
  return 1;
}

static LUA_FUNCTION(openssl_ts_resp_info)
{
  TS_RESP *res = CHECK_OBJECT(1, TS_RESP, "openssl.ts_resp");

  lua_newtable(L);

  {
    lua_newtable(L);

    PUSH_ASN1_INTEGER(L, res->status_info->status);
    lua_setfield(L, -2, "status");

    if (res->status_info->failure_info)
    {
      openssl_push_asn1(L, res->status_info->failure_info, V_ASN1_BIT_STRING);
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
    PKCS7* token = PKCS7_dup(res->token);
    AUXILIAR_SETOBJECT(L, token, "openssl.pkcs7", -1, "token");
  }

  if (res->tst_info)
  {
    openssl_push_ts_tst_info(L, res->tst_info);
    lua_setfield(L, -2, "tst_info");
  }

  return 1;
}

static LUA_FUNCTION(openssl_ts_resp_read)
{
  BIO* in = load_bio_object(L, 1);
  TS_RESP *res = d2i_TS_RESP_bio(in, NULL);
  BIO_free(in);
  if (res)
  {
    PUSH_OBJECT(res, "openssl.ts_resp");
  }
  else
    lua_pushnil(L);
  return 1;
}

static luaL_Reg ts_resp_funs[] =
{
  {"dup",           openssl_ts_resp_dup},
  {"export",        openssl_ts_resp_export},
  {"info",          openssl_ts_resp_info},
  {"tst_info",      openssl_ts_resp_tst_info},

  {"__tostring",    auxiliar_tostring},
  {"__gc",          openssl_ts_resp_gc},

  { NULL, NULL }
};

/********************************************************/

static LUA_FUNCTION(openssl_ts_create_response)
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

static LUA_FUNCTION(openssl_ts_resp_ctx_new)
{
  TS_RESP_CTX* ctx = TS_RESP_CTX_new();
  int i = 0;
  int n = lua_gettop(L);
  X509 *signer = NULL;
  EVP_PKEY *pkey = NULL;
  int nid = NID_undef;
  int ret = 1;

  for (i = 1; i <= n; i++)
  {
    if (auxiliar_isclass(L, "openssl.x509", i))
    {
      signer = CHECK_OBJECT(i, X509, "openssl.x509");
    }
    else if (auxiliar_isclass(L, "openssl.evp_pkey", i))
    {
      pkey = CHECK_OBJECT(i, EVP_PKEY, "openssl.evp_pkey");
    }
    else if (lua_isnumber(L, i) || lua_isstring(L, i) || auxiliar_isclass(L, "openssl.asn1_object", i))
    {
      nid = openssl_get_nid(L, i);
      luaL_argcheck(L, nid != NID_undef, i, "invalid asn1_object or object id");
    }
    else
      luaL_argerror(L, i, "not accept paramater");
  }
  if (signer && pkey)
  {
    ret = X509_check_private_key(signer, pkey);
    if (ret != 1)
    {
      luaL_error(L, "singer cert and private key not match");
    }
  }
  if (ret == 1 && nid != NID_undef)
    ret = TS_RESP_CTX_set_def_policy(ctx, OBJ_nid2obj(nid));

  if (ret == 1 && signer)
    ret = TS_RESP_CTX_set_signer_cert(ctx, signer);
  if (ret == 1 && pkey)
    ret = TS_RESP_CTX_set_signer_key(ctx, pkey);

  if (ret == 1)
  {
    PUSH_OBJECT(ctx, "openssl.ts_resp_ctx");
    openssl_newvalue(L, ctx);
  }
  else
  {
    TS_RESP_CTX_free(ctx);
    ctx = NULL;
    lua_pushnil(L);
  }
  return 1;
}

static LUA_FUNCTION(openssl_ts_resp_ctx_singer)
{
  TS_RESP_CTX *ctx = CHECK_OBJECT(1, TS_RESP_CTX, "openssl.ts_resp_ctx");
  if (lua_isnone(L, 2))
  {
    if (ctx->signer_cert)
    {
      X509* x = ctx->signer_cert;
      x = X509_dup(x);
      PUSH_OBJECT(x, "openssl.x509");
    }
    else
      lua_pushnil(L);
    if (ctx->signer_key)
    {
      EVP_PKEY* pkey = ctx->signer_key;
      CRYPTO_add(&pkey->references, 1, CRYPTO_LOCK_EVP_PKEY);
      PUSH_OBJECT(pkey, "openssl.evp_pkey");
    }
    else
      lua_pushnil(L);
    return 2;
  }
  else
  {
    X509 *signer = CHECK_OBJECT(2, X509, "openssl.x509");
    EVP_PKEY *pkey = CHECK_OBJECT(3, EVP_PKEY, "openssl.evp_pkey");
    int ret = X509_check_private_key(signer, pkey);
    if (ret != 1)
    {
      luaL_error(L, "signer cert and private key not match");
    }
    if (ret == 1)
      ret = TS_RESP_CTX_set_signer_cert(ctx, signer);
    if (ret == 1)
      ret = TS_RESP_CTX_set_signer_key(ctx, pkey);
    return openssl_pushresult(L, ret);
  }
}

static LUA_FUNCTION(openssl_ts_resp_ctx_certs)
{
  TS_RESP_CTX *ctx = CHECK_OBJECT(1, TS_RESP_CTX, "openssl.ts_resp_ctx");
  if (lua_isnone(L, 2))
  {
    if (ctx->certs)
    {
      openssl_sk_x509_totable(L, ctx->certs);
    }
    else
    {
      lua_pushnil(L);
    };
  }
  else
  {
    if (ctx->certs)
    {
      sk_X509_pop_free(ctx->certs, X509_free);
    }
    ctx->certs = openssl_sk_x509_fromtable(L, 2);
    lua_pushboolean(L, 1);
  }
  return 1;
}

static LUA_FUNCTION(openssl_ts_resp_ctx_default_policy)
{
  TS_RESP_CTX *ctx = CHECK_OBJECT(1, TS_RESP_CTX, "openssl.ts_resp_ctx");
  if (lua_isnone(L, 2))
  {
    if (ctx->default_policy)
      openssl_push_asn1object(L, ctx->default_policy);
    else
      lua_pushnil(L);
  }
  else
  {
    int nid = openssl_get_nid(L, 2);
    if (ctx->default_policy)
      ASN1_OBJECT_free(ctx->default_policy);
    ctx->default_policy = OBJ_nid2obj(nid);
    lua_pushboolean(L, 1);
  }
  return 1;
}

static LUA_FUNCTION(openssl_ts_resp_ctx_policies)
{
  TS_RESP_CTX *ctx = CHECK_OBJECT(1, TS_RESP_CTX, "openssl.ts_resp_ctx");
  if (lua_isnone(L, 2))
  {
    if (ctx->policies)
    {
      int i, n;
      lua_newtable(L);
      n = sk_ASN1_OBJECT_num(ctx->policies);
      for (i = 0; i < n; i++)
      {
        ASN1_OBJECT* obj = sk_ASN1_OBJECT_value(ctx->policies, i);
        lua_pushinteger(L, i + 1);
        PUSH_OBJECT(obj, "openssl.asn1_object");
        lua_rawset(L, -3);
      }
    }
    else
      lua_pushnil(L);
  }
  else
  {
    if (lua_istable(L, 2))
    {

    }
    else
    {
      int n = lua_gettop(L);
      int ret = 1;
      int nid;
      int i;
      for (i = 2; i <= n && ret == 1; i++)
      {
        if (lua_istable(L, i))
        {
          int j, k;
          k = lua_rawlen(L, i);
          for (j = 1; j <= k && ret == 1; j++)
          {
            lua_rawgeti(L, i, j);
            nid = openssl_get_nid(L, -1);
            lua_pop(L, 1);

            if (nid != NID_undef)
            {
              ret = TS_RESP_CTX_add_policy(ctx, OBJ_nid2obj(nid));
            }
            else
            {
              lua_pushfstring(L, "index %d is invalid asn1_object or object id", j);
              luaL_argerror(L, i, lua_tostring(L, -1));
            }
          }
        }
        else
        {
          nid = openssl_get_nid(L, i);
          if (nid != NID_undef)
          {
            ret = TS_RESP_CTX_add_policy(ctx, OBJ_nid2obj(nid));
          }
          else
            luaL_argerror(L, i, "invalid asn1_object or id");
        }
      }
      return openssl_pushresult(L, ret);
    }
  }
  return 1;
}

static LUA_FUNCTION(openssl_ts_resp_ctx_accuracy)
{
  TS_RESP_CTX *ctx = CHECK_OBJECT(1, TS_RESP_CTX, "openssl.ts_resp_ctx");
  if (lua_isnone(L, 2))
  {
    lua_pushinteger(L, ASN1_INTEGER_get(ctx->seconds));
    lua_pushinteger(L, ASN1_INTEGER_get(ctx->millis));
    lua_pushinteger(L, ASN1_INTEGER_get(ctx->micros));
    return 3;
  }
  else
  {
    int seconds = luaL_checkint(L, 2);
    int millis  = luaL_checkint(L, 3);
    int micros  = luaL_checkint(L, 4);
    int ret = TS_RESP_CTX_set_accuracy(ctx, seconds, millis, micros);
    return openssl_pushresult(L, ret);
  }
}

static LUA_FUNCTION(openssl_ts_resp_ctx_clock_precision_digits)
{
  TS_RESP_CTX *ctx = CHECK_OBJECT(1, TS_RESP_CTX, "openssl.ts_resp_ctx");
  if (lua_isnone(L, 2))
  {
    lua_pushinteger(L, ctx->clock_precision_digits);
    return 1;
  }
  else
  {
    int ret;
    int clock_precision_digits = luaL_checkint(L, 2);
    if (clock_precision_digits > TS_MAX_CLOCK_PRECISION_DIGITS)
      clock_precision_digits = TS_MAX_CLOCK_PRECISION_DIGITS;
    if (clock_precision_digits < 0)
      clock_precision_digits = 0;
    ret = TS_RESP_CTX_set_clock_precision_digits(ctx, clock_precision_digits);
    return openssl_pushresult(L, ret);
  }
}

static LUA_FUNCTION(openssl_ts_resp_ctx_set_status_info)
{
  TS_RESP_CTX *ctx = CHECK_OBJECT(1, TS_RESP_CTX, "openssl.ts_resp_ctx");
  int status = luaL_checkint(L, 2);
  const char* text = luaL_checkstring(L, 3);
  int ret = TS_RESP_CTX_set_status_info(ctx, status, text);
  return openssl_pushresult(L, ret);
}

static LUA_FUNCTION(openssl_ts_resp_ctx_set_status_info_cond)
{
  TS_RESP_CTX *ctx = CHECK_OBJECT(1, TS_RESP_CTX, "openssl.ts_resp_ctx");
  int status = luaL_checkint(L, 2);
  const char* text = luaL_checkstring(L, 3);
  int ret = TS_RESP_CTX_set_status_info_cond(ctx, status, text);
  return openssl_pushresult(L, ret);
}

static LUA_FUNCTION(openssl_ts_resp_ctx_add_failure_info)
{
  TS_RESP_CTX *ctx = CHECK_OBJECT(1, TS_RESP_CTX, "openssl.ts_resp_ctx");
  int failure = luaL_checkint(L, 2);
  int ret = TS_RESP_CTX_add_failure_info(ctx, failure);
  return openssl_pushresult(L, ret);
}

static LUA_FUNCTION(openssl_ts_resp_ctx_flags)
{
  TS_RESP_CTX *ctx = CHECK_OBJECT(1, TS_RESP_CTX, "openssl.ts_resp_ctx");
  if (lua_isnone(L, 2))
  {
    lua_pushinteger(L, ctx->flags);
  }
  else if (lua_isnumber(L, 2))
  {
    int flags = luaL_checkint(L, 2);
    ctx->flags = flags;
    lua_pushboolean(L, 1);
  }
  else if (lua_isstring(L, 2))
  {
    /* TS_RESP_CTX_add_flags(ctx, ) */
    luaL_error(L, "not support");
  }
  else
    luaL_error(L, "not support");
  return 1;
}

static LUA_FUNCTION(openssl_ts_resp_ctx_md)
{
  TS_RESP_CTX *ctx = CHECK_OBJECT(1, TS_RESP_CTX, "openssl.ts_resp_ctx");
  if (lua_isnone(L, 2))
  {
    if (ctx->mds)
    {
      int i;
      int n = sk_EVP_MD_num(ctx->mds);
      lua_newtable(L);
      for (i = 0; i < n; i++)
      {
        EVP_MD* md = sk_EVP_MD_value(ctx->mds, i);
        PUSH_OBJECT(md, "openssl.evp_digest");
        lua_rawseti(L, -2, i + 1);
      }
    }
    else
      lua_pushnil(L);
    return 1;
  }
  else if (lua_istable(L, 2))
  {
    int i;
    int n = lua_rawlen(L, 2);
    int ret = 1;
    for (i = 1; ret == 1 && i <= n; i++)
    {
      const EVP_MD* md;
      lua_rawgeti(L, 2, i);
      md = get_digest(L, -1);
      lua_pop(L, 1);
      if (md)
      {
        ret = TS_RESP_CTX_add_md(ctx, md);
      }
      else
      {
        lua_pushfstring(L, "#%d not valid evp_digest object or id", i);
        luaL_argcheck(L, md, 2, lua_tostring(L, -1));
        lua_pop(L, 1);
      }
    }
    return openssl_pushresult(L, ret);
  }
  else
  {
    const EVP_MD* md = get_digest(L, 2);
    int ret = TS_RESP_CTX_add_md(ctx, md);
    return openssl_pushresult(L, ret);
  }
}

static LUA_FUNCTION(openssl_ts_resp_ctx_tst_info)
{
  TS_RESP_CTX *ctx = CHECK_OBJECT(1, TS_RESP_CTX, "openssl.ts_resp_ctx");
  TS_TST_INFO *info = TS_RESP_CTX_get_tst_info(ctx);
  if (info)
  {
    openssl_push_ts_tst_info(L, info);
    TS_TST_INFO_ext_free(info);
  }
  else
    lua_pushnil(L);
  return 1;
}

static LUA_FUNCTION(openssl_ts_resp_ctx_request)
{
  TS_RESP_CTX *ctx = CHECK_OBJECT(1, TS_RESP_CTX, "openssl.ts_resp_ctx");
  TS_REQ *req = TS_RESP_CTX_get_request(ctx);
  if (req)
  {
    PUSH_OBJECT(req, "openssl.ts_req");
  }
  else
    lua_pushnil(L);
  return 1;
}

typedef struct
{
  lua_State* L;
  int callback;
  int ctx;
  int cb_arg;
} TS_CB_ARG;

static const char* time_cb_key  = "time_cb_key";
static const char* serial_cb_key = "serial_cb_key";

static ASN1_INTEGER* openssl_serial_cb(TS_RESP_CTX*ctx, void*data)
{
  TS_CB_ARG *arg = (TS_CB_ARG*)data;
  lua_State* L = arg->L;
  ASN1_INTEGER *ai = NULL;
  int err;
  (void)ctx;
  lua_rawgeti(L, LUA_REGISTRYINDEX, arg->callback);
  lua_rawgeti(L, LUA_REGISTRYINDEX, arg->ctx);
  lua_rawgeti(L, LUA_REGISTRYINDEX, arg->cb_arg);
  err = lua_pcall(L, 2, 1, 0);
  if (err == 0)
  {
    BIGNUM *bn = BN_get(L, -1);
    lua_pop(L, 1);
    if (bn)
    {
      ai = BN_to_ASN1_INTEGER(bn, NULL);
      BN_free(bn);
    }
    if (ai == NULL)
      luaL_error(L, "serial_cb not return openssl.bn");
  }
  else
    lua_error(L);
  return ai;
};

static LUA_FUNCTION(openssl_ts_resp_ctx_set_serial_cb)
{
  TS_RESP_CTX *ctx = CHECK_OBJECT(1, TS_RESP_CTX, "openssl.ts_resp_ctx");
  int cbref, argref;
  TS_CB_ARG* arg = NULL;
  luaL_checktype(L, 2, LUA_TFUNCTION);

  lua_pushvalue(L, 2);
  cbref = luaL_ref(L, LUA_REGISTRYINDEX);
  lua_pushvalue(L, 3);
  argref = luaL_ref(L, LUA_REGISTRYINDEX);

  arg = (TS_CB_ARG*)lua_newuserdata(L, sizeof(TS_CB_ARG));
  arg->callback = cbref;
  arg->cb_arg = argref;
  arg->L = L;
  lua_pushvalue(L, 1);
  arg->ctx = luaL_ref(L, LUA_REGISTRYINDEX);
  openssl_setvalue(L, ctx, "serial_cb");

  TS_RESP_CTX_set_serial_cb(ctx, openssl_serial_cb, arg);
  return 0;
};

static int openssl_time_cb(TS_RESP_CTX *ctx, void *data, long *sec, long *usec)
{
  TS_CB_ARG *arg = (TS_CB_ARG*)data;
  lua_State* L = arg->L;
  int err;
  (void) ctx;
  lua_rawgeti(L, LUA_REGISTRYINDEX, arg->callback);
  lua_rawgeti(L, LUA_REGISTRYINDEX, arg->ctx);
  lua_rawgeti(L, LUA_REGISTRYINDEX, arg->cb_arg);
  err = lua_pcall(L, 2, 2, 0);
  if (err == 0)
  {
    if (lua_isnil(L, -2))
    {
      lua_pop(L, 2);
      return 0;
    }
    else
    {
      *sec = (long)luaL_checkinteger(L, -2);
      *usec = (long)luaL_optinteger(L, -1, 0);
      lua_pop(L, 2);
      return 1;
    }
  }
  else
    lua_error(L);
  return 0;
}

static LUA_FUNCTION(openssl_ts_resp_ctx_set_time_cb)
{
  TS_RESP_CTX *ctx = CHECK_OBJECT(1, TS_RESP_CTX, "openssl.ts_resp_ctx");
  int cbref, argref;
  TS_CB_ARG* arg = NULL;
  luaL_checktype(L, 2, LUA_TFUNCTION);

  lua_pushvalue(L, 2);
  cbref = luaL_ref(L, LUA_REGISTRYINDEX);
  lua_pushvalue(L, 3);
  argref = luaL_ref(L, LUA_REGISTRYINDEX);

  arg = (TS_CB_ARG*)lua_newuserdata(L, sizeof(TS_CB_ARG));
  arg->callback = cbref;
  arg->cb_arg = argref;
  lua_pushvalue(L, 1);
  arg->ctx = luaL_ref(L, LUA_REGISTRYINDEX);
  arg->L = L;
  lua_rawsetp(L, LUA_REGISTRYINDEX, ctx);
  TS_RESP_CTX_set_time_cb(ctx, openssl_time_cb, arg);
  return 0;
}

static LUA_FUNCTION(openssl_ts_resp_ctx_gc)
{
  TS_RESP_CTX *ctx = CHECK_OBJECT(1, TS_RESP_CTX, "openssl.ts_resp_ctx");
  openssl_freevalue(L, ctx);
  TS_RESP_CTX_free(ctx);
  return 0;
}


static luaL_Reg ts_resp_ctx_funs[] =
{
  /* get and set */
  {"signer",              openssl_ts_resp_ctx_singer},
  {"certs",               openssl_ts_resp_ctx_certs},
  {"default_policy",      openssl_ts_resp_ctx_default_policy},
  {"policies",            openssl_ts_resp_ctx_policies},
  {"accuracy",            openssl_ts_resp_ctx_accuracy},
  {"clock_precision_digits",  openssl_ts_resp_ctx_clock_precision_digits},
  {"md",                  openssl_ts_resp_ctx_md},
  {"flags",               openssl_ts_resp_ctx_flags},

  /* set */
  {"set_status_info",         openssl_ts_resp_ctx_set_status_info},
  {"set_status_info_cond",    openssl_ts_resp_ctx_set_status_info_cond},
  {"set_serial_cb",      openssl_ts_resp_ctx_set_serial_cb},
  {"set_time_cb",        openssl_ts_resp_ctx_set_time_cb},
  {"add_failure_info",   openssl_ts_resp_ctx_add_failure_info},

  /* get */
  {"request",            openssl_ts_resp_ctx_request},
  {"tst_info",           openssl_ts_resp_ctx_tst_info},

  {"sign",               openssl_ts_create_response},
  {"create_response",    openssl_ts_create_response},

  {"__tostring",  auxiliar_tostring},
  {"__gc",        openssl_ts_resp_ctx_gc},

  { NULL, NULL }
};

/********************************************************************/

static LUA_FUNCTION(openssl_ts_verify_ctx_new)
{
  TS_VERIFY_CTX *ctx = NULL;
  if (lua_isnone(L, 1))
  {
    ctx = TS_VERIFY_CTX_new();
    ctx->flags |= TS_VFY_SIGNATURE;
  }
  else if (lua_isstring(L, 1))
  {
    BIO* bio = load_bio_object(L, 1);
    TS_REQ* req = d2i_TS_REQ_bio(bio, NULL);
    BIO_free(bio);
    if (req)
    {
      ctx = TS_REQ_to_TS_VERIFY_CTX(req, NULL);
      TS_REQ_free(req);
    }
    else
    {
      luaL_argerror(L, 1, "must be ts_req data or object or nil");
    }
  }
  else
  {
    TS_REQ* req = CHECK_OBJECT(1, TS_REQ, "openssl.ts_req");
    ctx = TS_REQ_to_TS_VERIFY_CTX(req, NULL);
  }
  if (ctx)
  {
    PUSH_OBJECT(ctx, "openssl.ts_verify_ctx");
  }
  else
    lua_pushnil(L);
  return 1;
}

static int openssl_ts_verify_ctx_store(lua_State*L)
{
  TS_VERIFY_CTX *ctx = CHECK_OBJECT(1, TS_VERIFY_CTX, "openssl.ts_verify_ctx");
  if (lua_isnone(L, 2))
  {
    /*
    if (ctx->store)
    {
      STACK_OF(X509) *cas =  X509_STORE_get1_certs(ctx->store, NULL);
      openssl_sk_x509_totable(L, cas);
    }
    else
    */
    lua_pushnil(L);
  }
  else
  {
    X509_STORE* store = CHECK_OBJECT(2, X509_STORE, "openssl.x509_store");
    if (ctx->store)
      openssl_xstore_free(ctx->store);

    CRYPTO_add(&store->references, 1, CRYPTO_LOCK_X509_STORE);
    ctx->store = store;
    ctx->flags |= TS_VFY_SIGNER | TS_VFY_SIGNATURE;
    lua_pushboolean(L, 1);
  }
  return 1;
}

static int openssl_ts_verify_ctx_certs(lua_State*L)
{
  TS_VERIFY_CTX *ctx = CHECK_OBJECT(1, TS_VERIFY_CTX, "openssl.ts_verify_ctx");
  if (lua_isnone(L, 2))
  {
    if (ctx->certs)
    {
      openssl_sk_x509_totable(L, ctx->certs);
    }
    else
      lua_pushnil(L);
  }
  else
  {
    if (ctx->certs)
      sk_X509_pop_free(ctx->certs, X509_free);

    ctx->certs = openssl_sk_x509_fromtable(L, 2);
    lua_pushboolean(L, 1);
  }
  return 1;
}

static int openssl_ts_verify_ctx_flags(lua_State*L)
{
  TS_VERIFY_CTX *ctx = CHECK_OBJECT(1, TS_VERIFY_CTX, "openssl.ts_verify_ctx");
  if (lua_isnone(L, 2))
  {
    lua_pushinteger(L, ctx->flags);
    return 1;
  }
  else
  {
    ctx->flags = luaL_checkinteger(L, 2);
  }
  return 0;
}

static int openssl_ts_verify_ctx_data(lua_State*L)
{
  TS_VERIFY_CTX *ctx = CHECK_OBJECT(1, TS_VERIFY_CTX, "openssl.ts_verify_ctx");
  if (lua_isnone(L, 2))
  {
    if (ctx->data)
    {
      BIO* bio = ctx->data;
      CRYPTO_add(&bio->references, 1, CRYPTO_LOCK_BIO);
      PUSH_OBJECT(bio, "openssl.bio");
    }
    else
      lua_pushnil(L);
    return 1;
  }
  else
  {
    BIO* bio = load_bio_object(L, 2);
    if (ctx->data)
      BIO_free(ctx->data);
    ctx->data = bio;
    ctx->flags |= TS_VFY_DATA;
    lua_pushboolean(L, 1);
    return 1;
  }
}

static int openssl_ts_verify_ctx_imprint(lua_State*L)
{
  TS_VERIFY_CTX *ctx = CHECK_OBJECT(1, TS_VERIFY_CTX, "openssl.ts_verify_ctx");
  if (lua_isnone(L, 2))
  {
    lua_pushlstring(L, (const char*)ctx->imprint, ctx->imprint_len);
    return 1;
  }
  else
  {
    size_t imprint_len;
    const char* imprint = luaL_checklstring(L, 2, &imprint_len);

    ctx->imprint = OPENSSL_malloc(imprint_len);
    memcpy(ctx->imprint, imprint, imprint_len);;
    ctx->imprint_len = imprint_len;
    ctx->flags |= TS_VFY_IMPRINT;
    lua_pushboolean(L, 1);
    return 1;
  }
}

static LUA_FUNCTION(openssl_ts_verify_ctx_gc)
{
  TS_VERIFY_CTX *ctx = CHECK_OBJECT(1, TS_VERIFY_CTX, "openssl.ts_verify_ctx");
  if (ctx->store)
    openssl_xstore_free(ctx->store);

  ctx->store = NULL;
  TS_VERIFY_CTX_free(ctx);
  return 0;
}

static LUA_FUNCTION(openssl_ts_verify_ctx_verify)
{
  TS_VERIFY_CTX *ctx = CHECK_OBJECT(1, TS_VERIFY_CTX, "openssl.ts_verify_ctx");
  int ret = 0;
  if (auxiliar_isclass(L, "openssl.ts_resp", 2))
  {
    TS_RESP *response = CHECK_OBJECT(2, TS_RESP, "openssl.ts_resp");
    ret = TS_RESP_verify_response(ctx, response);
  }
  else if (auxiliar_isclass(L, "openssl.pkcs7", 2))
  {
    PKCS7 *token = CHECK_OBJECT(2, PKCS7, "openssl.pkcs7");
    ret = TS_RESP_verify_token(ctx, token);
  }
  else if (lua_isstring(L, 2))
  {
    size_t size;
    const unsigned char* data = (const unsigned char*)lua_tolstring(L, 2, &size);
    TS_RESP *resp = d2i_TS_RESP(NULL, &data, size);
    if (resp)
    {
      ret = TS_RESP_verify_response(ctx, resp);
      TS_RESP_free(resp);
    }
    else
      luaL_argerror(L, 2, "data is not ts_resp object");
  }
  else
  {
    luaL_argerror(L, 2, "must be ts_resp or pkcs7 object");
  }
  return openssl_pushresult(L, ret);
}

static luaL_Reg ts_verify_ctx_funs[] =
{
  {"store",             openssl_ts_verify_ctx_store},
  {"certs",             openssl_ts_verify_ctx_certs},
  {"flags",             openssl_ts_verify_ctx_flags},
  {"verify",            openssl_ts_verify_ctx_verify},
  {"data",              openssl_ts_verify_ctx_data},
  {"imprint",           openssl_ts_verify_ctx_imprint},
//  {"info",              openssl_ts_verify_ctx_info},

  {"__tostring",        auxiliar_tostring},
  {"__gc",              openssl_ts_verify_ctx_gc},

  { NULL, NULL }
};

static luaL_Reg R[] =
{
  {"req_new",         openssl_ts_req_new},
  {"req_read",        openssl_ts_req_read},
  {"resp_read",       openssl_ts_resp_read},

  {"resp_ctx_new",    openssl_ts_resp_ctx_new },
  {"verify_ctx_new",  openssl_ts_verify_ctx_new },

  {NULL,    NULL}
};
#endif
int luaopen_ts(lua_State *L)
{
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
  auxiliar_newclass(L, "openssl.ts_req",        ts_req_funs);
  auxiliar_newclass(L, "openssl.ts_resp",       ts_resp_funs);
  auxiliar_newclass(L, "openssl.ts_resp_ctx",   ts_resp_ctx_funs);
  auxiliar_newclass(L, "openssl.ts_verify_ctx", ts_verify_ctx_funs);

  lua_newtable(L);
  luaL_setfuncs(L, R, 0);

  lua_pushliteral(L, "version");    /** version */
  lua_pushliteral(L, MYVERSION);
  lua_settable(L, -3);
#else
  lua_pushnil(L);
#endif
  return 1;
}
