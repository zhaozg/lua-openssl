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
      a = X509_ALGOR_dup(a);
      PUSH_OBJECT(a, "openssl.x509_algor");
      ASN1_OCTET_STRING_free(s);
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
  lua_pushinteger(L, TS_REQ_get_version(req));
  lua_setfield(L, -2, "version");

  AUXILIAR_SET(L, -1, "cert_req", TS_REQ_get_cert_req(req), boolean);

  if (TS_REQ_get_policy_id(req))
  {
    openssl_push_asn1object(L, TS_REQ_get_policy_id(req));
    lua_setfield(L, -2, "policy_id");
  }
  if (TS_REQ_get_nonce(req))
  {
    PUSH_ASN1_INTEGER(L, TS_REQ_get_nonce(req));
    lua_setfield(L, -2, "nonce");
  }

  lua_newtable(L);
  {
    TS_MSG_IMPRINT *msg_inprint = TS_REQ_get_msg_imprint(req);
    ASN1_OCTET_STRING *os = TS_MSG_IMPRINT_get_msg(msg_inprint);
    X509_ALGOR *alg = TS_MSG_IMPRINT_get_algo(msg_inprint);

    AUXILIAR_SETLSTR(L, -1, "content", (const char*)os->data, os->length);
    alg = X509_ALGOR_dup(alg);
    PUSH_OBJECT(alg, "openssl.x509_algor");
    lua_setfield(L, -2, "hash_algo");
  }
  lua_setfield(L, -2, "msg_imprint");

  if (TS_REQ_get_exts(req))
  {
    lua_pushstring(L, "extensions");
    openssl_sk_x509_extension_totable(L, TS_REQ_get_exts(req));
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
  if (accuracy)
  {
    lua_newtable(L);

    PUSH_ASN1_INTEGER(L, TS_ACCURACY_get_micros(accuracy));
    lua_setfield(L, -2, "micros");
    PUSH_ASN1_INTEGER(L, TS_ACCURACY_get_millis(accuracy));
    lua_setfield(L, -2, "millis");
    PUSH_ASN1_INTEGER(L, TS_ACCURACY_get_seconds(accuracy));
    lua_setfield(L, -2, "seconds");
  }
  else
    lua_pushnil(L);

  return 1;
}

static int openssl_push_ts_msg_imprint(lua_State*L, TS_MSG_IMPRINT* imprint)
{
  X509_ALGOR* alg = TS_MSG_IMPRINT_get_algo(imprint);
  ASN1_STRING* str =  TS_MSG_IMPRINT_get_msg(imprint);
  lua_newtable(L);
  if (alg)
  {
    alg = X509_ALGOR_dup(alg);
    PUSH_OBJECT(alg, "openssl.x509_algor");
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

  lua_pushinteger(L, TS_TST_INFO_get_version(info));
  lua_setfield(L, -2, "version");

  openssl_push_asn1object(L, TS_TST_INFO_get_policy_id(info));
  lua_setfield(L, -2, "policy_id");

  openssl_push_ts_msg_imprint(L, TS_TST_INFO_get_msg_imprint(info));
  lua_setfield(L, -2, "msg_imprint");

  PUSH_ASN1_INTEGER(L, TS_TST_INFO_get_serial(info));
  lua_setfield(L, -2, "serial");

  openssl_push_asn1(L, TS_TST_INFO_get_time(info), V_ASN1_GENERALIZEDTIME);
  lua_setfield(L, -2, "time");

  openssl_push_ts_accuracy(L, TS_TST_INFO_get_accuracy(info));
  lua_setfield(L, -2, "accuracy");

  AUXILIAR_SET(L, -1, "ordering", TS_TST_INFO_get_ordering(info), boolean);

  PUSH_ASN1_INTEGER(L, TS_TST_INFO_get_nonce(info));
  lua_setfield(L, -2, "nonce");

  openssl_push_general_name(L, TS_TST_INFO_get_tsa(info));
  lua_setfield(L, -2, "tsa");

  if (TS_TST_INFO_get_exts(info))
  {
    lua_pushstring(L, "extensions");
    openssl_sk_x509_extension_totable(L, TS_TST_INFO_get_exts(info));
    lua_rawset(L, -3);
  }

  return 1;
}

static LUA_FUNCTION(openssl_ts_resp_tst_info)
{
  TS_RESP *resp = CHECK_OBJECT(1, TS_RESP, "openssl.ts_resp");
  TS_TST_INFO *info = TS_RESP_get_tst_info(resp);

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
    TS_STATUS_INFO *si = TS_RESP_get_status_info(res);
    lua_newtable(L);
    PUSH_ASN1_INTEGER(L, TS_STATUS_INFO_get0_status(si));
    lua_setfield(L, -2, "status");

    if (TS_STATUS_INFO_get0_failure_info(si))
    {
      openssl_push_asn1(L, TS_STATUS_INFO_get0_failure_info(si), V_ASN1_BIT_STRING);
      lua_setfield(L, -2, "failure_info");
    }

    if (TS_STATUS_INFO_get0_text(si))
    {
      const STACK_OF(ASN1_UTF8STRING) * sk = TS_STATUS_INFO_get0_text(si);
      int i = 0, n = 0;
      lua_newtable(L);
      n = sk_ASN1_UTF8STRING_num(sk);
      for (i = 0; i < n; i++)
      {
        ASN1_UTF8STRING *x = sk_ASN1_UTF8STRING_value(sk, i);
        lua_pushlstring(L, (const char*)x->data, x->length);
        lua_rawseti(L, -2, i + 1);
      }
      lua_setfield(L, -2, "text");
    }

    lua_setfield(L, -2, "status_info");
  }


  if (TS_RESP_get_token(res))
  {
    PKCS7* token = PKCS7_dup(TS_RESP_get_token(res));
    AUXILIAR_SETOBJECT(L, token, "openssl.pkcs7", -1, "token");
  }

  if (TS_RESP_get_tst_info(res))
  {
    openssl_push_ts_tst_info(L, TS_RESP_get_tst_info(res));
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

static LUA_FUNCTION(openssl_ts_resp_ctx_certs)
{
  TS_RESP_CTX *ctx = CHECK_OBJECT(1, TS_RESP_CTX, "openssl.ts_resp_ctx");
  STACK_OF(X509) *certs = openssl_sk_x509_fromtable(L, 2);
  TS_RESP_CTX_set_certs(ctx, certs);
  return 0;
}

static LUA_FUNCTION(openssl_ts_resp_ctx_default_policy)
{
  TS_RESP_CTX *ctx = CHECK_OBJECT(1, TS_RESP_CTX, "openssl.ts_resp_ctx");
  int nid = openssl_get_nid(L, 2);
  int ret = TS_RESP_CTX_set_def_policy(ctx, OBJ_nid2obj(nid));
  return openssl_pushresult(L, ret);
}

static LUA_FUNCTION(openssl_ts_resp_ctx_policies)
{
  TS_RESP_CTX *ctx = CHECK_OBJECT(1, TS_RESP_CTX, "openssl.ts_resp_ctx");
  int ret = 1;
  int nid;
  int i;
  int n = lua_gettop(L);
  luaL_argcheck(L, n > 1, 2, "need one or more asn1_object");
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

static LUA_FUNCTION(openssl_ts_resp_ctx_accuracy)
{
  TS_RESP_CTX *ctx = CHECK_OBJECT(1, TS_RESP_CTX, "openssl.ts_resp_ctx");
  int seconds = luaL_checkint(L, 2);
  int millis = luaL_checkint(L, 3);
  int micros = luaL_checkint(L, 4);
  int ret = TS_RESP_CTX_set_accuracy(ctx, seconds, millis, micros);
  return openssl_pushresult(L, ret);
}

static LUA_FUNCTION(openssl_ts_resp_ctx_clock_precision_digits)
{
  TS_RESP_CTX *ctx = CHECK_OBJECT(1, TS_RESP_CTX, "openssl.ts_resp_ctx");
  int ret;
  int clock_precision_digits = luaL_checkint(L, 2);
  if (clock_precision_digits > TS_MAX_CLOCK_PRECISION_DIGITS)
    clock_precision_digits = TS_MAX_CLOCK_PRECISION_DIGITS;
  if (clock_precision_digits < 0)
    clock_precision_digits = 0;
  ret = TS_RESP_CTX_set_clock_precision_digits(ctx, clock_precision_digits);
  return openssl_pushresult(L, ret);
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
  int flags = luaL_checkint(L, 2);
  TS_RESP_CTX_add_flags(ctx, flags);
  return 0;
}

static LUA_FUNCTION(openssl_ts_resp_ctx_md)
{
  TS_RESP_CTX *ctx = CHECK_OBJECT(1, TS_RESP_CTX, "openssl.ts_resp_ctx");
  if (lua_istable(L, 2))
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
  X509_STORE* store = CHECK_OBJECT(2, X509_STORE, "openssl.x509_store");
  X509_STORE_up_ref(store);
  TS_VERIFY_CTX_set_store(ctx, store);
  return 0;
}

static int openssl_ts_verify_ctx_flags(lua_State*L)
{
  TS_VERIFY_CTX *ctx = CHECK_OBJECT(1, TS_VERIFY_CTX, "openssl.ts_verify_ctx");
  int flags = luaL_checkint(L, 2);
  int add = lua_isnoneornil(L, 3) ? 0 : lua_toboolean(L, 3);
  if (add)
    flags = TS_VERIFY_CTX_add_flags(ctx, flags);
  else
    flags = TS_VERIFY_CTX_set_flags(ctx, flags);
  lua_pushinteger(L, flags);
  return 1;
}

static int openssl_ts_verify_ctx_data(lua_State*L)
{
  TS_VERIFY_CTX *ctx = CHECK_OBJECT(1, TS_VERIFY_CTX, "openssl.ts_verify_ctx");
  BIO* bio = load_bio_object(L, 2);
  BIO_up_ref(bio);
  TS_VERIFY_CTX_set_data(ctx, bio);
  return 0;
}

static int openssl_ts_verify_ctx_imprint(lua_State*L)
{
  TS_VERIFY_CTX *ctx = CHECK_OBJECT(1, TS_VERIFY_CTX, "openssl.ts_verify_ctx");
  size_t imprint_len;
  const char* imprint = luaL_checklstring(L, 2, &imprint_len);
  const char* to = OPENSSL_malloc(imprint_len);
  memcpy(to, imprint, imprint_len);
  TS_VERIFY_CTX_set_imprint(ctx, to, imprint_len);
  return 0;
}

static LUA_FUNCTION(openssl_ts_verify_ctx_gc)
{
  TS_VERIFY_CTX *ctx = CHECK_OBJECT(1, TS_VERIFY_CTX, "openssl.ts_verify_ctx");
  /* hack openssl bugs */
#if OPENSSL_VERSION_NUMBER < 0x10002000L
  if (ctx->store->references > 1)
    CRYPTO_add(&ctx->store->references, -1, CRYPTO_LOCK_X509_STORE);
  ctx->store = NULL;
#endif
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
