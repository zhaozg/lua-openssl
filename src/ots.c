/*=========================================================================*\
* ots.c
* timestamp module for lua-openssl binding
*
* Author:  george zhao <zhaozg(at)gmail.com>
\*=========================================================================*/
#include "openssl.h"
#include "private.h"
#include <stdint.h>

#include <openssl/ts.h>

#define MYNAME    "ts"
#define MYVERSION MYNAME " library for " LUA_VERSION " / Nov 2014 / "\
  "based on OpenSSL " SHLIB_VERSION_NUMBER

static int openssl_ts_req_dup(lua_State*L) {
  TS_REQ* req = CHECK_OBJECT(1, TS_REQ, "openssl.ts_req");
  req = TS_REQ_dup(req);
  PUSH_OBJECT(req, "openssl.ts_req");
  return 1;
}

static int openssl_ts_req_cert_req(lua_State *L) {
  TS_REQ* req = CHECK_OBJECT(1, TS_REQ, "openssl.ts_req");
  if(lua_isnone(L, 2)) {
    lua_pushboolean(L, TS_REQ_get_cert_req(req));
    return 1;
  }else {
    int cert_req = auxiliar_checkboolean(L, 2);
    int ret = TS_REQ_set_cert_req(req, cert_req);
    return openssl_pushresult(L, ret);
  }
}

static int openssl_ts_req_nonce(lua_State*L) {
  TS_REQ* req = CHECK_OBJECT(1, TS_REQ, "openssl.ts_req");
  if(lua_isnone(L, 2)) {
    const ASN1_INTEGER* ai = TS_REQ_get_nonce(req);
    BIGNUM *bn;
    PUSH_ASN1_INTEGER(L, ai);
    bn = ASN1_INTEGER_to_BN(ai,NULL);
    PUSH_OBJECT(bn,"openssl.bn");
    return 2;
  }else {
    BIGNUM *bn = BN_get(L, 2);
    ASN1_INTEGER *ai = BN_to_ASN1_INTEGER(bn, NULL);
    int ret = TS_REQ_set_nonce(req, ai);
    ASN1_INTEGER_free(ai);
    BN_free(bn);
    return openssl_pushresult(L, ret);
  }
}

static int openssl_ts_req_policy_id(lua_State*L) {
  TS_REQ* req = CHECK_OBJECT(1, TS_REQ, "openssl.ts_req");
  if(lua_isnone(L, 2)) {
    ASN1_OBJECT* obj = TS_REQ_get_policy_id(req);
    openssl_push_asn1object(L, obj);
    ASN1_OBJECT_free(obj);
    return 1;
  }else {
    int nid = openssl_get_nid(L, 2);
    ASN1_OBJECT* obj;
    int ret;
    luaL_argcheck(L, nid!=NID_undef, 2, "must be asn1_object object identified");
    obj = OBJ_nid2obj(nid);
    ret = TS_REQ_set_policy_id(req, obj);
    return openssl_pushresult(L, ret);
  }
}

static int openssl_ts_req_version(lua_State*L) {
  TS_REQ* req = CHECK_OBJECT(1, TS_REQ, "openssl.ts_req");
  if(lua_isnone(L, 2)) {
    lua_pushinteger(L, TS_REQ_get_version(req));
    return 1;
  }else{
    long v = luaL_checkinteger(L, 2);
    int ret = TS_REQ_set_version(req, v);
    return openssl_pushresult(L, ret);
  }
}

static int openssl_ts_req_msg_imprint(lua_State*L) {
  TS_REQ* req = CHECK_OBJECT(1, TS_REQ, "openssl.ts_req");
  if(lua_isnone(L, 2)) {
    TS_MSG_IMPRINT * msg = TS_REQ_get_msg_imprint(req);
    if(msg) {
      ASN1_OCTET_STRING *s = TS_MSG_IMPRINT_get_msg(msg);
      X509_ALGOR *a = TS_MSG_IMPRINT_get_algo(msg);
      PUSH_ASN1_OCTET_STRING(L, s);
      openssl_push_x509_algor(L, a);
      ASN1_OCTET_STRING_free(s);
      X509_ALGOR_free(a);
      return 2;
    }
    return 1;
  }else{
    size_t size;
    const char* data = luaL_checklstring(L, 2, &size);
    const EVP_MD* md = lua_isnoneornil(L, 3) 
      ? EVP_get_digestbyname("sha1")
      : get_digest(L, 3);
    TS_MSG_IMPRINT *msg = TS_MSG_IMPRINT_new();
    int ret =TS_MSG_IMPRINT_set_msg(msg, (unsigned char*)data, size);
    if(ret==1){
      X509_ALGOR* alg = X509_ALGOR_new();
      X509_ALGOR_set_md(alg, md);
      if(ret==1)
        ret = TS_MSG_IMPRINT_set_algo(msg,alg);
      X509_ALGOR_free(alg);
    }
    if(ret!=1)
      TS_MSG_IMPRINT_free(msg);
    return openssl_pushresult(L, ret);
  }
};

static LUA_FUNCTION(openssl_ts_req_new)
{
  TS_REQ *ts_req = TS_REQ_new();
  long version = luaL_optinteger(L, 1, 1);

  int ret = TS_REQ_set_version(ts_req, 1);
  if (ret==1) {
    PUSH_OBJECT(ts_req, "openssl.ts_req");
    return 1;
  }
  TS_REQ_free(ts_req);
  return 0;
}

static LUA_FUNCTION(openssl_ts_req_gc)
{
  TS_REQ *req = CHECK_OBJECT(1, TS_REQ, "openssl.ts_req");
  lua_pushnil(L);
  lua_setmetatable(L, 1);
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
  int fmt = luaL_checkoption(L, 2, "auto", format);
  TS_REQ *ts_req = d2i_TS_REQ_bio(in, NULL);
  BIO_free(in);
  if (ts_req) {
    PUSH_OBJECT(ts_req, "openssl.ts_req");
    return 1;
  }
  return 0;
}

static LUA_FUNCTION(openssl_ts_req_export)
{
  TS_REQ *ts_req = CHECK_OBJECT(1, TS_REQ, "opensl.ts_req");
  unsigned char *data = NULL;
  int len = i2d_TS_REQ(ts_req, &data);
  if (len>0) {
    lua_pushlstring(L, data, len);
    OPENSSL_free(data);
    return 1;
  }
  return 0;
}


static LUA_FUNCTION(openssl_ts_req_info)
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



static LUA_FUNCTION(openssl_ts_req_d2i)
{
  size_t l;
  const char* buf = luaL_checklstring(L, 1, &l);

  TS_REQ *req = d2i_TS_REQ(NULL, (const byte**)&buf, l);
  PUSH_OBJECT(req, "openssl.ts_req");
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

/**************************************************************/
static LUA_FUNCTION(openssl_ts_resp_gc)
{
  TS_RESP *res = CHECK_OBJECT(1, TS_RESP, "openssl.ts_resp");
  lua_pushnil(L);
  lua_setmetatable(L, 1);
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

static int openssl_push_ts_msg_imprint(lua_State*L, TS_MSG_IMPRINT* imprint) {
  X509_ALGOR* alg = TS_MSG_IMPRINT_get_algo(imprint);
  ASN1_STRING* str =  TS_MSG_IMPRINT_get_msg(imprint);
  lua_newtable(L);
  openssl_push_x509_algor(L, alg);
  lua_setfield(L, -2, "algo");
  PUSH_ASN1_OCTET_STRING(L, str);
  lua_setfield(L, -2, "msg");
  X509_ALGOR_free(alg);
  ASN1_STRING_free(str);
  return 1;
};

static int openssl_push_ts_tst_info(lua_State*L, TS_TST_INFO* info, int utf8) {
  lua_newtable(L);
  if(info->version){
    PUSH_ASN1_INTEGER(L, info->version);
    lua_setfield(L, -2, "version");
  }
  if(info->policy_id) {
    openssl_push_asn1object(L, info->policy_id);
    lua_setfield(L, -2, "policy_id");
  }
  if(info->msg_imprint) {
    openssl_push_ts_msg_imprint(L, info->msg_imprint);
    lua_setfield(L, -2, "msg_imprint");
  }
  if(info->serial) {
    PUSH_ASN1_INTEGER(L, info->serial);
    lua_setfield(L, -2, "serial");
  }
  if(info->time) {
    PUSH_ASN1_GENERALIZEDTIME(L, info->time);
    lua_setfield(L, -2, "time");
  }
  if(info->accuracy) {
    openssl_push_ts_accuracy(L, info->accuracy);
    lua_setfield(L, -2, "accuracy");
  }

  AUXILIAR_SET(L, -1, "ordering", info->ordering, boolean);

  if(info->nonce) {
    PUSH_ASN1_INTEGER(L, info->nonce);
    lua_setfield(L, -2, "nonce");
  }
  if(info->tsa) {
    opensl_push_general_name(L, info->tsa, utf8);
    lua_setfield(L, -2, "tsa");
  }
  if(info->extensions) {
    STACK_OF(X509_EXTENSION)* exts = sk_X509_EXTENSION_dup(info->extensions);
    PUSH_OBJECT(exts,"openssl.stack_of_x509_extensions");
  }
  return 1;
}

static LUA_FUNCTION(openssl_ts_resp_tst_info)
{
  TS_RESP *resp = CHECK_OBJECT(1, TS_RESP, "openssl.ts_resp");
  int utf8 = lua_isnoneornil(L, 2) ? 1 : lua_toboolean(L, 2);
  TS_TST_INFO *info = resp->tst_info;
  if(info)
    openssl_push_ts_tst_info(L,info,utf8);
  else
    lua_pushnil(L);
  return 1;
}

static LUA_FUNCTION(openssl_ts_resp_info)
{
  TS_RESP *res = CHECK_OBJECT(1, TS_RESP, "openssl.ts_resp");
  int utf8 = lua_isnoneornil(L, 2) ? 1 : lua_toboolean(L, 2);

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
    openssl_push_ts_tst_info(L, res->tst_info, utf8);
    lua_setfield(L, -2, "tst_info");
  }

  BIO_free(bio);

  return 1;
}

static LUA_FUNCTION(openssl_ts_resp_read)
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

/********************************************************/

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
    return openssl_pushresult(L,0);
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


static LUA_FUNCTION(openssl_ts_resp_ctx_gc)
{
  TS_RESP_CTX *ctx = CHECK_OBJECT(1, TS_RESP_CTX, "openssl.ts_resp_ctx");
  TS_RESP_CTX_free(ctx);
  return 0;
}

static luaL_Reg ts_resp_ctx_funs[] =
{
  {"sign",        openssl_ts_sign},
  {"__tostring",  auxiliar_tostring},
  {"__gc",        openssl_ts_resp_ctx_gc},

  { NULL, NULL }
};

/********************************************************************/

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

static luaL_Reg ts_verify_ctx_funs[] =
{
  {"verify_response",   openssl_ts_verify_ctx_response},
  {"verify_token",      openssl_ts_verify_ctx_token},

  {"__tostring",        auxiliar_tostring},
  {"__gc",              openssl_ts_verify_ctx_gc},

  { NULL, NULL }
};

static luaL_reg R[] =
{
  {"req_new",         openssl_ts_req_new},
  {"req_read",        openssl_ts_req_read},
  {"resp_read",       openssl_ts_resp_read},

  {"resp_ctx_new",    openssl_ts_resp_ctx_new },
  {"verify_ctx_new",  openssl_ts_verify_ctx_new },

  {NULL,    NULL}
};

LUALIB_API int luaopen_ts(lua_State *L)
{
  auxiliar_newclass(L, "openssl.ts_req",        ts_req_funs);
  auxiliar_newclass(L, "openssl.ts_resp",       ts_resp_funs);
  auxiliar_newclass(L, "openssl.ts_resp_ctx",   ts_resp_ctx_funs);
  auxiliar_newclass(L, "openssl.ts_verify_ctx", ts_verify_ctx_funs);

  luaL_register(L, MYNAME, R);

  lua_pushliteral(L, "version");    /** version */
  lua_pushliteral(L, MYVERSION);
  lua_settable(L, -3);

  return 1;
}
