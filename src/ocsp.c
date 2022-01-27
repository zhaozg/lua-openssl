/*=========================================================================*\
* ocsp.c
* X509 certificate sign request routines for lua-openssl binding
*
* Author:  george zhao <zhaozg(at)gmail.com>
\*=========================================================================*/
#include "openssl.h"
#include "private.h"
#include "openssl/ocsp.h"

static int openssl_ocsp_request_new(lua_State *L)
{
  OCSP_REQUEST *req = NULL;

  X509 *issuer = CHECK_OBJECT(1, X509, "openssl.x509");
  X509_NAME *iname = X509_get_subject_name(issuer);
  ASN1_BIT_STRING *ikey = X509_get0_pubkey_bitstr(issuer);

  OCSP_CERTID *id = NULL;
  OCSP_ONEREQ *one = NULL;
  char buf[1024];
  int nonce = lua_gettop(L) > 2 ? auxiliar_checkboolean(L, 3) : 0;
  req = OCSP_REQUEST_new();

  if (lua_istable(L, 2))
  {
    int len = lua_rawlen(L, 2);
    int i;
    for (i = 1; i <= len; i++)
    {
      lua_rawgeti(L, 2, i);
      if (auxiliar_getclassudata(L, "openssl.x509", -1))
      {
        X509 *cert = CHECK_OBJECT(-1, X509, "openssl.x509");
        id = OCSP_cert_to_id(NULL, cert, issuer);
        one = OCSP_request_add0_id(req, id);
      }
      else
      {
        size_t size;
        char *serial = (char *)luaL_checklstring(L, -1, &size);
        ASN1_INTEGER *sno = ASN1_INTEGER_new();
        BIO* bio = BIO_new(BIO_s_mem());
        BIO_write(bio, serial, size);
        if (a2i_ASN1_INTEGER(bio, sno, buf, 1024) == 1)
        {
          id = OCSP_cert_id_new(EVP_sha1(), iname, ikey, sno);
          one = OCSP_request_add0_id(req, id);
        }
        ASN1_INTEGER_free(sno);
        BIO_free(bio);
      }
      if (!one)
      {
        OCSP_CERTID_free(id);
        OCSP_REQUEST_free(req);
        req = NULL;
        lua_pop(L, 1);
        break;
      }
      lua_pop(L, 1);
    }
  }
  else if (auxiliar_getclassudata(L, "openssl.x509", 2))
  {
    X509 *cert = CHECK_OBJECT(2, X509, "openssl.x509");
    id = OCSP_cert_to_id(NULL, cert, issuer);
    one = OCSP_request_add0_id(req, id);
    if (!one)
    {
      OCSP_CERTID_free(id);
      OCSP_REQUEST_free(req);
      req = NULL;
    }
  }
  else
  {
    ASN1_INTEGER *sno = ASN1_INTEGER_new();
    BIO* bio = load_bio_object(L, 2);

    if (a2i_ASN1_INTEGER(bio, sno, buf, 1024) == 1)
    {
      id = OCSP_cert_id_new(EVP_sha1(), iname, ikey, sno);
      one = OCSP_request_add0_id(req, id);
      if (!one)
      {
        OCSP_CERTID_free(id);
        OCSP_REQUEST_free(req);
        req = NULL;
      }
    }
    ASN1_INTEGER_free(sno);
    BIO_free(bio);
  }
  if (nonce)
    OCSP_request_add1_nonce(req, NULL,  -1);

  if (req)
  {
    PUSH_OBJECT(req, "openssl.ocsp_request");
  }
  else
    lua_pushnil(L);

  return 1;
}

static int openssl_ocsp_request_add_ext(lua_State *L)
{
  OCSP_REQUEST *req = CHECK_OBJECT(1, OCSP_REQUEST, "openssl.ocsp_request");
  X509_EXTENSION *x = CHECK_OBJECT(2, X509_EXTENSION, "openssl.x509_extension");
  int loc = luaL_optint(L, 3, OCSP_REQUEST_get_ext_count(req));
  int ret;

  ret = OCSP_REQUEST_add_ext(req, x, loc);
  return openssl_pushresult(L, ret);
}

static int openssl_ocsp_request_read(lua_State *L)
{
  BIO *bio = load_bio_object(L, 1);
  int pem = lua_gettop(L) > 1 ? auxiliar_checkboolean(L, 2) : 0;

  OCSP_REQUEST *req = pem ? PEM_read_bio_OCSP_REQUEST(bio, NULL, NULL)
                      : d2i_OCSP_REQUEST_bio(bio, NULL);
  BIO_free(bio);

  if (req)
  {
    PUSH_OBJECT(req, "openssl.ocsp_request");
  }
  else
    lua_pushnil(L);

  return 1;
}

static int openssl_ocsp_request_export(lua_State*L)
{
  OCSP_REQUEST *req = CHECK_OBJECT(1, OCSP_REQUEST, "openssl.ocsp_request");
  int pem = lua_gettop(L) > 1 ? auxiliar_checkboolean(L, 2) : 0;
  int ret = 0;
  BIO* bio;

  bio = BIO_new(BIO_s_mem());
  if (pem)
  {
    ret = PEM_write_bio_OCSP_REQUEST(bio, req);
  }
  else
  {
    ret = i2d_OCSP_REQUEST_bio(bio, req);
  }
  if (ret == 1)
  {
    BUF_MEM *buf;
    BIO_get_mem_ptr(bio, &buf);
    lua_pushlstring(L, buf->data, buf->length);
  }
  BIO_free(bio);
  return ret == 1 ? ret : openssl_pushresult(L, ret);
}

static int openssl_ocsp_request_free(lua_State*L)
{
  OCSP_REQUEST *req = CHECK_OBJECT(1, OCSP_REQUEST, "openssl.ocsp_request");
  OCSP_REQUEST_free(req);
  return 0;
}

static int openssl_ocsp_request_sign(lua_State*L)
{
  OCSP_REQUEST *req = CHECK_OBJECT(1, OCSP_REQUEST, "openssl.ocsp_request");
  X509 *signer = CHECK_OBJECT(2, X509, "openssl.x509");
  EVP_PKEY *pkey = CHECK_OBJECT(3, EVP_PKEY, "openssl.evp_pkey");
  STACK_OF(X509) *others = NULL;
  const EVP_MD *md = NULL;
  int ret;
  int sflags = 0;

  if (lua_isnoneornil(L, 4))
  {
    sflags = OCSP_NOCERTS;
  }
  else
  {
    others = openssl_sk_x509_fromtable(L, 4);
  }
  sflags = luaL_optint(L, 5, sflags);
  md = lua_isnoneornil(L, 6) ? NULL : get_digest(L, 6, "sha256");

  ret = OCSP_request_sign(req, signer, pkey, md, others, sflags);
  lua_pushboolean(L, ret);
  if (others!=NULL)
    sk_X509_pop_free(others, X509_free);
  return 1;
}

static int openssl_push_ocsp_certid(lua_State*L, OCSP_CERTID* cid)
{
  ASN1_OCTET_STRING *iNameHash = NULL;
  ASN1_OBJECT *md = NULL;
  ASN1_OCTET_STRING *ikeyHash = NULL;
  ASN1_INTEGER *serial = NULL;

  int ret = OCSP_id_get0_info(&iNameHash, &md, &ikeyHash, &serial, cid);
  if (ret == 1)
  {
    lua_newtable(L);

    if(iNameHash)
    {
      PUSH_ASN1_OCTET_STRING(L, iNameHash);
      lua_setfield(L, -2, "issuerNameHash");
    }

    if(ikeyHash)
    {
      PUSH_ASN1_OCTET_STRING(L, ikeyHash);
      lua_setfield(L, -2, "issuerKeyHash");
    }

    if (serial)
    {
      BIGNUM *bn = ASN1_INTEGER_to_BN(serial, NULL);
      PUSH_OBJECT(bn, "openssl.bn");
      lua_setfield(L, -2, "serialNumber");
    }

    if(md)
    {
      md = OBJ_dup(md);
      PUSH_OBJECT(md, "openssl.asn1_object");
      lua_setfield(L, -2, "hashAlgorithm");
    }
  }
  else
    lua_pushnil(L);
  return 1;
}

static int openssl_ocsp_request_parse(lua_State*L)
{
  OCSP_REQUEST *req = CHECK_OBJECT(1, OCSP_REQUEST, "openssl.ocsp_request");
#if OPENSSL_VERSION_NUMBER < 0x10100000L
  OCSP_REQINFO *inf = req->tbsRequest;
  OCSP_SIGNATURE *sig = req->optionalSignature;
#endif
  int i, num;
  lua_newtable(L);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
  AUXILIAR_SET(L, -1, "version", ASN1_INTEGER_get(inf->version), integer);
  if (inf->requestorName)
  {
    openssl_push_general_name(L, inf->requestorName);
    lua_setfield(L, -2, "requestorName");
  }
#endif

  num = OCSP_request_onereq_count(req);
  lua_newtable(L);
  for (i = 0; i < num; i++)
  {
    OCSP_ONEREQ *one = OCSP_request_onereq_get0(req, i);
    OCSP_CERTID *cid = OCSP_onereq_get0_id(one);
    openssl_push_ocsp_certid(L, cid);
    lua_rawseti(L, -2, i + 1);
  }
  lua_setfield(L, -2, "requestList");

  num = OCSP_REQUEST_get_ext_count(req);
  lua_newtable(L);
  for (i = 0; i < num; i++)
  {
    X509_EXTENSION* e = OCSP_REQUEST_get_ext(req, i);
    e = X509_EXTENSION_dup(e);
    PUSH_OBJECT(e, "openssl.x509_extension");
    lua_rawseti(L, -2, i + 1);
  }
  lua_setfield(L, -2, "extensions");

#if OPENSSL_VERSION_NUMBER < 0x10100000L
  if (sig)
  {
    BIO* bio = BIO_new(BIO_s_mem());
    (void)BIO_reset(bio);
    X509_signature_print(bio, sig->signatureAlgorithm, sig->signature);
    for (i = 0; i < sk_X509_num(sig->certs); i++)
    {
      X509_print(bio, sk_X509_value(sig->certs, i));
      PEM_write_bio_X509(bio, sk_X509_value(sig->certs, i));
    }
    BIO_free(bio);
  }
#endif
 
  return 1;
}

static int openssl_ocsp_response_read(lua_State *L)
{
  BIO *bio = load_bio_object(L, 1);
  int pem = lua_gettop(L) > 1 ? auxiliar_checkboolean(L, 2) : 0;

  OCSP_RESPONSE *res = pem ? PEM_read_bio_OCSP_RESPONSE(bio, NULL, NULL)
                      : d2i_OCSP_RESPONSE_bio(bio, NULL);
  if (res)
    PUSH_OBJECT(res, "openssl.ocsp_response");
  else
    lua_pushnil(L);
  BIO_free(bio);

  return 1;
}

static int openssl_ocsp_response_new(lua_State *L)
{
  OCSP_RESPONSE *res = NULL;

  ASN1_TIME* thispnd, *nextpnd;
  OCSP_CERTID *ca_id, *cid;
  OCSP_BASICRESP *bs;
  OCSP_REQUEST *req = CHECK_OBJECT(1, OCSP_REQUEST, "openssl.ocsp_request");
  X509* ca = CHECK_OBJECT(2, X509, "openssl.x509");
  X509* rcert = CHECK_OBJECT(3, X509, "openssl.x509");
  EVP_PKEY *rkey = CHECK_OBJECT(4, EVP_PKEY, "openssl.evp_pkey");

  unsigned long flag = luaL_optint(L, 6, 0);
  int nmin = luaL_optint(L, 7, 0);
  int nday = luaL_optint(L, 8, 1);
  STACK_OF(X509) *rother = lua_isnoneornil(L, 9) ? NULL : openssl_sk_x509_fromtable(L, 9);

  int i, id_count, type;
  BIO* bio = NULL;

  type = lua_type(L, 5);
  if (type != LUA_TFUNCTION && type != LUA_TTABLE)
  {
    luaL_error(L, "#5 must be a table or function that to get status of certificate");
  }
  bio = BIO_new(BIO_s_mem());
  ca_id = OCSP_cert_to_id(EVP_sha1(), NULL, ca);
  bs = OCSP_BASICRESP_new();
  thispnd = X509_gmtime_adj(NULL, 0);
  nextpnd = X509_gmtime_adj(NULL, nmin * 60 + nday * 3600 * 24);
  id_count = OCSP_request_onereq_count(req);

  for (i = 0; i < id_count; i++)
  {
    OCSP_ONEREQ  *one;
    ASN1_INTEGER *serial;
    ASN1_OBJECT* inst = NULL;
    ASN1_TIME* revtm = NULL;
    ASN1_GENERALIZEDTIME *invtm = NULL;
    OCSP_SINGLERESP *single = NULL;
    int reason = OCSP_REVOKED_STATUS_UNSPECIFIED, status = V_OCSP_CERTSTATUS_UNKNOWN;

    one = OCSP_request_onereq_get0(req, i);
    cid = OCSP_onereq_get0_id(one);
    if (OCSP_id_issuer_cmp(ca_id, cid))
    {
      OCSP_basic_add1_status(bs, cid, V_OCSP_CERTSTATUS_UNKNOWN,
                             0, NULL, thispnd, nextpnd);
      continue;
    }
    OCSP_id_get0_info(NULL, NULL, NULL, &serial, cid);

    if (lua_istable(L, 5))
    {
      BIGNUM* sn = ASN1_INTEGER_to_BN(serial, NULL);
      char* hex = BN_bn2hex(sn);

      lua_pushstring(L, hex);
      OPENSSL_free(hex);
      BN_free(sn);

      lua_rawget(L, 5);
      if (lua_isnil(L, -1))
        status = V_OCSP_CERTSTATUS_UNKNOWN;
      else
      {
        int top = lua_gettop(L);
        luaL_checktype(L, -1, LUA_TTABLE);
        lua_pushliteral(L, "reovked");
        lua_rawget(L, top);
        if (lua_toboolean(L, -1))
        {
          lua_pop(L, 1);

          status = V_OCSP_CERTSTATUS_REVOKED;

          lua_getfield(L, -1, "revoked_time");
          if (!lua_isnil(L, -1))
          {
            revtm = ASN1_TIME_new();
            ASN1_TIME_set(revtm, luaL_checkint(L, -1));
          }
          lua_pop(L, 1);

          lua_getfield(L, -1, "reason");
          if (lua_isstring(L, -1))
            reason = openssl_s2i_revoke_reason(lua_tostring(L, -1));
          else
            reason = luaL_checkint(L, -1);
          lua_pop(L, 1);
        }
        else
        {
          lua_pop(L, 1);
          status = V_OCSP_CERTSTATUS_GOOD;
        }
      }
    }
    else
      status = V_OCSP_CERTSTATUS_UNKNOWN;

    single = OCSP_basic_add1_status(bs, cid, status, reason, revtm, thispnd, nextpnd);

    if (invtm)
    {
      OCSP_SINGLERESP_add1_ext_i2d(single, NID_invalidity_date, invtm, 0, 0);
      ASN1_GENERALIZEDTIME_free(invtm);
    }
    if (inst)
    {
      OCSP_SINGLERESP_add1_ext_i2d(single, NID_hold_instruction_code, inst, 0, 0);
      ASN1_OBJECT_free(inst);
    }
    if (revtm)
      ASN1_TIME_free(revtm);
  }
  OCSP_copy_nonce(bs, req);
  OCSP_basic_sign(bs, rcert, rkey, EVP_sha1(), rother, flag);

  res = OCSP_response_create(OCSP_RESPONSE_STATUS_SUCCESSFUL, bs);
  BIO_free(bio);

  ASN1_TIME_free(thispnd);
  ASN1_TIME_free(nextpnd);
  OCSP_BASICRESP_free(bs);
  OCSP_CERTID_free(ca_id);

  if (res)
  {
    PUSH_OBJECT(res, "openssl.ocsp_response");
  }
  else
    lua_pushnil(L);
  return 1;
}

static int openssl_ocsp_response_export(lua_State*L)
{
  OCSP_RESPONSE *res = CHECK_OBJECT(1, OCSP_RESPONSE, "openssl.ocsp_response");
  int pem = lua_gettop(L) > 1 ? auxiliar_checkboolean(L, 2) : 0;
  int ret = 0;
  BIO* bio;

  bio = BIO_new(BIO_s_mem());
  if (pem)
  {
    ret = PEM_write_bio_OCSP_RESPONSE(bio, res);
  }
  else
  {
    ret = i2d_OCSP_RESPONSE_bio(bio, res);
  }
  if (ret)
  {
    BUF_MEM *buf;
    BIO_get_mem_ptr(bio, &buf);
    lua_pushlstring(L, buf->data, buf->length);
  }
  BIO_free(bio);
  return ret;
}

static int openssl_ocsp_response_parse(lua_State *L)
{
  luaL_error(L, "NYI");
  return 1;
}
int openssl_ocsp_response_free(lua_State*L)
{
  OCSP_RESPONSE *res = CHECK_OBJECT(1, OCSP_RESPONSE, "openssl.ocsp_response");
  OCSP_RESPONSE_free(res);
  return 0;
}

static luaL_Reg ocsp_req_cfuns[] =
{
  {"export",      openssl_ocsp_request_export },
  {"parse",       openssl_ocsp_request_parse  },
  {"sign",        openssl_ocsp_request_sign },
  {"add_ext",     openssl_ocsp_request_add_ext },

  {"__tostring",  auxiliar_tostring },
  {"__gc",        openssl_ocsp_request_free },

  {NULL,        NULL  }
};

static luaL_Reg ocsp_res_cfuns[] =
{
  {"export",      openssl_ocsp_response_export  },
  {"parse",       openssl_ocsp_response_parse },
  {"__gc",        openssl_ocsp_response_free  },

  {"__tostring",  auxiliar_tostring },

  {NULL,        NULL  }
};

static luaL_Reg R[] =
{
  {"request_read", openssl_ocsp_request_read},
  {"request_new",  openssl_ocsp_request_new},
  {"response_read", openssl_ocsp_response_read},
  {"response_new", openssl_ocsp_response_new},

  {NULL,    NULL}
};

static LuaL_Enumeration ocsp_reasons[] =
{
#define DEFINE_ENUM(x)  {#x,  OCSP_REVOKED_STATUS_##x}
  DEFINE_ENUM(NOSTATUS),
  DEFINE_ENUM(UNSPECIFIED),
  DEFINE_ENUM(KEYCOMPROMISE),
  DEFINE_ENUM(CACOMPROMISE),
  DEFINE_ENUM(AFFILIATIONCHANGED),
  DEFINE_ENUM(SUPERSEDED),
  DEFINE_ENUM(CESSATIONOFOPERATION),
  DEFINE_ENUM(CERTIFICATEHOLD),
  DEFINE_ENUM(REMOVEFROMCRL),
#undef DEFINE_ENUM

#define DEFINE_ENUM(x)  {#x,  V_OCSP_CERTSTATUS_##x}
  DEFINE_ENUM(GOOD),
  DEFINE_ENUM(REVOKED),
  DEFINE_ENUM(UNKNOWN),
#undef DEFINE_ENUM

  {NULL,                    -1}
};

int luaopen_ocsp(lua_State *L)
{
  auxiliar_newclass(L, "openssl.ocsp_request",   ocsp_req_cfuns);
  auxiliar_newclass(L, "openssl.ocsp_response",  ocsp_res_cfuns);

  lua_newtable(L);
  luaL_setfuncs(L, R, 0);
  auxiliar_enumerate(L, -1, ocsp_reasons);

  return 1;
}
