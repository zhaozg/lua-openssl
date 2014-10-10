/*=========================================================================*\
* crl.c
* X509 certificate revoke routines for lua-openssl binding
*
* Author:  george zhao <zhaozg(at)gmail.com>
\*=========================================================================*/
#include "openssl.h"
#include "private.h"
#include <openssl/x509v3.h>

#define MYNAME    "crl"
#define MYVERSION MYNAME " library for " LUA_VERSION " / Nov 2014 / "\
  "based on OpenSSL " SHLIB_VERSION_NUMBER

int   X509_CRL_cmp(const X509_CRL *a, const X509_CRL *b);
int   X509_CRL_match(const X509_CRL *a, const X509_CRL *b);

static const BIT_STRING_BITNAME reason_flags[] =
{
  {0, "Unused", "unused"},
  {1, "Key Compromise", "keyCompromise"},
  {2, "CA Compromise", "CACompromise"},
  {3, "Affiliation Changed", "affiliationChanged"},
  {4, "Superseded", "superseded"},
  {5, "Cessation Of Operation", "cessationOfOperation"},
  {6, "Certificate Hold", "certificateHold"},
  {7, "Privilege Withdrawn", "privilegeWithdrawn"},
  {8, "AA Compromise", "AACompromise"},
  { -1, NULL, NULL}
};

static const int reason_num = sizeof(reason_flags) / sizeof(BIT_STRING_BITNAME) - 1;

int openssl_get_revoke_reason(const char*s)
{
  int reason = -1;
  int i;
  for (i = 0; i < reason_num; i++)
  {
    if (strcasecmp(s, reason_flags[i].lname) == 0 || strcasecmp(s, reason_flags[i].sname) == 0)
    {
      reason = reason_flags[i].bitnum;
      break;
    }
  }
  return reason;
}

static int reason_get(lua_State*L, int reasonidx)
{
  int reason = 0;

  if (lua_isnumber(L, reasonidx))
  {
    reason = lua_tointeger(L, reasonidx);
  }
  else if (lua_isstring(L, reasonidx))
  {
    const char* s = lua_tostring(L, reasonidx);
    reason = openssl_get_revoke_reason(s);
  }
  else if (lua_isnoneornil(L, reasonidx))
    reason = 0;
  else
    luaL_argerror(L, reasonidx, "invalid revoke reason");

  luaL_argcheck(L, reason >= 0 && reason < reason_num, reasonidx, "fail convert to revoke reason");

  return reason;
}

static X509_REVOKED *create_revoked(lua_State*L, const BIGNUM* bn, time_t t, int reason)
{
  X509_REVOKED *revoked = X509_REVOKED_new();
  ASN1_TIME *tm = ASN1_TIME_new();
  ASN1_INTEGER *it =  BN_to_ASN1_INTEGER(bn, NULL);;

  ASN1_TIME_set(tm, t);

  X509_REVOKED_set_revocationDate(revoked, tm);
  X509_REVOKED_set_serialNumber(revoked, it);
#if OPENSSL_VERSION_NUMBER > 0x10000000L
  revoked->reason = reason;
#else
  {
    ASN1_ENUMERATED * e = ASN1_ENUMERATED_new();
    X509_EXTENSION * ext = X509_EXTENSION_new();

    ASN1_ENUMERATED_set(e, reason);

    X509_EXTENSION_set_data(ext, e);
    X509_EXTENSION_set_object(ext, OBJ_nid2obj(NID_crl_reason));
    X509_REVOKED_add_ext(revoked, ext, 0);

    X509_EXTENSION_free(ext);
    ASN1_ENUMERATED_free(e);
  }
#endif
  ASN1_TIME_free(tm);
  ASN1_INTEGER_free(it);

  return revoked;
}

static LUA_FUNCTION(openssl_crl_add_revocked)
{
  X509_CRL *crl = CHECK_OBJECT(1, X509_CRL, "openssl.x509_crl");
  BIGNUM* sn = BN_get(L, 2);
  time_t t = lua_tointeger(L, 3);
  int reason = reason_get(L, 4);

  int ret = 0;
  X509_REVOKED* revoked = create_revoked(L, sn, t, reason);
  ret = X509_CRL_add0_revoked(crl, revoked);
  lua_pushboolean(L, ret);
  BN_free(sn);
  return 1;
}

static int openssl_crl_extensions(lua_State* L)
{
  X509_CRL *crl = CHECK_OBJECT(1, X509_CRL, "openssl.x509_crl");
  if(lua_isnone(L,2))
  {
    STACK_OF(X509_EXTENSION) *exts = crl->crl->extensions;
    if(exts) {
      exts = sk_X509_EXTENSION_dup(exts);
      PUSH_OBJECT(exts,"openssl.stack_of_x509_extension");
    }else
      lua_pushnil(L);
    return 1;
  }else {
    STACK_OF(X509_EXTENSION) *exts = CHECK_OBJECT(1, STACK_OF(X509_EXTENSION), "openssl.stack_of_x509_extension");
    int i, n, ret;
    n = sk_X509_EXTENSION_num(exts);
    for(i=0, ret=1; i<n && ret==1; i++)
    {
      X509_EXTENSION *ext = sk_X509_EXTENSION_value(exts, i);
      X509_CRL_add_ext(crl, ext, i);
    };
    return openssl_pushresult(L, ret);
  }
  return 0;
}

static LUA_FUNCTION(openssl_crl_new)
{
  X509* x509 = lua_isnoneornil(L, 1) ? NULL : CHECK_OBJECT(1, X509, "openssl.x509");
  time_t lastUpdate = luaL_optinteger(L, 3, (lua_Integer)time(&lastUpdate));
  time_t nextUpdate = luaL_optinteger(L, 4, (lua_Integer)(lastUpdate + 7 * 24 * 3600));
  long version = luaL_optint(L, 5, 1);

  X509_CRL * crl = NULL;
  ASN1_TIME *ltm, *ntm;

  if (!lua_isnoneornil(L, 2))
    luaL_checktype(L, 2, LUA_TTABLE);

  crl = X509_CRL_new();
  X509_CRL_set_version(crl, version);
  if (x509)
    X509_CRL_set_issuer_name(crl, X509_get_subject_name(x509));

  ltm = ASN1_TIME_new();
  ntm = ASN1_TIME_new();
  ASN1_TIME_set(ltm, lastUpdate);
  ASN1_TIME_set(ntm, nextUpdate);
  X509_CRL_set_lastUpdate(crl, ltm);
  X509_CRL_set_nextUpdate(crl, ntm);
  ASN1_TIME_free(ltm);
  ASN1_TIME_free(ntm);


  if (lua_istable(L, 2) && lua_objlen(L, 2) > 0)
  {
    int i;
    int n = lua_objlen(L, 2);

    for (i = 1; i <= n; i++)
    {
      lua_rawgeti(L, 2, i);
      if (lua_istable(L, -1))
      {
        X509_REVOKED *revoked;

        lua_getfield(L, -1, "reason");
        lua_getfield(L, -2, "time");
        lua_getfield(L, -3, "sn");

        revoked = create_revoked(L, BN_get(L, -1), lua_tointeger(L, -2), reason_get(L, -3));
        if (revoked)
        {
          X509_CRL_add0_revoked(crl, revoked);
        }
        lua_pop(L, 3);
      }
      lua_pop(L, 1);
    }
  }

  PUSH_OBJECT(crl, "openssl.x509_crl");
  return 1;
}

static LUA_FUNCTION(openssl_crl_read)
{
  BIO * in = load_bio_object(L, 1);
  int fmt = luaL_checkoption(L, 2, "auto", format);

  X509_CRL *crl = NULL;

  if (fmt == FORMAT_AUTO || fmt == FORMAT_PEM)
  {
    crl = PEM_read_bio_X509_CRL(in, NULL, NULL, NULL);
    BIO_reset(in);
  }
  if ((fmt == FORMAT_AUTO && crl == NULL) || fmt == FORMAT_DER)
  {
    crl = d2i_X509_CRL_bio(in, NULL);
    BIO_reset(in);
  }
  BIO_free(in);
  if (crl)
  {
    ERR_clear_error();
    PUSH_OBJECT(crl, "openssl.x509_crl");
    return 1;
  }
  return 0;
}

static LUA_FUNCTION(openssl_crl_version)
{
  X509_CRL *crl = CHECK_OBJECT(1, X509_CRL, "openssl.x509_crl");
  if(lua_isnone(L, 2)) {
    lua_pushinteger(L, X509_CRL_get_version(crl));
    return 1;
  }else {
    long version = luaL_optinteger(L, 2, 0);
    int ret = X509_CRL_set_version(crl, version);
    return openssl_pushresult(L, ret);
  }
}

static LUA_FUNCTION(openssl_crl_issuer)
{
  X509_CRL *crl = CHECK_OBJECT(1, X509_CRL, "openssl.x509_crl");
  if(lua_isnone(L, 2)) {
    return openssl_push_xname_asobject(L, X509_CRL_get_issuer(crl));
  }else if(auxiliar_isclass(L, "openssl.x509_name", 2))
  {
    X509_NAME* xn = CHECK_OBJECT(2, X509_NAME, "openssl.x509_name");
    int ret = X509_CRL_set_issuer_name(crl, xn);
    return openssl_pushresult(L, ret);
  }else if(auxiliar_isclass(L, "openssl.x509", 2)) {
    X509* x = CHECK_OBJECT(2, X509, "openssl.x509");
    int ret = X509_CRL_set_issuer_name(crl, X509_get_issuer_name(x));
    return openssl_pushresult(L, ret);
  }else {
    luaL_argerror(L, 2, "only accept x509 or x509_name object");
  }
  return 0;
}

static LUA_FUNCTION(openssl_crl_lastUpdate)
{
  X509_CRL *crl = CHECK_OBJECT(1, X509_CRL, "openssl.x509_crl");
  if(lua_isnone(L, 2)) {
    ASN1_TIME *tm = X509_CRL_get_lastUpdate(crl);
    PUSH_ASN1_TIME(L, tm);
    return 1;
  }else {
    int ret;
    time_t time = luaL_checkint(L, 2);
    ASN1_TIME *tm = ASN1_TIME_new();
    ASN1_TIME_set(tm, time);

    ret = X509_CRL_set_lastUpdate(crl, tm);
    ASN1_TIME_free(tm);
    return openssl_pushresult(L, ret);
  }
}

static LUA_FUNCTION(openssl_crl_nextUpdate)
{
  X509_CRL *crl = CHECK_OBJECT(1, X509_CRL, "openssl.x509_crl");
  if(lua_isnone(L, 2)) {
    ASN1_TIME *tm = X509_CRL_get_nextUpdate(crl);
    PUSH_ASN1_TIME(L, tm);
    return 1;
  }else {
    int ret;
    time_t time = luaL_checkint(L, 2);
    ASN1_TIME *tm = ASN1_TIME_new();
    ASN1_TIME_set(tm, time);

    ret = X509_CRL_set_nextUpdate(crl, tm);
    ASN1_TIME_free(tm);
    return openssl_pushresult(L, ret);
  }
}

static LUA_FUNCTION(openssl_crl_updateTime)
{
  X509_CRL *crl = CHECK_OBJECT(1, X509_CRL, "openssl.x509_crl");
  if(lua_isnone(L, 2)) {
     ASN1_TIME *ltm, *ntm;
     ltm = X509_CRL_get_lastUpdate(crl);
     ntm = X509_CRL_get_nextUpdate(crl);
     PUSH_ASN1_TIME(L, ltm);
     PUSH_ASN1_TIME(L, ntm);
     return 2;
  }else  {
    ASN1_TIME *ltm, *ntm;
    int ret = 0;

    time_t last, next;

    if (lua_gettop(L)==2) {
      time(&last);
      next = last + luaL_checkint(L,2);
    }else{
      last = luaL_checkint(L, 2);
      next = last + luaL_checkint(L, 3);
      luaL_argcheck(L, next > last, 3, "value must after #2");
    }

    ltm = ASN1_TIME_new();
    ASN1_TIME_set(ltm, last);
    ntm = ASN1_TIME_new();
    ASN1_TIME_set(ntm, next);
    ret = X509_CRL_set_lastUpdate(crl, ltm);
    if (ret == 1)
      ret = X509_CRL_set_nextUpdate(crl, ntm);
    ASN1_TIME_free(ltm);
    ASN1_TIME_free(ntm);
    openssl_pushresult(L, ret);
    return 1;
  }
  return 0;
}

static LUA_FUNCTION(openssl_crl_sort)
{
  X509_CRL *crl = CHECK_OBJECT(1, X509_CRL, "openssl.x509_crl");
  int ret = X509_CRL_sort(crl);
  return openssl_pushresult(L, ret);
}

static LUA_FUNCTION(openssl_crl_verify)
{
  X509_CRL *crl = CHECK_OBJECT(1, X509_CRL, "openssl.x509_crl");
  X509* cacert = CHECK_OBJECT(2, X509, "openssl.x509");

  int ret = X509_CRL_verify(crl, cacert->cert_info->key->pkey);
  return openssl_pushresult(L, ret);
}

LUA_FUNCTION(openssl_crl_sign)
{
  X509_CRL *crl = CHECK_OBJECT(1, X509_CRL, "openssl.x509_crl");
  EVP_PKEY *key = CHECK_OBJECT(2, EVP_PKEY, "openssl.evp_pkey");
  const EVP_MD *md = lua_isnoneornil(L, 4)
                     ? EVP_get_digestbyname("sha1") : get_digest(L, 4);

  int ret = 1;

  luaL_argcheck(L, auxiliar_isclass(L,"openssl.x509", 3) || auxiliar_isclass(L, "openssl.x509_name", 3),
    3, "must be openssl.x509 or openssl.x509_name object");
  if(auxiliar_isclass(L, "openssl.x509_name", 3)) {
    X509_NAME* xn = CHECK_OBJECT(3, X509_NAME, "openssl.x509_name");
    ret = X509_CRL_set_issuer_name(crl,xn);
  }else if(auxiliar_isclass(L, "openssl.x509", 3)) {
    X509* ca = CHECK_OBJECT(3, X509, "openssl.x509");
    ret = X509_CRL_set_issuer_name(crl, X509_get_issuer_name(ca));
    if(ret==1){
      ret = X509_check_private_key(ca, key);
      if(ret!=1) {
        luaL_error(L, "private key not match with cacert");
      }
    }
  }
  if(ret==1)
    ret = X509_CRL_sort(crl);
  if(ret==1)
    ret = X509_CRL_sign(crl, key, md);
  return openssl_pushresult(L, ret);
}

static LUA_FUNCTION(openssl_crl_digest)
{
  X509_CRL *crl = CHECK_OBJECT(1, X509_CRL, "openssl.x509_crl");
  byte buf[EVP_MAX_MD_SIZE];
  int lbuf = sizeof(buf);
  const EVP_MD *md = lua_isnoneornil(L, 2)
    ? EVP_get_digestbyname("sha1") : get_digest(L, 2);

  int ret =  X509_CRL_digest(crl, md, buf, &lbuf);
  if(ret==1)
  {
    lua_pushlstring(L, buf, lbuf);
    return ret;
  }
  return openssl_pushresult(L, ret);
}

static LUA_FUNCTION(openssl_crl_cmp)
{
  X509_CRL *crl = CHECK_OBJECT(1, X509_CRL, "openssl.x509_crl");
  X509_CRL *oth = CHECK_OBJECT(2, X509_CRL, "openssl.x509_crl");
  int ret = X509_CRL_cmp(crl, oth);
  lua_pushboolean(L, ret==0);
  return 1;
}

static LUA_FUNCTION(openssl_crl_diff)
{
  X509_CRL *crl = CHECK_OBJECT(1, X509_CRL, "openssl.x509_crl");
  X509_CRL *newer = CHECK_OBJECT(2, X509_CRL, "openssl.x509_crl");
  EVP_PKEY* pkey = CHECK_OBJECT(3, EVP_PKEY, "openssl.evp_pkey");
  const EVP_MD *md = lua_isnoneornil(L, 4)
    ? EVP_get_digestbyname("sha1") : get_digest(L, 4);
  int flags = luaL_optinteger(L, 5, 0);

  X509_CRL *diff  =  X509_CRL_diff(crl, newer, pkey, md, flags);
  if(diff)
  {
    PUSH_OBJECT(diff,"openssl.x509_crl");
  }else
    lua_pushnil(L);
  return 1;
}

static LUA_FUNCTION(openssl_crl_check_suiteb)
{
  X509_CRL *crl = CHECK_OBJECT(1, X509_CRL, "openssl.x509_crl");
  EVP_PKEY* pkey = CHECK_OBJECT(2, EVP_PKEY, "openssl.evp_pkey");
  unsigned long flags = luaL_optinteger(L, 3, 0);

  int ret = X509_CRL_check_suiteb(crl, pkey, flags);
  return openssl_pushresult(L, ret);
}

static LUA_FUNCTION(openssl_crl_parse)
{
  X509_CRL *crl = CHECK_OBJECT(1, X509_CRL, "openssl.x509_crl");
  int utf8 = lua_isnoneornil(L, 2) ? 1 : lua_toboolean(L, 2);
  int n, i;

  lua_newtable(L);
  AUXILIAR_SET(L, -1, "version", X509_CRL_get_version(crl), integer);

  /* hash as used in CA directories to lookup cert by subject name */
  {
    char buf[32];
    snprintf(buf, sizeof(buf), "%08lx", X509_NAME_hash(X509_CRL_get_issuer(crl)));
    AUXILIAR_SET(L, -1, "hash", buf, string);
  }

  {
    const EVP_MD *digest = EVP_get_digestbyname("sha1");
    unsigned char md[EVP_MAX_MD_SIZE];
    int n = sizeof(md);

    if (X509_CRL_digest(crl, digest, md, (unsigned int*)&n))
    {
      lua_newtable(L);
      AUXILIAR_SET(L, -1, "alg", OBJ_nid2sn(EVP_MD_type(digest)), string);
      AUXILIAR_SETLSTR(L, -1, "hash", (const char*)md, n);

      lua_setfield(L, -2, "fingerprint");
    }
  }

  openssl_push_xname_asobject(L, X509_CRL_get_issuer(crl));
  lua_setfield(L, -2, "issuer");

  PUSH_ASN1_TIME(L,X509_CRL_get_lastUpdate(crl));
  lua_setfield(L, -2, "lastUpdate");
  PUSH_ASN1_TIME(L,X509_CRL_get_nextUpdate(crl));
  lua_setfield(L, -2, "nextUpdate");

  openssl_push_x509_algor(L, crl->crl->sig_alg);
  lua_setfield(L, -2, "sig_alg");
  
  PUSH_ASN1_INTEGER(L, X509_CRL_get_ext_d2i(crl, NID_crl_number, NULL, NULL));
  lua_setfield(L, -2, "crl_number");
  
  {
    STACK_OF(X509_EXTENSION) *extensions = sk_X509_EXTENSION_dup(crl->crl->extensions);
    PUSH_OBJECT(extensions,"openssl.stack_of_x509_extension");
    lua_setfield(L, -2, "extensions");
  }

  n = sk_X509_REVOKED_num(crl->crl->revoked);
  lua_newtable(L);
  for (i = 0; i < n; i++)
  {
    X509_REVOKED *revoked = sk_X509_REVOKED_value(crl->crl->revoked, i);
    lua_newtable(L);

#if OPENSSL_VERSION_NUMBER > 0x10000000L
    AUXILIAR_SET(L, -1, "CRLReason", reason_flags[revoked->reason].lname, string);
#else
    {
      int crit = 0;
      void* reason = X509_REVOKED_get_ext_d2i(revoked, NID_crl_reason, &crit, NULL);

      AUXILIAR_SET(L, -1, "CRLReason", reason_flags[ASN1_ENUMERATED_get(reason)].lname, string);
      ASN1_ENUMERATED_free(reason);
    }
#endif
    PUSH_ASN1_INTEGER(L, revoked->serialNumber);
    lua_setfield(L,-2, "serialNumber");

    PUSH_ASN1_TIME(L, revoked->revocationDate);
    lua_setfield(L,-2, "revocationDate");

    {
      STACK_OF(X509_EXTENSION) *extensions = sk_X509_EXTENSION_dup(crl->crl->extensions);
      PUSH_OBJECT(extensions,"openssl.stack_of_x509_extension");
      lua_setfield(L,-2, "extensions");
    }

    lua_rawseti(L, -2, i + 1);
  }

  lua_setfield(L, -2, "revoked");
  return 1;
}

static LUA_FUNCTION(openssl_crl_free)
{
  X509_CRL *crl = CHECK_OBJECT(1, X509_CRL, "openssl.x509_crl");
  lua_pushnil(L);
  lua_setmetatable(L, 1);
  X509_CRL_free(crl);
  return 0;
}

static LUA_FUNCTION(openssl_crl_export)
{
  X509_CRL * crl = CHECK_OBJECT(1, X509_CRL, "openssl.x509_crl");
  int fmt = luaL_checkoption(L, 2, "pem", format);
  int notext = lua_isnoneornil(L, 3) ? 1 : lua_toboolean(L, 3);
  BIO *out  = NULL;

  luaL_argcheck(L, fmt == FORMAT_DER || fmt == FORMAT_PEM, 2,
                "only accept der or pem");

  out  = BIO_new(BIO_s_mem());
  if (fmt == FORMAT_PEM)
  {
    if (!notext)
    {
      X509_CRL_print(out, crl);
    }

    if (PEM_write_bio_X509_CRL(out, crl))
    {
      BUF_MEM *bio_buf;
      BIO_get_mem_ptr(out, &bio_buf);
      lua_pushlstring(L, bio_buf->data, bio_buf->length);
    }
    else
      lua_pushnil(L);
  }
  else
  {
    if (i2d_X509_CRL_bio(out, crl))
    {
      BUF_MEM *bio_buf;
      BIO_get_mem_ptr(out, &bio_buf);
      lua_pushlstring(L, bio_buf->data, bio_buf->length);
    }
    else
      lua_pushnil(L);
  }

  BIO_free(out);
  return 1;
}

static luaL_Reg crl_funcs[] =
{
  {"sort",            openssl_crl_sort},
  {"verify",          openssl_crl_verify},
  {"sign",            openssl_crl_sign},
  {"digest",          openssl_crl_digest},
  {"diff",            openssl_crl_diff},
  {"check",           openssl_crl_check_suiteb},

  /* set and get */
  {"version",         openssl_crl_version},
  {"issuer",          openssl_crl_issuer},
  {"lastUpdate",      openssl_crl_lastUpdate},
  {"nextUpdate",      openssl_crl_nextUpdate},
  {"updateTime",      openssl_crl_updateTime},
  {"extension",       openssl_crl_extensions},

  {"add",             openssl_crl_add_revocked},

  {"parse",           openssl_crl_parse},
  {"export",          openssl_crl_export},

  {"cmp",             openssl_crl_cmp},
  {"__eq",            openssl_crl_cmp},

  {"__tostring",      auxiliar_tostring},
  {"__gc",            openssl_crl_free  },

  {NULL,  NULL}
};

static luaL_reg R[] =
{
  {"new",       openssl_crl_new },
  {"read",      openssl_crl_read},
  {NULL,    NULL}
};

LUALIB_API int luaopen_crl(lua_State *L)
{
  auxiliar_newclass(L, "openssl.x509_crl", crl_funcs);

  luaL_register(L, MYNAME, R);

  lua_pushliteral(L, "version");    /** version */
  lua_pushliteral(L, MYVERSION);
  lua_settable(L, -3);

  return 1;
}
