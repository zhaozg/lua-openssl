/*=========================================================================*\
* crl.c
* X509 certificate revoke routines for lua-openssl binding
*
* Author:  george zhao <zhaozg(at)gmail.com>
\*=========================================================================*/
#include "openssl.h"
#include "private.h"
#define CRYPTO_LOCK_REF
#include "sk.h"
#include <openssl/x509v3.h>

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

const char* openssl_i2s_revoke_reason(int reason)
{
  int i;
  for (i = 0; i < reason_num && i != reason; i++);
  if (i == reason_num)
    return "unset";
  else
    return reason_flags[i].sname;
}
int openssl_s2i_revoke_reason(const char*s)
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
    reason = openssl_s2i_revoke_reason(s);
  }
  else if (lua_isnoneornil(L, reasonidx))
    reason = 0;
  else
    luaL_argerror(L, reasonidx, "invalid revoke reason");

  luaL_argcheck(L, reason >= 0 && reason < reason_num, reasonidx, "fail convert to revoke reason");

  return reason;
}

static X509_REVOKED *create_revoked(const BIGNUM* bn, time_t t, int reason)
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
  X509_REVOKED* revoked = create_revoked(sn, t, reason);
  ret = X509_CRL_add0_revoked(crl, revoked);
  lua_pushboolean(L, ret);
  BN_free(sn);
  return 1;
}

static int openssl_crl_extensions(lua_State* L)
{
  X509_CRL *crl = CHECK_OBJECT(1, X509_CRL, "openssl.x509_crl");
  if (lua_isnone(L, 2))
  {
    STACK_OF(X509_EXTENSION) *exts = crl->crl->extensions;
    if (exts)
    {
      openssl_sk_x509_extension_totable(L, exts);
    }
    else
      lua_pushnil(L);
    return 1;
  }
  else
  {
    STACK_OF(X509_EXTENSION) *exts = openssl_sk_x509_extension_fromtable(L, 2);
    int i, n;
    n = sk_X509_EXTENSION_num(exts);
    for (i = 0; i < n; i++)
    {
      X509_EXTENSION *ext = sk_X509_EXTENSION_value(exts, i);
      X509_CRL_add_ext(crl, X509_EXTENSION_dup(ext), i);
    };
    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    return openssl_pushresult(L, 1);
  }
}

static LUA_FUNCTION(openssl_crl_new)
{
  int i;
  int n = lua_gettop(L);
  X509_CRL * crl = X509_CRL_new();
  int ret = X509_CRL_set_version(crl, 0);
  X509* cacert = NULL;
  EVP_PKEY* capkey = NULL;
  const EVP_MD* md = NULL;
  int step;

  for (i = 1; ret == 1 && i <= n; i++)
  {
    if (i == 1)
    {
      luaL_argcheck(L, lua_istable(L, 1), 1, "must be table contains rovked entry table{reason,time,sn}");
      if (lua_rawlen(L, i) > 0)
      {
        int j, m;
        m = lua_rawlen(L, i);

        for (j = 1; ret == 1 && j <= m; j++)
        {
          X509_REVOKED *revoked;
          BIGNUM* sn;
          lua_rawgeti(L, i, j);
          luaL_checktable(L, -1);

          lua_getfield(L, -1, "reason");
          lua_getfield(L, -2, "time");
          lua_getfield(L, -3, "sn");
          sn = BN_get(L, -1);
          revoked = create_revoked(sn, lua_tointeger(L, -2), reason_get(L, -3));
          if (revoked)
          {
            ret = X509_CRL_add0_revoked(crl, revoked);
          }
          BN_free(sn);
          lua_pop(L, 3);
          lua_pop(L, 1);
        };
      }
    };
    if (i == 2)
    {
      cacert = CHECK_OBJECT(2, X509, "openssl.x509");
      ret = X509_CRL_set_issuer_name(crl, X509_get_issuer_name(cacert));
    }
    if (i == 3)
    {
      capkey = CHECK_OBJECT(3, EVP_PKEY, "openssl.evp_pkey");
      luaL_argcheck(L, openssl_pkey_is_private(capkey), 3, "must be private key");
      luaL_argcheck(L, X509_check_private_key(cacert, capkey) == 1, 3, "evp_pkey not match with x509 in #2");
    }
  }
  md = lua_isnoneornil(L, 4) ? EVP_get_digestbyname("sha1") : get_digest(L, 4);
  step = lua_isnoneornil(L, 5) ? 7 * 24 * 3600 : luaL_checkint(L, 5);

  if (ret == 1)
  {
    time_t lastUpdate;
    time_t nextUpdate;
    ASN1_TIME *ltm, *ntm;

    time(&lastUpdate);
    nextUpdate = lastUpdate + step;

    ltm = ASN1_TIME_new();
    ntm = ASN1_TIME_new();
    ASN1_TIME_set(ltm, lastUpdate);
    ASN1_TIME_set(ntm, nextUpdate);
    ret = X509_CRL_set_lastUpdate(crl, ltm);
    if (ret == 1)
      ret = X509_CRL_set_nextUpdate(crl, ntm);
    ASN1_TIME_free(ltm);
    ASN1_TIME_free(ntm);
  }
  if (cacert && capkey && md)
  {
    ret = (X509_CRL_sign(crl, capkey, md) == EVP_PKEY_size(capkey));
  }
  if (ret == 1)
  {
    PUSH_OBJECT(crl, "openssl.x509_crl");
  }
  else
  {
    X509_CRL_free(crl);
    return openssl_pushresult(L, ret);
  };

  return 1;
}

static LUA_FUNCTION(openssl_crl_read)
{
  BIO * in = load_bio_object(L, 1);
  int fmt = luaL_checkoption(L, 2, "auto", format);
  X509_CRL *crl = NULL;

  if (fmt == FORMAT_AUTO)
  {
    fmt = bio_is_der(in) ? FORMAT_DER : FORMAT_PEM;
  }

  if (fmt == FORMAT_PEM)
  {
    crl = PEM_read_bio_X509_CRL(in, NULL, NULL, NULL);
    BIO_reset(in);
  }
  else if (fmt == FORMAT_DER)
  {
    crl = d2i_X509_CRL_bio(in, NULL);
    BIO_reset(in);
  }
  BIO_free(in);
  if (crl)
  {
    PUSH_OBJECT(crl, "openssl.x509_crl");
    return 1;
  }
  return openssl_pushresult(L, 0);
}

static LUA_FUNCTION(openssl_crl_version)
{
  X509_CRL *crl = CHECK_OBJECT(1, X509_CRL, "openssl.x509_crl");
  if (lua_isnone(L, 2))
  {
    lua_pushinteger(L, X509_CRL_get_version(crl));
    return 1;
  }
  else
  {
    long version = luaL_optinteger(L, 2, 0);
    int ret = X509_CRL_set_version(crl, version);
    return openssl_pushresult(L, ret);
  }
}

static LUA_FUNCTION(openssl_crl_issuer)
{
  X509_CRL *crl = CHECK_OBJECT(1, X509_CRL, "openssl.x509_crl");
  if (lua_isnone(L, 2))
  {
    return openssl_push_xname_asobject(L, X509_CRL_get_issuer(crl));
  }
  else if (auxiliar_isclass(L, "openssl.x509_name", 2))
  {
    X509_NAME* xn = CHECK_OBJECT(2, X509_NAME, "openssl.x509_name");
    int ret = X509_CRL_set_issuer_name(crl, xn);
    return openssl_pushresult(L, ret);
  }
  else if (auxiliar_isclass(L, "openssl.x509", 2))
  {
    X509* x = CHECK_OBJECT(2, X509, "openssl.x509");
    int ret = X509_CRL_set_issuer_name(crl, X509_get_issuer_name(x));
    return openssl_pushresult(L, ret);
  }
  else
  {
    luaL_argerror(L, 2, "only accept x509 or x509_name object");
  }
  return 0;
}

static LUA_FUNCTION(openssl_crl_lastUpdate)
{
  X509_CRL *crl = CHECK_OBJECT(1, X509_CRL, "openssl.x509_crl");
  if (lua_isnone(L, 2))
  {
    ASN1_TIME *tm = X509_CRL_get_lastUpdate(crl);
    PUSH_ASN1_TIME(L, tm);
    return 1;
  }
  else
  {
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
  if (lua_isnone(L, 2))
  {
    ASN1_TIME *tm = X509_CRL_get_nextUpdate(crl);
    PUSH_ASN1_TIME(L, tm);
    return 1;
  }
  else
  {
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
  if (lua_isnone(L, 2))
  {
    ASN1_TIME *ltm, *ntm;
    ltm = X509_CRL_get_lastUpdate(crl);
    ntm = X509_CRL_get_nextUpdate(crl);
    PUSH_ASN1_TIME(L, ltm);
    PUSH_ASN1_TIME(L, ntm);
    return 2;
  }
  else
  {
    ASN1_TIME *ltm, *ntm;
    int ret = 0;

    time_t last, next;

    if (lua_gettop(L) == 2)
    {
      time(&last);
      next = last + luaL_checkint(L, 2);
    }
    else
    {
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
  EVP_PKEY *pub = NULL;
  int ret;
  luaL_argcheck(L, 
    auxiliar_isclass(L, "openssl.x509", 2) ||
    auxiliar_isclass(L, "openssl.evp_pkey", 2),
    2,
    "must be x509 or evp_pkey object");
  if (auxiliar_isclass(L, "openssl.evp_pkey", 2))
  {
    pub = CHECK_OBJECT(2, EVP_PKEY, "openssl.evp_pkey");
    ret = X509_CRL_verify(crl, pub);
  }
  else 
  {
    X509* cacert = CHECK_OBJECT(2, X509, "openssl.x509");
    pub = X509_get_pubkey(cacert);
    ret = X509_CRL_verify(crl, pub);
    EVP_PKEY_free(pub);
  }

  
  return openssl_pushresult(L, ret);
}

LUA_FUNCTION(openssl_crl_sign)
{
  X509_CRL *crl = CHECK_OBJECT(1, X509_CRL, "openssl.x509_crl");
  EVP_PKEY *key = CHECK_OBJECT(2, EVP_PKEY, "openssl.evp_pkey");
  const EVP_MD *md = lua_isnoneornil(L, 4)
                     ? EVP_get_digestbyname("sha1") : get_digest(L, 4);

  int ret = 1;

  luaL_argcheck(L, auxiliar_isclass(L, "openssl.x509", 3) || auxiliar_isclass(L, "openssl.x509_name", 3),
                3, "must be openssl.x509 or openssl.x509_name object");
  if (auxiliar_isclass(L, "openssl.x509_name", 3))
  {
    X509_NAME* xn = CHECK_OBJECT(3, X509_NAME, "openssl.x509_name");
    ret = X509_CRL_set_issuer_name(crl, xn);
  }
  else if (auxiliar_isclass(L, "openssl.x509", 3))
  {
    X509* ca = CHECK_OBJECT(3, X509, "openssl.x509");
    ret = X509_CRL_set_issuer_name(crl, X509_get_issuer_name(ca));
    if (ret == 1)
    {
      ret = X509_check_private_key(ca, key);
      if (ret != 1)
      {
        luaL_error(L, "private key not match with cacert");
      }
    }
  }
  if (ret == 1)
    ret = X509_CRL_sort(crl);
  if (ret == 1)
    ret = X509_CRL_sign(crl, key, md) == EVP_PKEY_size(key);
  return openssl_pushresult(L, ret);
}

static LUA_FUNCTION(openssl_crl_digest)
{
  X509_CRL *crl = CHECK_OBJECT(1, X509_CRL, "openssl.x509_crl");
  byte buf[EVP_MAX_MD_SIZE];
  unsigned int lbuf = sizeof(buf);
  const EVP_MD *md = lua_isnoneornil(L, 2)
                     ? EVP_get_digestbyname("sha1") : get_digest(L, 2);

  int ret =  X509_CRL_digest(crl, md, buf, &lbuf);
  if (ret == 1)
  {
    lua_pushlstring(L, (const char*)buf, (size_t)lbuf);
    return ret;
  }
  return openssl_pushresult(L, ret);
}

static LUA_FUNCTION(openssl_crl_cmp)
{
  X509_CRL *crl = CHECK_OBJECT(1, X509_CRL, "openssl.x509_crl");
  X509_CRL *oth = CHECK_OBJECT(2, X509_CRL, "openssl.x509_crl");
  int ret = X509_CRL_cmp(crl, oth);
  lua_pushboolean(L, ret == 0);
  return 1;
}

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined (LIBRESSL_VERSION_NUMBER)
static LUA_FUNCTION(openssl_crl_diff)
{
  X509_CRL *crl = CHECK_OBJECT(1, X509_CRL, "openssl.x509_crl");
  X509_CRL *newer = CHECK_OBJECT(2, X509_CRL, "openssl.x509_crl");
  EVP_PKEY* pkey = CHECK_OBJECT(3, EVP_PKEY, "openssl.evp_pkey");
  const EVP_MD *md = lua_isnoneornil(L, 4)
                     ? EVP_get_digestbyname("sha1") : get_digest(L, 4);
  unsigned int flags = luaL_optinteger(L, 5, 0);
  X509_CRL *diff;

  diff  =  X509_CRL_diff(crl, newer, pkey, md, flags);
  if (diff)
  {
    PUSH_OBJECT(diff, "openssl.x509_crl");
  }
  else
    lua_pushnil(L);
  return 1;
}
static LUA_FUNCTION(openssl_crl_check)
{
  X509_CRL *crl = CHECK_OBJECT(1, X509_CRL, "openssl.x509_crl");
  EVP_PKEY* pkey = CHECK_OBJECT(2, EVP_PKEY, "openssl.evp_pkey");
  unsigned long flags = luaL_optinteger(L, 3, X509_V_FLAG_SUITEB_128_LOS);
  int ret  =  X509_CRL_check_suiteb(crl, pkey, flags);
  return openssl_pushresult(L, ret == X509_V_OK);
}
#endif

static LUA_FUNCTION(openssl_crl_parse)
{
  X509_CRL *crl = CHECK_OBJECT(1, X509_CRL, "openssl.x509_crl");
  int num, i;
  X509_ALGOR *alg;

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
    unsigned int l = sizeof(md);

    if (X509_CRL_digest(crl, digest, md, &l) == 1)
    {
      lua_newtable(L);
      AUXILIAR_SET(L, -1, "alg", OBJ_nid2sn(EVP_MD_type(digest)), string);
      AUXILIAR_SETLSTR(L, -1, "hash", (const char*)md, l);

      lua_setfield(L, -2, "fingerprint");
    }
  }

  openssl_push_xname_asobject(L, X509_CRL_get_issuer(crl));
  lua_setfield(L, -2, "issuer");

  PUSH_ASN1_TIME(L, X509_CRL_get_lastUpdate(crl));
  lua_setfield(L, -2, "lastUpdate");
  PUSH_ASN1_TIME(L, X509_CRL_get_nextUpdate(crl));
  lua_setfield(L, -2, "nextUpdate");

  alg = X509_ALGOR_dup(crl->crl->sig_alg);
  PUSH_OBJECT(alg, "openssl.x509_algor");
  lua_setfield(L, -2, "sig_alg");

#if OPENSSL_VERSION_NUMBER > 0x00909000L
  if (crl->crl_number)
  {
    PUSH_ASN1_INTEGER(L, crl->crl_number);
    lua_setfield(L, -2, "crl_number");
  }
#endif
  if (crl->crl->extensions)
  {
    lua_pushstring(L, "extensions");
    openssl_sk_x509_extension_totable(L, crl->crl->extensions);
    lua_rawset(L, -3);
  }

  num = sk_X509_REVOKED_num(crl->crl->revoked);
  lua_newtable(L);
  for (i = 0; i < num; i++)
  {
    X509_REVOKED *revoked = sk_X509_REVOKED_value(crl->crl->revoked, i);
    lua_newtable(L);

#if OPENSSL_VERSION_NUMBER > 0x10000000L
    AUXILIAR_SET(L, -1, "CRLReason", openssl_i2s_revoke_reason(revoked->reason), string);
#else
    {
      int crit = 0;
      void* reason = X509_REVOKED_get_ext_d2i(revoked, NID_crl_reason, &crit, NULL);

      AUXILIAR_SET(L, -1, "CRLReason", openssl_i2s_revoke_reason(ASN1_ENUMERATED_get(reason)), string);
      ASN1_ENUMERATED_free(reason);
    }
#endif
    PUSH_ASN1_INTEGER(L, revoked->serialNumber);
    lua_setfield(L, -2, "serialNumber");

    PUSH_ASN1_TIME(L, revoked->revocationDate);
    lua_setfield(L, -2, "revocationDate");

    if (crl->crl->extensions)
    {
      lua_pushstring(L, "extensions");
      openssl_sk_x509_extension_totable(L, crl->crl->extensions);
      lua_rawset(L, -3);
    }

    lua_rawseti(L, -2, i + 1);
  }

  lua_setfield(L, -2, "revoked");
  return 1;
}

static LUA_FUNCTION(openssl_crl_free)
{
  X509_CRL *crl = CHECK_OBJECT(1, X509_CRL, "openssl.x509_crl");
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


static LUA_FUNCTION(openssl_crl_count)
{
  X509_CRL * crl = CHECK_OBJECT(1, X509_CRL, "openssl.x509_crl");
  int n = sk_X509_REVOKED_num(crl->crl->revoked);
  lua_pushinteger(L, n);
  return 1;
}

static LUA_FUNCTION(openssl_crl_get)
{
  X509_CRL * crl = CHECK_OBJECT(1, X509_CRL, "openssl.x509_crl");
  int i = 0;
  X509_REVOKED *revoked = NULL;
  if (lua_isinteger(L, 2))
  {
    i = lua_tointeger(L, 2);
    luaL_argcheck(L, (i >= 0 && i < sk_X509_REVOKED_num(crl->crl->revoked)), 2, "Out of range");
    revoked = sk_X509_REVOKED_value(crl->crl->revoked, i);
  }
  else
  {
    ASN1_STRING *sn = CHECK_OBJECT(2, ASN1_STRING, "openssl.asn1_integer");
    int cnt = sk_X509_REVOKED_num(crl->crl->revoked);
    for (i = 0; i < cnt; i++)
    {
      X509_REVOKED *rev = sk_X509_REVOKED_value(crl->crl->revoked, i);
      if (ASN1_STRING_cmp(rev->serialNumber, sn) == 0)
      {
        revoked = rev;
        break;
      }
    }
  }
  if (revoked)
  {
    lua_newtable(L);

#if OPENSSL_VERSION_NUMBER > 0x10000000L
    AUXILIAR_SET(L, -1, "code", revoked->reason, number);
    AUXILIAR_SET(L, -1, "reason", openssl_i2s_revoke_reason(revoked->reason), string);
#else
    {
      int crit = 0;
      void* reason = X509_REVOKED_get_ext_d2i(revoked, NID_crl_reason, &crit, NULL);
      AUXILIAR_SET(L, -1, "code", ASN1_ENUMERATED_get(reason), number);
      AUXILIAR_SET(L, -1, "reason", openssl_i2s_revoke_reason(ASN1_ENUMERATED_get(reason)), string);
      ASN1_ENUMERATED_free(reason);
    }
#endif
    PUSH_ASN1_INTEGER(L, revoked->serialNumber);
    lua_setfield(L, -2, "serialNumber");

    PUSH_ASN1_TIME(L, revoked->revocationDate);
    lua_setfield(L, -2, "revocationDate");

    if (crl->crl->extensions)
    {
      lua_pushstring(L, "extensions");
      openssl_sk_x509_extension_totable(L, crl->crl->extensions);
      lua_rawset(L, -3);
    }
  }
  else
    lua_pushnil(L);
  return 1;
}

static luaL_Reg crl_funcs[] =
{
  {"sort",            openssl_crl_sort},
  {"verify",          openssl_crl_verify},
  {"sign",            openssl_crl_sign},
  {"digest",          openssl_crl_digest},

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined (LIBRESSL_VERSION_NUMBER)
  {"diff",            openssl_crl_diff},
  {"check",           openssl_crl_check},
#endif

  /* set and get */
  {"version",         openssl_crl_version},
  {"issuer",          openssl_crl_issuer},
  {"lastUpdate",      openssl_crl_lastUpdate},
  {"nextUpdate",      openssl_crl_nextUpdate},
  {"updateTime",      openssl_crl_updateTime},
  {"extensions",      openssl_crl_extensions},

  {"add",             openssl_crl_add_revocked},

  {"parse",           openssl_crl_parse},
  {"export",          openssl_crl_export},

  {"cmp",             openssl_crl_cmp},
  {"count",           openssl_crl_count},
  {"get",             openssl_crl_get},
  {"__len",           openssl_crl_count},
  {"__eq",            openssl_crl_cmp},

  {"__tostring",      auxiliar_tostring},
  {"__gc",            openssl_crl_free  },

  {NULL,  NULL}
};

static int openssl_revoked_info(lua_State* L)
{
  X509_REVOKED* revoked = CHECK_OBJECT(1, X509_REVOKED, "openssl.x509_revoked");
  lua_newtable(L);

#if OPENSSL_VERSION_NUMBER > 0x10000000L
  AUXILIAR_SET(L, -1, "reason", openssl_i2s_revoke_reason(revoked->reason), string);
#else
  {
    int crit = 0;
    void* reason = X509_REVOKED_get_ext_d2i(revoked, NID_crl_reason, &crit, NULL);

    AUXILIAR_SET(L, -1, "reason", openssl_i2s_revoke_reason(ASN1_ENUMERATED_get(reason)), string);
    ASN1_ENUMERATED_free(reason);
  }
#endif
  PUSH_ASN1_INTEGER(L, revoked->serialNumber);
  lua_setfield(L, -2, "serialNumber");

  PUSH_ASN1_TIME(L, revoked->revocationDate);
  lua_setfield(L, -2, "revocationDate");

  if (revoked->extensions)
  {
    lua_pushstring(L, "extensions");
    openssl_sk_x509_extension_totable(L, revoked->extensions);
    lua_rawset(L, -3);
  }
  return 1;
};

static int openssl_revoked_reason(lua_State* L)
{
  X509_REVOKED* revoked = CHECK_OBJECT(1, X509_REVOKED, "openssl.x509_revoked");
#if OPENSSL_VERSION_NUMBER > 0x00909000L
  lua_pushstring(L, openssl_i2s_revoke_reason(revoked->reason));
  lua_pushinteger(L, revoked->reason);
  return 2;
#else
  /*
  {
    int crit = 0;
    void* reason = X509_REVOKED_get_ext_d2i(revoked, NID_crl_reason, &crit, NULL);
    lua_pushstring(L, openssl_i2s_revoke_reason(ASN1_ENUMERATED_get(reason)).lname);
    lua_pushinteger(revoked->reason);
    ASN1_ENUMERATED_free(reason);
  }*/
  return 0;
#endif
}

static time_t ASN1_GetTimeT(ASN1_TIME* time)
{
  struct tm t;
  const char* str = (const char*) time->data;
  size_t i = 0;

  memset(&t, 0, sizeof(t));

  if (time->type == V_ASN1_UTCTIME)  /* two digit year */
  {
    t.tm_year = (str[i++] - '0') * 10;
    t.tm_year += (str[i++] - '0');
    if (t.tm_year < 70)
      t.tm_year += 100;
  }
  else if (time->type == V_ASN1_GENERALIZEDTIME)    /* four digit year */
  {
    t.tm_year = (str[i++] - '0') * 1000;
    t.tm_year += (str[i++] - '0') * 100;
    t.tm_year += (str[i++] - '0') * 10;
    t.tm_year += (str[i++] - '0');
    t.tm_year -= 1900;
  }
  t.tm_mon = (str[i++] - '0') * 10;
  t.tm_mon += (str[i++] - '0') - 1; // -1 since January is 0 not 1.
  t.tm_mday = (str[i++] - '0') * 10;
  t.tm_mday += (str[i++] - '0');
  t.tm_hour = (str[i++] - '0') * 10;
  t.tm_hour += (str[i++] - '0');
  t.tm_min = (str[i++] - '0') * 10;
  t.tm_min += (str[i++] - '0');
  t.tm_sec  = (str[i++] - '0') * 10;
  t.tm_sec += (str[i++] - '0');

  /* Note: we did not adjust the time based on time zone information */
  return mktime(&t);
}

static int openssl_revoked_revocationDate(lua_State* L)
{
  X509_REVOKED* revoked = CHECK_OBJECT(1, X509_REVOKED, "openssl.x509_revoked");
  PUSH_ASN1_TIME(L, revoked->revocationDate);
  lua_pushinteger(L, (LUA_INTEGER)ASN1_GetTimeT(revoked->revocationDate));
  return 2;
}

static int openssl_revoked_serialNumber(lua_State* L)
{
  X509_REVOKED* revoked = CHECK_OBJECT(1, X509_REVOKED, "openssl.x509_revoked");
  BIGNUM *bn = ASN1_INTEGER_to_BN(revoked->serialNumber, NULL);
  PUSH_ASN1_INTEGER(L, revoked->serialNumber);
  PUSH_OBJECT(bn, "openssl.bn");
  return 2;
}

static int openssl_revoked_extensions(lua_State* L)
{
  X509_REVOKED* revoked = CHECK_OBJECT(1, X509_REVOKED, "openssl.x509_revoked");

  if (revoked->extensions)
  {
    openssl_sk_x509_extension_totable(L, revoked->extensions);
  }
  else
    lua_pushnil(L);
  return 1;
};

static int openssl_revoked_free(lua_State* L)
{
  X509_REVOKED* revoked = CHECK_OBJECT(1, X509_REVOKED, "openssl.x509_revoked");
  X509_REVOKED_free(revoked);
  return 1;
}

static luaL_Reg revoked_funcs[] =
{
  {"info",            openssl_revoked_info},
  {"reason",          openssl_revoked_reason},
  {"revocationDate",  openssl_revoked_revocationDate},
  {"serialNumber",    openssl_revoked_serialNumber},
  {"extensions",      openssl_revoked_extensions},

  {"__tostring",      auxiliar_tostring},
  {"__gc",            openssl_revoked_free  },

  {NULL,    NULL}
};

static int openssl_crl_reason(lua_State *L)
{
  int i;
  const BIT_STRING_BITNAME* bitname;
  lua_newtable(L);
  for (i = 0, bitname = &reason_flags[i]; bitname->bitnum != -1; i++, bitname = &reason_flags[i])
  {
    openssl_push_bit_string_bitname(L, bitname);
    lua_rawseti(L, -2, i + 1);
  }
  return 1;
}

static luaL_Reg R[] =
{
  {"new",       openssl_crl_new },
  {"read",      openssl_crl_read},
  {"reason",    openssl_crl_reason},
  {NULL,    NULL}
};

IMP_LUA_SK(X509_CRL, x509_crl)

int luaopen_x509_crl(lua_State *L)
{
  auxiliar_newclass(L, "openssl.x509_crl", crl_funcs);
  auxiliar_newclass(L, "openssl.x509_revoked", revoked_funcs);

  lua_newtable(L);
  luaL_setfuncs(L, R, 0);

  return 1;
}
