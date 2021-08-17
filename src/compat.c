#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#include "openssl.h"
#include "private.h"

#if OPENSSL_VERSION_NUMBER < 0x10100000L
int BIO_up_ref(BIO *b)
{
  CRYPTO_add(&b->references, 1, CRYPTO_LOCK_BIO);
  return 1;
}
int X509_up_ref(X509 *x)
{
  CRYPTO_add(&x->references, 1, CRYPTO_LOCK_X509);
  return 1;
}
int X509_STORE_up_ref(X509_STORE *s)
{
  CRYPTO_add(&s->references, 1, CRYPTO_LOCK_X509_STORE);
  return 1;
}
int EVP_PKEY_up_ref(EVP_PKEY *pkey)
{
  CRYPTO_add(&pkey->references, 1, CRYPTO_LOCK_EVP_PKEY);
  return 1;
}

int SSL_up_ref(SSL *ssl)
{
  CRYPTO_add(&ssl->references, 1, CRYPTO_LOCK_SSL);
  return 1;
}

int SSL_SESSION_up_ref(SSL_SESSION *sess)
{
  CRYPTO_add(&sess->references, 1, CRYPTO_LOCK_SSL_SESSION);
  return 1;
}

#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
#if !defined(LIBRESSL_VERSION_NUMBER)
int RSA_bits(const RSA *r)
{
  return (BN_num_bits(r->n));
}

void ECDSA_SIG_get0(const ECDSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps)
{
  *pr = sig->r;
  *ps = sig->s;
}
int ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s)
{
  if (r == NULL || s == NULL)
    return 0;
  BN_free(sig->r);
  BN_free(sig->s);
  sig->r = r;
  sig->s = s;
  return 1;
}

void RSA_get0_key(const RSA *r,
                  const BIGNUM **n, const BIGNUM **e, const BIGNUM **d)
{
  if (n != NULL)
    *n = r->n;
  if (e != NULL)
    *e = r->e;
  if (d != NULL)
    *d = r->d;
}

void RSA_get0_factors(const RSA *r, const BIGNUM **p, const BIGNUM **q)
{
  if (p != NULL)
    *p = r->p;
  if (q != NULL)
    *q = r->q;
}

void RSA_get0_crt_params(const RSA *r,
                         const BIGNUM **dmp1, const BIGNUM **dmq1,
                         const BIGNUM **iqmp)
{
  if (dmp1 != NULL)
    *dmp1 = r->dmp1;
  if (dmq1 != NULL)
    *dmq1 = r->dmq1;
  if (iqmp != NULL)
    *iqmp = r->iqmp;
}

HMAC_CTX *HMAC_CTX_new(void)
{
  HMAC_CTX *ctx = OPENSSL_malloc(sizeof(HMAC_CTX));

  if (ctx != NULL)
  {
    HMAC_CTX_init(ctx);
  }
  return ctx;
}

void HMAC_CTX_free(HMAC_CTX *ctx)
{
  if (ctx != NULL)
  {
    HMAC_CTX_cleanup(ctx);
    OPENSSL_free(ctx);
  }
}
#endif

#ifndef OPENSSL_NO_DSA
int DSA_bits(const DSA *dsa)
{
  return BN_num_bits(dsa->p);
}

#if !defined(LIBRESSL_VERSION_NUMBER)
DSA *EVP_PKEY_get0_DSA(EVP_PKEY *pkey)
{
  if (pkey->type != EVP_PKEY_DSA)
  {
    return NULL;
  }
  return pkey->pkey.dsa;
}

void DSA_get0_pqg(const DSA *d,
                  const BIGNUM **p, const BIGNUM **q, const BIGNUM **g)
{
  if (p != NULL)
    *p = d->p;
  if (q != NULL)
    *q = d->q;
  if (g != NULL)
    *g = d->g;
}

int DSA_set0_pqg(DSA *d, BIGNUM *p, BIGNUM *q, BIGNUM *g)
{
  /* If the fields p, q and g in d are NULL, the corresponding input
  * parameters MUST be non-NULL.
  */
  if ((d->p == NULL && p == NULL)
      || (d->q == NULL && q == NULL)
      || (d->g == NULL && g == NULL))
    return 0;

  if (p != NULL)
  {
    BN_free(d->p);
    d->p = p;
  }
  if (q != NULL)
  {
    BN_free(d->q);
    d->q = q;
  }
  if (g != NULL)
  {
    BN_free(d->g);
    d->g = g;
  }

  return 1;
}

void DSA_get0_key(const DSA *d,
                  const BIGNUM **pub_key, const BIGNUM **priv_key)
{
  if (pub_key != NULL)
    *pub_key = d->pub_key;
  if (priv_key != NULL)
    *priv_key = d->priv_key;
}

int DSA_set0_key(DSA *d, BIGNUM *pub_key, BIGNUM *priv_key)
{
  /* If the field pub_key in d is NULL, the corresponding input
  * parameters MUST be non-NULL.  The priv_key field may
  * be left NULL.
  */
  if (d->pub_key == NULL && pub_key == NULL)
    return 0;

  if (pub_key != NULL)
  {
    BN_free(d->pub_key);
    d->pub_key = pub_key;
  }
  if (priv_key != NULL)
  {
    BN_free(d->priv_key);
    d->priv_key = priv_key;
  }

  return 1;
}
#endif
#endif

#ifndef OPENSSL_NO_EC

#if !defined(LIBRESSL_VERSION_NUMBER)
EC_KEY *EVP_PKEY_get0_EC_KEY(EVP_PKEY *pkey)
{
  if (pkey->type != EVP_PKEY_EC)
  {
    return NULL;
  }
  return pkey->pkey.ec;
}
#endif
#endif

#ifndef OPENSSL_NO_DH
#if !defined(LIBRESSL_VERSION_NUMBER)
DH *EVP_PKEY_get0_DH(EVP_PKEY *pkey)
{
  if (pkey->type != EVP_PKEY_DH)
  {
    return NULL;
  }
  return pkey->pkey.dh;
}

int DH_bits(const DH *dh)
{
  return BN_num_bits(dh->p);
}

void DH_get0_key(const DH *dh, const BIGNUM **pub_key, const BIGNUM **priv_key)
{
  if (pub_key != NULL)
    *pub_key = dh->pub_key;
  if (priv_key != NULL)
    *priv_key = dh->priv_key;
}

int DH_set0_key(DH *dh, BIGNUM *pub_key, BIGNUM *priv_key)
{
  /* If the field pub_key in dh is NULL, the corresponding input
  * parameters MUST be non-NULL.  The priv_key field may
  * be left NULL.
  */
  if (dh->pub_key == NULL && pub_key == NULL)
    return 0;

  if (pub_key != NULL)
  {
    BN_free(dh->pub_key);
    dh->pub_key = pub_key;
  }
  if (priv_key != NULL)
  {
    BN_free(dh->priv_key);
    dh->priv_key = priv_key;
  }

  return 1;
}
void DH_get0_pqg(const DH *dh,
                 const BIGNUM **p, const BIGNUM **q, const BIGNUM **g)
{
  if (p != NULL)
    *p = dh->p;
  if (q != NULL)
    *q = dh->q;
  if (g != NULL)
    *g = dh->g;
}

int DH_set0_pqg(DH *dh, BIGNUM *p, BIGNUM *q, BIGNUM *g)
{
  /* If the fields p and g in d are NULL, the corresponding input
  * parameters MUST be non-NULL.  q may remain NULL.
  */
  if ((dh->p == NULL && p == NULL)
      || (dh->g == NULL && g == NULL))
    return 0;

  if (p != NULL)
  {
    BN_free(dh->p);
    dh->p = p;
  }
  if (q != NULL)
  {
    BN_free(dh->q);
    dh->q = q;
  }
  if (g != NULL)
  {
    BN_free(dh->g);
    dh->g = g;
  }

  if (q != NULL)
  {
    dh->length = BN_num_bits(q);
  }

  return 1;
}
#endif
#endif

#ifndef OPENSSL_NO_RSA
#if !defined(LIBRESSL_VERSION_NUMBER)
RSA *EVP_PKEY_get0_RSA(EVP_PKEY *pkey)
{
  if (pkey->type != EVP_PKEY_RSA)
  {
    return NULL;
  }
  return pkey->pkey.rsa;
}

int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d)
{
  /* If the fields n and e in r are NULL, the corresponding input
  * parameters MUST be non-NULL for n and e.  d may be
  * left NULL (in case only the public key is used).
  */
  if ((r->n == NULL && n == NULL)
      || (r->e == NULL && e == NULL))
    return 0;

  if (n != NULL)
  {
    BN_free(r->n);
    r->n = n;
  }
  if (e != NULL)
  {
    BN_free(r->e);
    r->e = e;
  }
  if (d != NULL)
  {
    BN_free(r->d);
    r->d = d;
  }

  return 1;
}

int RSA_set0_factors(RSA *r, BIGNUM *p, BIGNUM *q)
{
  /* If the fields p and q in r are NULL, the corresponding input
  * parameters MUST be non-NULL.
  */
  if ((r->p == NULL && p == NULL)
      || (r->q == NULL && q == NULL))
    return 0;

  if (p != NULL)
  {
    BN_free(r->p);
    r->p = p;
  }
  if (q != NULL)
  {
    BN_free(r->q);
    r->q = q;
  }

  return 1;
}

int RSA_set0_crt_params(RSA *r, BIGNUM *dmp1, BIGNUM *dmq1, BIGNUM *iqmp)
{
  /* If the fields dmp1, dmq1 and iqmp in r are NULL, the corresponding input
  * parameters MUST be non-NULL.
  */
  if ((r->dmp1 == NULL && dmp1 == NULL)
      || (r->dmq1 == NULL && dmq1 == NULL)
      || (r->iqmp == NULL && iqmp == NULL))
    return 0;

  if (dmp1 != NULL)
  {
    BN_free(r->dmp1);
    r->dmp1 = dmp1;
  }
  if (dmq1 != NULL)
  {
    BN_free(r->dmq1);
    r->dmq1 = dmq1;
  }
  if (iqmp != NULL)
  {
    BN_free(r->iqmp);
    r->iqmp = iqmp;
  }

  return 1;
}
#endif
#endif

#if !defined(LIBRESSL_VERSION_NUMBER)
EVP_MD_CTX *EVP_MD_CTX_new(void)
{
  return OPENSSL_malloc(sizeof(EVP_MD_CTX));
}

int EVP_MD_CTX_reset(EVP_MD_CTX *ctx)
{
  return EVP_MD_CTX_cleanup(ctx);
}

void EVP_MD_CTX_free(EVP_MD_CTX *ctx)
{
  EVP_MD_CTX_cleanup(ctx);
  OPENSSL_free(ctx);
}

void X509_REQ_get0_signature(const X509_REQ *req, const ASN1_BIT_STRING **psig,
                             const X509_ALGOR **palg)
{
  if (psig != NULL)
    *psig = req->signature;
  if (palg != NULL)
    *palg = req->sig_alg;
}
#endif

X509_PUBKEY *X509_REQ_get_X509_PUBKEY(X509_REQ *req)
{
  return req->req_info->pubkey;
}

int i2d_re_X509_REQ_tbs(X509_REQ *req, unsigned char **pp)
{
  req->req_info->enc.modified = 1;
  return i2d_X509_REQ_INFO(req->req_info, pp);
}

#if !defined(LIBRESSL_VERSION_NUMBER)
const ASN1_INTEGER *X509_get0_serialNumber(const X509 *a)
{
  return a->cert_info->serialNumber;
}

const STACK_OF(X509_EXTENSION) *X509_get0_extensions(const X509 *x)
{
  return x->cert_info->extensions;
}

const ASN1_TIME *X509_REVOKED_get0_revocationDate(const X509_REVOKED *x)
{
  return x->revocationDate;
}

const ASN1_INTEGER *X509_REVOKED_get0_serialNumber(const X509_REVOKED *x)
{
  return x->serialNumber;
}

const STACK_OF(X509_EXTENSION) *X509_REVOKED_get0_extensions(const X509_REVOKED *r)
{
  return r->extensions;
}

const STACK_OF(X509_EXTENSION) *X509_CRL_get0_extensions(const X509_CRL *crl)
{
  return crl->crl->extensions;
}

void X509_CRL_get0_signature(const X509_CRL *crl, const ASN1_BIT_STRING **psig,
                             const X509_ALGOR **palg)
{
  if (psig != NULL)
    *psig = crl->signature;
  if (palg != NULL)
    *palg = crl->sig_alg;
}

const ASN1_TIME *X509_CRL_get0_lastUpdate(const X509_CRL *crl)
{
  return crl->crl->lastUpdate;
}

const ASN1_TIME *X509_CRL_get0_nextUpdate(const X509_CRL *crl)
{
  return crl->crl->nextUpdate;
}
#endif

const ASN1_INTEGER *TS_STATUS_INFO_get0_status(const TS_STATUS_INFO *a)
{
  return a->status;
}
const STACK_OF(ASN1_UTF8STRING) *TS_STATUS_INFO_get0_text(const TS_STATUS_INFO *a)
{
  return a->text;
}

const ASN1_BIT_STRING *TS_STATUS_INFO_get0_failure_info(const TS_STATUS_INFO *a)
{
  return a->failure_info;
}

#if OPENSSL_VERSION_NUMBER < 0x10002000L || defined(LIBRESSL_VERSION_NUMBER)
int i2d_re_X509_tbs(X509 *x, unsigned char **pp)
{
  x->cert_info->enc.modified = 1;
  return i2d_X509_CINF(x->cert_info, pp);
}

#if !defined(LIBRESSL_VERSION_NUMBER)
void X509_get0_signature(CONSTIFY_X509_get0 ASN1_BIT_STRING **psig,
                         CONSTIFY_X509_get0 X509_ALGOR **palg,
                         const X509 *x)
{
  if (psig)
    *psig = x->signature;
  if (palg)
    *palg = x->sig_alg;
}

int X509_get_signature_nid(const X509 *x)
{
  return OBJ_obj2nid(x->sig_alg->algorithm);
}
#endif
#endif /* < 1.0.2 */


int TS_VERIFY_CTX_add_flags(TS_VERIFY_CTX *ctx, int f)
{
  ctx->flags |= f;
  return ctx->flags;
}

int TS_VERIFY_CTX_set_flags(TS_VERIFY_CTX *ctx, int f)
{
  ctx->flags = f;
  return ctx->flags;
}

BIO *TS_VERIFY_CTX_set_data(TS_VERIFY_CTX *ctx, BIO *b)
{
  ctx->data = b;
  return ctx->data;
}

X509_STORE *TS_VERIFY_CTX_set_store(TS_VERIFY_CTX *ctx, X509_STORE *s)
{
  ctx->store = s;
  return ctx->store;
}

STACK_OF(X509) *TS_VERIFY_CTS_set_certs(TS_VERIFY_CTX *ctx,
                                        STACK_OF(X509) *certs)
{
  ctx->certs = certs;
  return ctx->certs;
}

unsigned char *TS_VERIFY_CTX_set_imprint(TS_VERIFY_CTX *ctx,
    unsigned char *hexstr, long len)
{
  ctx->imprint = hexstr;
  ctx->imprint_len = len;
  return ctx->imprint;
}

#if !defined(LIBRESSL_VERSION_NUMBER)
const unsigned char *ASN1_STRING_get0_data(const ASN1_STRING *x)
{
  return x->data;
}
#endif

#endif /* < 1.1.0 */
