/*=========================================================================*\
* crl.c
* X509 certificate revoke routines for lua-openssl binding
*
* Author:  george zhao <zhaozg(at)gmail.com>
\*=========================================================================*/
#include "openssl.h"
#include "private.h"
#include <openssl/x509v3.h>

#define MYNAME		"crl"
#define MYVERSION	MYNAME " library for " LUA_VERSION " / Nov 2014 / "\
	"based on OpenSSL " SHLIB_VERSION_NUMBER
#define MYTYPE			"crl"

int		X509_CRL_cmp(const X509_CRL *a, const X509_CRL *b);
int		X509_CRL_match(const X509_CRL *a, const X509_CRL *b);

static const BIT_STRING_BITNAME reason_flags[] = {
	{0, "Unused", "unused"},
	{1, "Key Compromise", "keyCompromise"},
	{2, "CA Compromise", "CACompromise"},
	{3, "Affiliation Changed", "affiliationChanged"},
	{4, "Superseded", "superseded"},
	{5, "Cessation Of Operation", "cessationOfOperation"},
	{6, "Certificate Hold", "certificateHold"},
	{7, "Privilege Withdrawn", "privilegeWithdrawn"},
	{8, "AA Compromise", "AACompromise"},
	{-1, NULL, NULL}
};

static const int reason_num = sizeof(reason_flags)/sizeof(BIT_STRING_BITNAME) - 1;

int openssl_get_revoke_reason(const char*s){
	int reason = -1;
	int i;
	for (i=0; i<reason_num; i++)
	{
		if(strcasecmp(s,reason_flags[i].lname)==0 || strcasecmp(s,reason_flags[i].sname)==0)
		{
			reason = reason_flags[i].bitnum;
			break;
		}
	}
	return reason;
}

static int reason_get(lua_State*L, int reasonidx){
	int reason = 0;

	if(lua_isnumber(L, reasonidx))
	{
		reason = lua_tointeger(L, reasonidx);
	} else if(lua_isstring(L, reasonidx))
	{
		const char* s = lua_tostring(L, reasonidx);
		reason = openssl_get_revoke_reason(s);
	}else if(lua_isnoneornil(L, reasonidx))
		reason = 0;
	else
		luaL_argerror(L, reasonidx, "invalid revoke reason");

	luaL_argcheck(L, reason >=0 && reason < reason_num, reasonidx, "fail convert to revoke reason");

	return reason;
}

static X509_REVOKED *create_revoked(lua_State*L,const BIGNUM* bn, time_t t, int reason) {
    X509_REVOKED *revoked = X509_REVOKED_new();
    ASN1_TIME *tm = ASN1_TIME_new();
    ASN1_INTEGER *it =  BN_to_ASN1_INTEGER((BIGNUM*)bn,NULL);;

	ASN1_TIME_set(tm,t);
    
    X509_REVOKED_set_revocationDate(revoked, tm);
    X509_REVOKED_set_serialNumber(revoked, it);
#if OPENSSL_VERSION_NUMBER > 0x10000000L
    revoked->reason = reason;
#else
    {
        ASN1_ENUMERATED * e = ASN1_ENUMERATED_new();
		X509_EXTENSION * ext = X509_EXTENSION_new();

        ASN1_ENUMERATED_set(e, reason);

		X509_EXTENSION_set_data(ext,e);
        X509_EXTENSION_set_object(ext, OBJ_nid2obj(NID_crl_reason));
		X509_REVOKED_add_ext(revoked,ext,0);

        X509_EXTENSION_free(ext);
        ASN1_ENUMERATED_free(e);
    }
#endif
    ASN1_TIME_free(tm);
    ASN1_INTEGER_free(it);

    return revoked;
}

static LUA_FUNCTION(openssl_crl_add_revocked) {
	X509_CRL *crl = CHECK_OBJECT(1, X509_CRL, "openssl.x509_crl");
	BIGNUM* sn = BN_get(L, 2);
	time_t t = lua_tointeger(L, 3);
	int reason = reason_get(L, 4);

	int ret = 0;
	X509_REVOKED* revoked = create_revoked(L, sn, t, reason);
	ret = X509_CRL_add0_revoked(crl,revoked);
	lua_pushboolean(L,ret);
	BN_free(sn);
	return 1;
}

static LUA_FUNCTION(openssl_crl_new) {
    X509* x509 = lua_isnoneornil(L,1) ? NULL :CHECK_OBJECT(1, X509, "openssl.x509");
    time_t lastUpdate = luaL_optinteger(L,3,time(&lastUpdate));
    time_t nextUpdate = luaL_optinteger(L,4,lastUpdate+7*24*3600);
	long version = luaL_optint(L, 5, 1);

    X509_CRL * crl = NULL;
    ASN1_TIME *ltm,*ntm;

    if(!lua_isnoneornil(L,2))
		luaL_checktype(L, 2, LUA_TTABLE);

    crl = X509_CRL_new();
    X509_CRL_set_version(crl, version);
	if(x509)
		X509_CRL_set_issuer_name(crl, X509_get_subject_name(x509));

    ltm = ASN1_TIME_new();
    ntm = ASN1_TIME_new();
	ASN1_TIME_set(ltm, lastUpdate);
    ASN1_TIME_set(ntm, nextUpdate);
    X509_CRL_set_lastUpdate(crl, ltm);
    X509_CRL_set_nextUpdate(crl, ntm);
    
	if(lua_istable(L,2) && lua_objlen(L, 2)>0)
	{
		int i;
		int n = lua_objlen(L, 2);

		for (i=1; i<=n; i++)
		{
			lua_rawgeti(L, 2, i);
			if(lua_istable(L, -1)) {
				X509_REVOKED *revoked;

				lua_getfield(L, -1, "reason");
				lua_getfield(L, -2, "time");
				lua_getfield(L, -3, "sn");

				revoked = create_revoked(L, BN_get(L, -1), lua_tointeger(L, -2), reason_get(L, -3));
				if(revoked) {
					X509_CRL_add0_revoked(crl,revoked);
				}
				lua_pop(L, 3);
			}
			lua_pop(L,1);
		}
	}
		

	ASN1_TIME_free(ltm);
    ASN1_TIME_free(ntm);
    PUSH_OBJECT(crl,"openssl.x509_crl");
    return 1;
}

static LUA_FUNCTION(openssl_crl_read) {
	BIO * in = load_bio_object(L, 1);
	int fmt = luaL_checkoption(L, 2, "auto", format);

    X509_CRL *crl = NULL;
	
	if(fmt==FORMAT_AUTO || fmt==FORMAT_PEM){
		crl = PEM_read_bio_X509_CRL(in, NULL,NULL,NULL);
		BIO_reset(in);
	}
	if((fmt==FORMAT_AUTO && crl==NULL) || fmt==FORMAT_DER) {
		crl = d2i_X509_CRL_bio(in,NULL);
        BIO_reset(in);
    }
    BIO_free(in);

    if(crl)
    {
        PUSH_OBJECT(crl,"openssl.x509_crl");
        return 1;
    }
    return 0;
}

static LUA_FUNCTION(openssl_crl_set_version) {
	X509_CRL *crl = CHECK_OBJECT(1, X509_CRL, "openssl.x509_crl");
	long version = luaL_optinteger(L,2, 0);
	int ret = X509_CRL_set_version(crl, version);
	lua_pushboolean(L,ret);
	return 1;
}

static LUA_FUNCTION(openssl_crl_set_issuer) {
	X509_CRL *crl = CHECK_OBJECT(1, X509_CRL, "openssl.x509_crl");
	X509* x509 = CHECK_OBJECT(2, X509, "openssl.x509");

	int ret = X509_CRL_set_issuer_name(crl, x509->cert_info->issuer);

	lua_pushboolean(L,ret);
	return 1;
}

static LUA_FUNCTION(openssl_crl_set_updatetime) {
	X509_CRL *crl = CHECK_OBJECT(1, X509_CRL, "openssl.x509_crl");
	ASN1_TIME *ltm, *ntm;
	int ret = 0;

	time_t last, next;
	time(&last);
	last = luaL_optinteger(L, 2, (lua_Integer)last);
	next = luaL_optinteger(L, 3, (lua_Integer)last+7*24*3600);

	ltm = ASN1_TIME_new();
	ASN1_TIME_set(ltm, last);
	ntm = ASN1_TIME_new();
	ASN1_TIME_set(ntm, next);

	ret = X509_CRL_set_lastUpdate(crl, ltm);
	if(ret==1)
		ret = X509_CRL_set_nextUpdate(crl, ntm);

	lua_pushboolean(L,ret);
	return 1;
}

static LUA_FUNCTION(openssl_crl_sort) {
	X509_CRL *crl = CHECK_OBJECT(1, X509_CRL, "openssl.x509_crl");
	int ret = X509_CRL_sort(crl);
	lua_pushboolean(L,ret);
	return 1;
}

static LUA_FUNCTION(openssl_crl_verify) {
	X509_CRL *crl = CHECK_OBJECT(1, X509_CRL, "openssl.x509_crl");
	X509* cacert = CHECK_OBJECT(2, X509, "openssl.x509");


	int ret = X509_CRL_verify(crl, cacert->cert_info->key->pkey);
	lua_pushboolean(L,ret);
	return 1;
}

LUA_FUNCTION(openssl_crl_sign) {
	X509_CRL *crl = CHECK_OBJECT(1, X509_CRL, "openssl.x509_crl");
	EVP_PKEY *key = CHECK_OBJECT(2, EVP_PKEY, "openssl.evp_pkey");
	const EVP_MD *md = lua_isnoneornil(L,3) 
		? EVP_get_digestbyname("sha1WithRSAEncryption") : get_digest(L, 3);

	int ret = 0;

	luaL_argcheck(L, md, 3, "must be openssl.evp_digest or a valid digest alg name");

	X509_CRL_sort(crl);
	ret = X509_CRL_sign(crl, key, md);
	lua_pushboolean(L,ret);
	return 1;
}

static LUA_FUNCTION(openssl_crl_parse) {
    X509_CRL *crl = CHECK_OBJECT(1, X509_CRL, "openssl.x509_crl");
    int useshortnames = lua_isnoneornil(L,2) ? 0 : lua_toboolean(L,2);
	int n,i;

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

        if (X509_CRL_digest(crl,digest,md,(unsigned int*)&n))
        {
			lua_newtable(L);
			AUXILIAR_SET(L, -1, "alg", OBJ_nid2sn(EVP_MD_type(digest)), string);
			AUXILIAR_SETLSTR(L,-1,"hash",(const char*)md,n);

			lua_setfield(L,-2,"fingerprint");
        }
    }

    add_assoc_name_entry(L, "issuer", 	X509_CRL_get_issuer(crl), useshortnames);

	AUXILIAR_SETOBJECT(L,X509_CRL_get_lastUpdate(crl),"openssl.asn1_time",-1,"lastUpdate");
	AUXILIAR_SETOBJECT(L,X509_CRL_get_nextUpdate(crl),"openssl.asn1_time",-1, "nextUpdate");
	AUXILIAR_SETOBJECT(L,crl->crl->sig_alg,"openssl.x509_algor",-1, "sig_alg");

	AUXILIAR_SETOBJECT(L, X509_CRL_get_ext_d2i(crl, NID_crl_number,NULL, NULL),
		"openssl.asn1_string",-1,"crl_number");

    add_assoc_x509_extension(L, "extensions", crl->crl->extensions);

    n = sk_X509_REVOKED_num(crl->crl->revoked);
    lua_newtable(L);
	for (i=0; i<n; i++)
	{
		X509_REVOKED *revoked = sk_X509_REVOKED_value(crl->crl->revoked,i);
		lua_newtable(L);

#if OPENSSL_VERSION_NUMBER > 0x10000000L
		AUXILIAR_SET(L, -1, "CRLReason", reason_flags[revoked->reason].lname, string);
#else
		{
			int crit = 0;
			void* reason = X509_REVOKED_get_ext_d2i(revoked, NID_crl_reason,&crit, NULL);

			AUXILIAR_SET(L, -1, "CRLReason", reason_flags[ASN1_ENUMERATED_get(reason)].lname, string);
			ASN1_ENUMERATED_free(reason);
		}
#endif
		AUXILIAR_SETOBJECT(L, revoked->serialNumber, "openssl.asn1_string", -1, "serialNumber");
		AUXILIAR_SETOBJECT(L, revoked->revocationDate, "openssl.asn1_string", -1, "revocationDate");

		add_assoc_x509_extension(L, "extensions", revoked->extensions);

		lua_rawseti(L, -2, i+1);
	}

	lua_setfield(L,-2, "revoked");
    return 1;
}

static LUA_FUNCTION(openssl_crl_free) {
    X509_CRL *crl = CHECK_OBJECT(1, X509_CRL, "openssl.x509_crl");
    X509_CRL_free(crl);
    return 0;
}

static LUA_FUNCTION(openssl_crl_export)
{
	X509_CRL * crl = CHECK_OBJECT(1,X509_CRL,"openssl.x509_crl");
	int fmt = luaL_checkoption(L, 2, "pem", format); 
	int notext = lua_isnoneornil(L, 3) ? 1 : lua_toboolean(L,3);
	BIO *out  = NULL;

	luaL_argcheck(L, fmt==FORMAT_DER || fmt==FORMAT_PEM, 2,
		"only accept der or pem");

	out	 = BIO_new(BIO_s_mem());
	if (fmt==FORMAT_PEM) {
		if (!notext) {
			X509_CRL_print(out, crl);
		}

		if (PEM_write_bio_X509_CRL(out, crl))  {
			BUF_MEM *bio_buf;
			BIO_get_mem_ptr(out, &bio_buf);
			lua_pushlstring(L,bio_buf->data, bio_buf->length);
		} else
			lua_pushnil(L);
	} else
	{
		if(i2d_X509_CRL_bio(out, crl)) {
			BUF_MEM *bio_buf;
			BIO_get_mem_ptr(out, &bio_buf);
			lua_pushlstring(L,bio_buf->data, bio_buf->length);
		} else
			lua_pushnil(L);
	}

	BIO_free(out);
	return 1;
}

static luaL_Reg crl_funcs[] = {
    {"sort",	openssl_crl_sort},
    {"verify",	openssl_crl_verify},
    {"sign",	openssl_crl_sign},
	{"export",	openssl_crl_export},

    {"set_version",		openssl_crl_set_version		},
    {"set_update_time",	openssl_crl_set_updatetime	},
    {"set_issuer",		openssl_crl_set_issuer		},
    {"add",		openssl_crl_add_revocked	},

    {"parse",			openssl_crl_parse			},


    {"__tostring",		auxiliar_tostring	},
    {"__gc",			openssl_crl_free	},

    {NULL,	NULL}
};

static luaL_reg R[] = {
	{"new",				openssl_crl_new	},
	{"read",			openssl_crl_read},
	{NULL,		NULL}
};

LUALIB_API int luaopen_crl(lua_State *L)
{
	auxiliar_newclass(L,"openssl.x509_crl", crl_funcs);

	luaL_newmetatable(L,MYTYPE);
	lua_setglobal(L,MYNAME);
	luaL_register(L,MYNAME,R);
	lua_pushvalue(L, -1);
	lua_setmetatable(L, -2);
	lua_pushliteral(L,"version");			/** version */
	lua_pushliteral(L,MYVERSION);
	lua_settable(L,-3);
	lua_pushliteral(L,"__index");
	lua_pushvalue(L,-2);
	lua_settable(L,-3);
	return 1;
}
