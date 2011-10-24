#include "openssl.h"

#ifdef OPENSSL_HAVE_TS

#include <openssl/ts.h>

ASN1_INTEGER *tsa_serial_cb(TS_RESP_CTX *ctx, void *data)
{
	//apr_file_t *serial_fp = data;
	ASN1_INTEGER *serial = NULL;
	ASN1_INTEGER * new_serial = NULL;

	/* Acquire an exclusive lock for the serial file. */
        
        /*********************************************************
         * Merge server id and serial number                     *
         * example : server_id = 0x0F , serial = 2               *
         *           result = 0x0F2                              *
         * Modification made by JOUVE <opentsa@jouve-hdi.com>    *
         *********************************************************/
	//new_serial=add_server_id(ctx,serial);

	return new_serial;
#if 0
	TS_RESP_CTX_set_status_info(ctx, TS_STATUS_REJECTION,
				    tsa_error());

	TS_RESP_CTX_set_status_info(ctx, TS_STATUS_REJECTION,
				    "could not generate serial number");

	TS_RESP_CTX_add_failure_info(ctx, TS_INFO_ADD_INFO_NOT_AVAILABLE);
	/* Clean up serial number if it was created. */
	ASN1_INTEGER_free(serial);
	return NULL;
#endif
	} 

/*  openssl.ts_resp_ctx_newsign(x509 signer, evp_pkey pkey, string def_policy, table options[, stack_of_x509 certs=nil] ) -> ts_resp_ctx {{{1
*/

LUA_FUNCTION(openssl_ts_resp_ctx_new){
	X509 *signer = CHECK_OBJECT(1,X509,"openssl.x509");
	EVP_PKEY *pkey = CHECK_OBJECT(2, EVP_PKEY, "openssl.evp_pkey");
	STACK_OF(X509) *certs = lua_isnoneornil(L,3) ? NULL : CHECK_OBJECT(3,STACK_OF(X509),"openssl.stack_of_x509");
	const char* def_policy = luaL_optstring(L, 4, "1.1.2");
	int options = lua_gettop(L) > 4 ? 5 : 0;

	ASN1_OBJECT *oid = NULL;
	char buffer[1024];

	TS_RESP_CTX* ctx = TS_RESP_CTX_new();

	//TS_RESP_CTX_set_serial_cb(ctx, tsa_serial_cb, serial_fp);

	if (!X509_check_private_key(signer, pkey))
	{
		lua_pushnil(L);
		lua_pushstring(L, "signer cert don't match with privatekey");
		return 2;
	}
	if(!TS_RESP_CTX_set_signer_cert(ctx, signer))
	{
		lua_pushnil(L);
		lua_pushstring(L, "signer cert don't support timestamp sign");
		return 2;
	}
	TS_RESP_CTX_set_signer_key(ctx, pkey);
	if(certs) TS_RESP_CTX_set_certs(ctx, certs);

	oid = OBJ_txt2obj(def_policy, 0);
	if(oid) {
		TS_RESP_CTX_set_def_policy(ctx, oid);
		OBJ_obj2txt(buffer, sizeof(buffer), oid, 0);
	}

	if (options==0)
	{
		lua_newtable(L);
		lua_pushvalue(L,5);
		options = 5;
	}
	luaL_checktype(L, options, LUA_TTABLE);

	lua_getfield(L,options,"digest");
	if(lua_isnil(L,-1)) {
		lua_pop(L,1);
		//set default digets
		lua_newtable(L);
		lua_pushstring(L,"md5");
		lua_rawseti(L,-2,1);
		lua_pushstring(L,"sha1");
		lua_rawseti(L,-2,2);
		//lua_setfield(L,-2,"digest");
	}

	if(lua_istable(L,-1))
	{
		int i;
		int len = lua_objlen(L, -1);
		for(i=1; i<=len; i++)
		{
			const char* p;
			const EVP_MD *md_obj;
			lua_rawgeti(L,-1,i);
			p = lua_tostring(L,-1);
			md_obj = EVP_get_digestbyname(p);
			TS_RESP_CTX_add_md(ctx, md_obj);
			lua_pop(L,1);
		}
	}
	lua_pop(L,1);
		
	lua_getfield(L,options,"policy");
	if(lua_isnil(L,-1))
	{
		lua_pop(L,1);
		//set default policy
		lua_newtable(L);
		lua_pushstring(L,"1.1.3");
		lua_rawseti(L,-2, 1);
		lua_pushstring(L,"1.1.4");
		lua_rawseti(L,-2, 2);
		//lua_setfield(L,-2,"policy");
	}

	if(lua_istable(L,-1))
	{
		int i;
		int len = lua_objlen(L, -1);
		for(i=1; i<=len; i++)
		{
			ASN1_OBJECT *oid = NULL;
			char buffer[1024];

			const char* p;
			lua_rawgeti(L,-1,i);
			p = lua_tostring(L,-1);

			oid = OBJ_txt2obj(p, 0);
			if(oid) {
				if(TS_RESP_CTX_add_policy(ctx, oid))
					OBJ_obj2txt(buffer, sizeof(buffer), oid, 0);
			}
			lua_pop(L,1);
		}
	}
	lua_pop(L,1);
	

	lua_getfield(L,options,"accuracy");
	if(lua_istable(L,-1))
	{
		int secs,millisecs,microsecs;
		lua_getfield(L,-1,"seconds");
		secs = lua_tointeger(L,-1);
		lua_pop(L,1);
		lua_getfield(L,-1,"millisecs");
		millisecs = lua_tointeger(L,-1);
		lua_pop(L,1);
		lua_getfield(L,-1,"microsecs");
		microsecs = lua_tointeger(L,-1);
		lua_pop(L,1);
		TS_RESP_CTX_set_accuracy(ctx, secs, millisecs, microsecs);
	}
	lua_pop(L,1);


	lua_getfield(L,-1,"precision");
	if (!lua_isnil(L,-1)) {
		int precision = lua_tointeger(L,-1);
		TS_RESP_CTX_set_clock_precision_digits(ctx, precision);
	}
	lua_pop(L,1);


	lua_getfield(L,-1,"ordering");
	if (!lua_isnil(L,-1)) {
		if(lua_toboolean(L,-1))
			TS_RESP_CTX_add_flags(ctx, TS_ORDERING);
	}
	lua_pop(L,1);

	lua_getfield(L,-1,"inc_name");
	if (!lua_isnil(L,-1)) {
		if(lua_toboolean(L,-1))
			TS_RESP_CTX_add_flags(ctx, TS_TSA_NAME);
	}
	lua_pop(L,1);

	lua_getfield(L,-1,"ess_ids");
	if (!lua_isnil(L,-1)) {
		if(lua_toboolean(L,-1))
			TS_RESP_CTX_add_flags(ctx, TS_ESS_CERT_ID_CHAIN);
	}
	lua_pop(L,1);
	
	PUSH_OBJECT(ctx,"openssl.ts_resp_ctx");
	return 1;
}


/*  ts_resp_ctx:ts_sign(string req|ts_req res ) -> ts_resp{{{1
*/
LUA_FUNCTION(openssl_ts_sign){
	TS_RESP_CTX *ctx = CHECK_OBJECT(1, TS_RESP_CTX,"openssl.ts_resp_ctx");
	BIO *bio = NULL;
	TS_RESP * resp;
	if(lua_isstring(L,2))
	{
		size_t l = 0;
		const char* buf = luaL_checklstring(L,2,&l);

		bio = BIO_new_mem_buf((void*)buf, l);
	}else{
		TS_REQ *req = CHECK_OBJECT(2,TS_REQ,"openssl.ts_req");
		bio = BIO_new(BIO_s_mem());
		i2d_TS_REQ_bio(bio,req);
	}

	resp  = TS_RESP_create_response(ctx, bio);
	if(resp){
		PUSH_OBJECT(resp,"openssl.ts_resp");
	}else
		lua_pushnil(L);

	return 1;
}
/* }}} */

LUA_FUNCTION(openssl_ts_resp_ctx_gc){
	TS_RESP_CTX *ctx = CHECK_OBJECT(1,TS_RESP_CTX,"openssl.ts_resp_ctx");
	TS_RESP_CTX_free(ctx);
	return 0;
}

LUA_FUNCTION(openssl_ts_resp_ctx_tostring){
	TS_RESP_CTX *ctx = CHECK_OBJECT(1,TS_RESP_CTX,"openssl.ts_resp_ctx");
	lua_pushfstring(L,"openssl.ts_resp_ctx:%p",ctx);
	return 1;
}

//////////////////////////////////////////////////////////////////////////


/*  openssl:ts_req_new(string req,string digest_alg[,table option={version=1,policy=,nonce=,cert_req=}] ) -> ts_req{{{1
*/

LUA_FUNCTION(openssl_ts_req_new){
	int l;
	const char* hash = luaL_checklstring(L, 1, &l);
	const char* hash_alg = luaL_checkstring(L, 2);
	int option = lua_gettop(L)>2 ? 3 : 0;
	TS_REQ *ts_req;

	if(option>0)
		luaL_checktype(L,option, LUA_TTABLE);

	ts_req = TS_REQ_new();
	if(ts_req!=NULL)
	{
		X509_ALGOR *algo = X509_ALGOR_new();
		TS_REQ_set_version(ts_req, 1);
		if(algo!=NULL) {
			algo->algorithm = OBJ_txt2obj(hash_alg, 0);
			algo->parameter = ASN1_TYPE_new();
			if (algo->algorithm && algo->parameter) {

				TS_MSG_IMPRINT *msg_imprint = TS_MSG_IMPRINT_new();
				algo->parameter->type = V_ASN1_NULL;

				if(msg_imprint!=NULL)
				{
					if(TS_MSG_IMPRINT_set_algo(msg_imprint, algo)) {
						if(TS_MSG_IMPRINT_set_msg(msg_imprint, (unsigned char*)hash, l))
						{
							if(TS_REQ_set_msg_imprint(ts_req, msg_imprint))
							{
								if(option>0) 
								{
									lua_getfield(L,option, "version");
									if(!lua_isnil(L,-1))
									{
										int version = luaL_optint(L, -1, 1);
										TS_REQ_set_version(ts_req, version);
									}
									lua_pop(L,1);
									
									lua_getfield(L,option, "policy");
									if(!lua_isnil(L,-1))
									{
										const char* policy = luaL_checkstring(L, -1);
										ASN1_OBJECT *policy_obj = OBJ_txt2obj(policy, 0);
										if(policy_obj) {
											TS_REQ_set_policy_id(ts_req, policy_obj);
										}
									}
									lua_pop(L,1);

									lua_getfield(L,option, "nonce");
									if(!lua_isnil(L,-1))
									{
										int nonce = lua_tointeger(L, -1);
										ASN1_INTEGER *asn_nonce = ASN1_INTEGER_new();
										ASN1_INTEGER_set(asn_nonce, nonce);
										TS_REQ_set_nonce(ts_req, asn_nonce);
									}
									lua_pop(L,1);

									lua_getfield(L,option, "cert_req");
									if(!lua_isnil(L,-1))
									{
										TS_REQ_set_cert_req(ts_req, lua_tointeger(L, -1));
									}
									lua_pop(L,1);
								}
								PUSH_OBJECT(ts_req,"openssl.ts_req");
								return 1;
							}
						}
					}
				}
				if(msg_imprint){
					TS_MSG_IMPRINT_free(msg_imprint);
					msg_imprint = NULL;
				}
			}

		}

		if(algo){
			X509_ALGOR_free(algo);
			algo = NULL;
		}
	}
	if(ts_req){
		TS_REQ_free(ts_req);
		ts_req = NULL;

	}
	return 0;
}

LUA_FUNCTION(openssl_ts_req_gc){
	TS_REQ *req = CHECK_OBJECT(1,TS_REQ,"openssl.ts_req");
	TS_REQ_free(req);
	return 0;
}

LUA_FUNCTION(openssl_ts_req_tostring){
	TS_REQ *req = CHECK_OBJECT(1,TS_REQ,"openssl.ts_req");
	lua_pushfstring(L,"openssl.ts_req:%p",req);
	return 1;
}

LUA_FUNCTION(openssl_ts_req_to_verify_ctx){
	TS_REQ *req = CHECK_OBJECT(1,TS_REQ,"openssl.ts_req");
	TS_VERIFY_CTX *ctx = TS_REQ_to_TS_VERIFY_CTX(req, NULL);
	PUSH_OBJECT(ctx,"openssl.ts_verify_ctx");
	return 1;
}



LUA_FUNCTION(openssl_ts_req_parse){
	TS_REQ *req = CHECK_OBJECT(1,TS_REQ,"openssl.ts_req");
	BIO* bio = BIO_new(BIO_s_mem());

	lua_newtable(L);
#if 0
	typedef struct TS_req_st
	{
		ASN1_INTEGER *version;
		TS_MSG_IMPRINT *msg_imprint;
		ASN1_OBJECT *policy_id;		/* OPTIONAL */
		ASN1_INTEGER *nonce;		/* OPTIONAL */
		ASN1_BOOLEAN cert_req;		/* DEFAULT FALSE */
		STACK_OF(X509_EXTENSION) *extensions;	/* [0] OPTIONAL */
	} TS_REQ;
#endif
	ADD_ASSOC_ASN1(ASN1_INTEGER, bio, req->version, "version");
	lua_pushboolean(L,req->cert_req);
	lua_setfield(L,-2, "cert_req");

	if(req->policy_id)
		ADD_ASSOC_ASN1(ASN1_OBJECT, bio, req->policy_id, "policy_id");
	if(req->nonce)
		ADD_ASSOC_ASN1(ASN1_INTEGER, bio, req->nonce, "nonce");

	lua_newtable(L);
	{
		ASN1_OCTET_STRING *os = req->msg_imprint->hashed_msg;
		lua_pushlstring(L,os->data, os->length);
		lua_setfield(L,-2,"content");

		PUSH_OBJECT(req->msg_imprint->hash_algo,"openssl.x509_algor");
		lua_setfield(L,-2,"hash_algo");
	}
	lua_setfield(L,-2,"msg_imprint");

	
	if(req->extensions)
	{
		PUSH_OBJECT(req->extensions,"openssl.stack_of_x509_extension");
		lua_setfield(L,-2,"extensions");
	}


	BIO_free(bio);

	return 1;
}

LUA_FUNCTION(openssl_ts_req_i2d){
	TS_REQ *req = CHECK_OBJECT(1, TS_REQ,"openssl.ts_req");

	BIO *bio = BIO_new(BIO_s_mem());

	if (i2d_TS_REQ_bio(bio, req)) {
		BUF_MEM *bptr = NULL;
		BIO_get_mem_ptr(bio, &bptr);
		lua_pushlstring(L,bptr->data,bptr->length);
		BIO_set_close(bio, BIO_NOCLOSE);
		BIO_free(bio);
		return 1;
	}
	BIO_free(bio);
	return 0;
}

LUA_FUNCTION(openssl_ts_req_d2i){
	size_t l;
	const char* buf = luaL_checklstring(L,1,&l);

	TS_REQ *req = d2i_TS_REQ(NULL,&buf,l);
	PUSH_OBJECT(req,"openssl.ts_req");
	return 1;
}
//////////////////////////////////////////////////////////////////////////

LUA_FUNCTION(openssl_ts_resp_gc){
	TS_RESP *res = CHECK_OBJECT(1,TS_RESP,"openssl.ts_resp");
	TS_RESP_free(res);
	return 0;
}

LUA_FUNCTION(openssl_ts_resp_i2d){
	TS_RESP *res = CHECK_OBJECT(1, TS_RESP,"openssl.ts_resp");

	BIO *bio = BIO_new(BIO_s_mem());

	if (i2d_TS_RESP_bio(bio, res)) {
		BUF_MEM *bptr = NULL;
		BIO_get_mem_ptr(bio, &bptr);
		lua_pushlstring(L,bptr->data,bptr->length);
		BIO_free(bio);
		return 1;
	}
	return 0;
}

LUA_FUNCTION(openssl_ts_resp_parse){
	TS_RESP *res = CHECK_OBJECT(1, TS_RESP,"openssl.ts_resp");

	BIO* bio = BIO_new(BIO_s_mem());
	lua_newtable(L);

	{
		lua_newtable(L);

		ADD_ASSOC_ASN1(ASN1_INTEGER,bio,res->status_info->status,"status");
		if(res->status_info->failure_info) {
			lua_pushlstring(L,res->status_info->failure_info->data,res->status_info->failure_info->length);
			lua_setfield(L,-2,"failure_info");
		}

		if(res->status_info->text)
		{
			STACK_OF(ASN1_UTF8STRING) * sk = res->status_info->text;
			int i=0, n=0;
			lua_newtable(L); 
			n = SKM_sk_num(ASN1_UTF8STRING, sk);
			for(i=0;i<n;i++) { 
					ASN1_UTF8STRING *x =  SKM_sk_value(ASN1_UTF8STRING, sk, i); 
					lua_pushlstring(L,x->data,x->length);
					lua_rawseti(L,-2, i+1); 
			} 
			lua_setfield(L,-2,"text");
		}

		lua_setfield(L, -2, "status_info");
	}


	if(res->token){
		PUSH_OBJECT(PKCS7_dup(res->token),"openssl.pkcs7");
		lua_setfield(L, -2, "token");
	}


	if(res->tst_info)
	{
		TS_TST_INFO *info = res->tst_info;
		lua_newtable(L);

		ADD_ASSOC_ASN1(ASN1_INTEGER, bio, info->version, "version");
		ADD_ASSOC_ASN1(ASN1_INTEGER, bio, info->serial, "serial");
		ADD_ASSOC_ASN1(ASN1_INTEGER, bio, info->nonce, "nonce");
		ADD_ASSOC_ASN1_TIME(bio,info->time,"time");
		lua_pushboolean(L,info->ordering);
		lua_setfield(L,-2,"ordering");

		ADD_ASSOC_ASN1(ASN1_OBJECT,bio,info->policy_id,"policy_id");

		if(info->msg_imprint)
		{
			ASN1_OCTET_STRING *os = info->msg_imprint->hashed_msg;
			lua_newtable(L);

			lua_pushlstring(L,os->data, os->length);
			lua_setfield(L,-2,"content");

			PUSH_OBJECT(info->msg_imprint->hash_algo,"openssl.x509_algor");
			lua_setfield(L,-2,"hash_algo");

			lua_setfield(L,-2,"msg_imprint");
		}

		if(info->accuracy)
		{
			lua_newtable(L);
			ADD_ASSOC_ASN1(ASN1_INTEGER, bio, info->accuracy->micros, "micros");
			ADD_ASSOC_ASN1(ASN1_INTEGER, bio, info->accuracy->millis, "millis");
			ADD_ASSOC_ASN1(ASN1_INTEGER, bio, info->accuracy->seconds, "seconds");
			lua_setfield(L,-2,"accuracy");
		}
		if(info->tsa)
			add_assoc_name_entry(L,"tsa",info->tsa->d.dirn,0);		


		if(info->extensions)
		{
			PUSH_OBJECT(info->extensions,"openssl.stack_of_x509_extension");
			lua_setfield(L,-2,"extensions");
		}
		
		lua_setfield(L,-2,"tst_info");
	}

	BIO_free(bio);

	return 1;
}

LUA_FUNCTION(openssl_ts_resp_d2i){
	size_t l;
	const char* buf = luaL_checklstring(L,1,&l);

	TS_RESP *res = d2i_TS_RESP(NULL,&buf,l);
	PUSH_OBJECT(res,"openssl.ts_resp");
	return 1;
}

LUA_FUNCTION(openssl_ts_resp_tst_info){
	TS_RESP *resp = CHECK_OBJECT(1,TS_RESP,"openssl.ts_resp");
	TS_TST_INFO *info = resp->tst_info;
	BIO *bio = BIO_new(BIO_s_mem());
	BUF_MEM *bio_buf;
	i2d_TS_TST_INFO_bio(bio,info);

	
	BIO_get_mem_ptr(bio, &bio_buf);
	lua_pushlstring(L,bio_buf->data, bio_buf->length);
	BIO_free(bio);
	return 1;
}

LUA_FUNCTION(openssl_ts_resp_tostring){
	TS_RESP *resp = CHECK_OBJECT(1,TS_RESP,"openssl.ts_resp");
	lua_pushfstring(L,"openssl.ts_resp:%p",resp);
	return 1;
}

//////////////////////////////////////////////////////////////////////////
X509_STORE* Stack2Store(STACK_OF(X509)* sk)
{
	X509_STORE *store = NULL;
	int i;

	/* Creating the X509_STORE object. */
	store = X509_STORE_new();
	/* Setting the callback for certificate chain verification. */
	X509_STORE_set_verify_cb(store, NULL);

	for(i=0; i<sk_X509_num(sk); i++)
	{
		X509_STORE_add_cert(store, X509_dup(sk_X509_value(sk,i)));
	};

	return store;
}

LUA_FUNCTION(openssl_ts_verify_ctx_new){
	TS_VERIFY_CTX *ctx = NULL;
	int top = lua_gettop(L);
	if(auxiliar_isclass(L,"openssl.ts_req",1))
	{
		TS_REQ* req = CHECK_OBJECT(1,TS_REQ,"openssl.ts_req");
		ctx = TS_REQ_to_TS_VERIFY_CTX(req, NULL);
	}else if(lua_istable(L,1))
	{
		
		lua_getfield(L,1,"source");
		if(!lua_isnil(L,-1))
		{
			int l;
			const char*data = luaL_checklstring(L,-1,&l);
			ctx = TS_VERIFY_CTX_new();
			ctx->flags = TS_VFY_VERSION | TS_VFY_SIGNER;
			ctx->data = BIO_new_mem_buf((void*)data,l);
		}
		lua_pop(L,1);

		lua_getfield(L,1,"digest");
		if(!lua_isnil(L,-1)){
			int l;
			const char*data = luaL_checklstring(L,-1,&l);
			ctx = TS_VERIFY_CTX_new();
			ctx->flags = TS_VFY_VERSION | TS_VFY_SIGNER;
			ctx->flags |= TS_VFY_IMPRINT;
			ctx->imprint_len = l;
			ctx->imprint = (unsigned char*)data;

		}
		lua_pop(L,1);

		lua_getfield(L,1,"request");
		if(!lua_isnil(L,-1)){
			if(auxiliar_isclass(L,"openssl.ts_verify_ctx",1))
			{
				TS_REQ* req = CHECK_OBJECT(1,TS_REQ,"openssl.ts_req");
				ctx = TS_REQ_to_TS_VERIFY_CTX(req, NULL);
			}else{
				int l;
				const char*data = luaL_checklstring(L,-1,&l);

				BIO* bio = BIO_new_mem_buf((void*)data,l);
				TS_REQ* req = d2i_TS_REQ_bio(bio, NULL);
				ctx = TS_REQ_to_TS_VERIFY_CTX(req, NULL);
			}
		}
		lua_pop(L,1);
	}
	if(ctx)
	{
		STACK_OF(X509) *cas = CHECK_OBJECT(2, STACK_OF(X509), "openssl.stack_of_x509");
		ctx->store = Stack2Store(cas);
		if(top>2)
		{
			ctx->certs = sk_X509_dup(CHECK_OBJECT(3,STACK_OF(X509), "openssl.stack_of_x509"));
		}
		
		ctx->flags |= TS_VFY_SIGNATURE;
		PUSH_OBJECT(ctx,"openssl.ts_verify_ctx");
	}else
		lua_pushnil(L);
	return 1;
}

LUA_FUNCTION(openssl_ts_verify_ctx_gc){
	TS_VERIFY_CTX *ctx = CHECK_OBJECT(1,TS_VERIFY_CTX,"openssl.ts_verify_ctx");
	TS_VERIFY_CTX_free(ctx);
	//void TS_VERIFY_CTX_cleanup(TS_VERIFY_CTX *ctx); 
	return 0;
}

LUA_FUNCTION(openssl_ts_verify_ctx_response){
	TS_VERIFY_CTX *ctx = CHECK_OBJECT(1,TS_VERIFY_CTX,"openssl.ts_verify_ctx");
	TS_RESP *response = CHECK_OBJECT(2,TS_RESP,"openssl.ts_resp");
	int ret = TS_RESP_verify_response(ctx, response);
	lua_pushboolean(L,ret);
	return 1;
}

LUA_FUNCTION(openssl_ts_verify_ctx_token){
	TS_VERIFY_CTX *ctx = CHECK_OBJECT(1,TS_VERIFY_CTX,"openssl.ts_verify_ctx");
	PKCS7 *token = CHECK_OBJECT(2,PKCS7,"openssl.pkcs7");
	int ret = TS_RESP_verify_token(ctx, token); 
	lua_pushboolean(L,ret);
	return 1;
}

LUA_FUNCTION(openssl_ts_verify_ctx_tostring){
	TS_RESP *resp = CHECK_OBJECT(1,TS_RESP,"openssl.ts_verify_ctx");
	lua_pushfstring(L,"openssl.ts_verify_ctx:%p",resp);
	return 1;
}

//////////////////////////////////////////////////////////////////////////
static luaL_Reg ts_req_funs[] = {
	{"__tostring", openssl_ts_req_tostring},
	{"parse", openssl_ts_req_parse},
	{"i2d", openssl_ts_req_i2d},
	{"__gc", openssl_ts_req_gc},
	{"to_verify_ctx", openssl_ts_req_to_verify_ctx},
	
	{ NULL, NULL }
};

static luaL_Reg ts_resp_funs[] = {
	{"__tostring", openssl_ts_resp_tostring},
	{"i2d", openssl_ts_resp_i2d},
	{"parse", openssl_ts_resp_parse},
	{"__gc", openssl_ts_resp_gc},
	{"tst_info", openssl_ts_resp_tst_info},
	
	{ NULL, NULL }
};

static luaL_Reg ts_resp_ctx_funs[] = {
	{"__tostring", openssl_ts_resp_ctx_tostring},
	{"__gc", openssl_ts_resp_ctx_gc},
	{"sign", openssl_ts_sign},
	
	{ NULL, NULL }
};

static luaL_Reg ts_verify_ctx_funs[] = {
	{"__tostring",	openssl_ts_verify_ctx_tostring},
	{"__gc",		openssl_ts_verify_ctx_gc},
	{"verify_response",		openssl_ts_verify_ctx_response},
	{"verify_token",		openssl_ts_verify_ctx_token},

	{ NULL, NULL }
};

int openssl_register_ts(lua_State* L)
{
	auxiliar_newclass(L,"openssl.ts_req",		ts_req_funs);
	auxiliar_newclass(L,"openssl.ts_resp",		ts_resp_funs);
	auxiliar_newclass(L,"openssl.ts_resp_ctx",	ts_resp_ctx_funs);
	auxiliar_newclass(L,"openssl.ts_verify_ctx",	ts_verify_ctx_funs);

	
	return 0;
}

#endif
