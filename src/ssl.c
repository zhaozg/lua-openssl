#include "openssl.h"
#include <openssl/ssl.h>

/****************************SSL CTX********************************/
int openssl_ssl_ctx_new(lua_State*L)
{
	const char* meth = luaL_optstring(L, 1, "TLSv1");
	SSL_METHOD* method = NULL;
	SSL_CTX* ctx;
	int ret = 0;
	if(strcmp(meth,"SSLv3")==0)
		method = SSLv3_method();		/* SSLv3 */
	else if(strcmp(meth,"SSLv3_server")==0)
		method = SSLv3_server_method();	/* SSLv3 */
	else if(strcmp(meth,"SSLv3_sclient")==0)
		method = SSLv3_client_method();	/* SSLv3 */
	else if(strcmp(meth,"SSLv23")==0)
		method = SSLv23_method();		/* SSLv3 but can rollback to v2 */
	else if(strcmp(meth,"SSLv23_server")==0)
		method = SSLv23_server_method();	/* SSLv3 but can rollback to v2 */
	else if(strcmp(meth,"SSLv23_client")==0)
		method = SSLv23_client_method();	/* SSLv3 but can rollback to v2 */
	else if(strcmp(meth, "TLSv1")==0)
		method = TLSv1_method();		/* TLSv1.0 */
	else if(strcmp(meth, "TLSv1_server")==0)
		method = TLSv1_server_method();	/* TLSv1.0 */
	else if(strcmp(meth,"TLSv1_client")==0)
		method = TLSv1_client_method();	/* TLSv1.0 */
	else if(strcmp(meth,"DTLSv1")==0)
		method = DTLSv1_method();		/* DTLSv1.0 */
	else if(strcmp(meth,"DTLSv1_server")==0)
		method = DTLSv1_server_method();	/* DTLSv1.0 */
	else if(strcmp(meth,"DTLSv1_client")==0)
		method = DTLSv1_client_method();	/* DTLSv1.0 */
#ifndef OPENSSL_NO_SSL2
	else if(strcmp(meth,"SSLv2")==0)
		method = SSLv2_method();		/* SSLv2 */
	else if(strcmp(meth,"SSLv2_server")==0)
		method = SSLv2_server_method();	/* SSLv2 */
	else if(strcmp(meth,"SSLv2_client")==0)
		method = SSLv2_client_method();
#endif
	else
		luaL_error(L,	"#1:%s not supported\n"
						"Maybe SSLv3 SSLv23 TLSv1 DTLSv1 [SSLv2], option followed by -client or -server\n",
						"default is SSLv3",
						meth);
	ctx = SSL_CTX_new(method);
	if(!ctx)
		luaL_error(L,	"#1:%s not supported\n"
			"Maybe SSLv3 SSLv23 TLSv1 DTLSv1 [SSLv2], option followed by -client or -server\n",
			"default is SSLv3",
			meth);

	PUSH_OBJECT(ctx,"openssl.ssl_ctx");
	return 1;
}

static int openssl_ssl_ctx_cipher_list(lua_State*L){
	SSL_CTX* ctx = CHECK_OBJECT(1, SSL_CTX, "openssl.ssl_ctx");
	const char*ciphers = luaL_checkstring(L, 2);
	int ret = SSL_CTX_set_cipher_list(ctx, ciphers);
	if(!ret){
		luaL_error(L, "#2 SSL_CTX_set_cipher_list(%s) failed", lua_tostring(L, 2));
	}
	return 0;
}

static int openssl_ssl_ctx_gc(lua_State*L)
{
	SSL_CTX* ctx = CHECK_OBJECT(1, SSL_CTX, "openssl.ssl_ctx");
	SSL_CTX_free(ctx);
	return 0;
}

static int openssl_ssl_ctx_timeout(lua_State*L)
{
	SSL_CTX* ctx = CHECK_OBJECT(1, SSL_CTX, "openssl.ssl_ctx");
	long t;
	if(!lua_isnoneornil(L, 2))
	{
		t = SSL_CTX_set_timeout(ctx, lua_tointeger(L, 2));
		lua_pushinteger(L, t);
		return 1;
	}
	t = SSL_CTX_get_timeout(ctx);
	lua_pushinteger(L, t);
	return 1;
}

static int openssl_ssl_ctx_options(lua_State*L)
{
	SSL_CTX* ctx = CHECK_OBJECT(1, SSL_CTX, "openssl.ssl_ctx");
	int options;
	int ret;
	if(!lua_isnoneornil(L, 2))
	{
		options = luaL_checkint(L,2);
		ret = SSL_CTX_set_options(ctx, options);
		lua_pushboolean(L, ret);
		return 1;
	}
	options = SSL_CTX_get_options(ctx);
	lua_pushinteger(L, options);
	return 1;
}


static int openssl_ssl_ctx_mode(lua_State*L)
{
	SSL_CTX* ctx = CHECK_OBJECT(1, SSL_CTX, "openssl.ssl_ctx");
	int mode;
	int ret;
	if(!lua_isnoneornil(L, 2))
	{
		int clear = lua_isnoneornil(L, 3)?1:auxiliar_checkboolean(L, 3);

		mode = luaL_checkint(L,2);
		if(clear!=0)
			ret = SSL_CTX_set_mode(ctx, mode);
		else
			ret = SSL_CTX_clear_mode(ctx, mode);

		lua_pushboolean(L, ret);
		return 1;
	}
	mode = SSL_CTX_get_mode(ctx);
	lua_pushinteger(L, mode);
	return 1;
}

static int openssl_ssl_ctx_cert_store(lua_State*L)
{
	SSL_CTX* ctx = CHECK_OBJECT(1, SSL_CTX, "openssl.ssl_ctx");
	X509_STORE* store;
	if(!lua_isnoneornil(L, 2)){
		store = CHECK_OBJECT(2, X509_STORE, "openssl.x509_store");
		SSL_CTX_set_cert_store(ctx, store);
		return 0;
	}

	store = SSL_CTX_get_cert_store(ctx);
	PUSH_OBJECT(store,"openssl.x509_store");
	return 1;
}

static int openssl_ssl_ctx_flush_sessions(lua_State*L){
	SSL_CTX* ctx = CHECK_OBJECT(1, SSL_CTX, "openssl.ssl_ctx");
	long tm = luaL_checkinteger(L, 2);
	SSL_CTX_flush_sessions(ctx, tm);
	return 0;
}

static int openssl_ssl_ctx_sessions(lua_State*L){
	SSL_CTX* ctx = CHECK_OBJECT(1, SSL_CTX, "openssl.ssl_ctx");
	if(lua_isstring(L, 2)){
		size_t s;
		const char* sid_ctx = luaL_checklstring(L, 2, &s);
		int ret = SSL_CTX_set_session_id_context(ctx, sid_ctx, s);
		lua_pushboolean(L, ret);
		return 1;
	}else{
		SSL_SESSION *s = CHECK_OBJECT(2, SSL_SESSION, "openssl.ssl_session");
		int add = 1;
		if(!lua_isnoneornil(L, 3))
			add = auxiliar_checkboolean(L, 3);
		if(add)
			add = SSL_CTX_add_session(ctx, s);
		else
			add = SSL_CTX_remove_session(ctx, s);

		lua_pushboolean(L, add);
		return 1;
	}
}

static int openssl_ssl_ctx_verify_mode(lua_State*L){
	SSL_CTX* ctx = CHECK_OBJECT(1, SSL_CTX, "openssl.ssl_ctx");
	int mode = SSL_CTX_get_verify_mode(ctx);
	lua_pushinteger(L, mode);
	return 1;
}


static int openssl_ssl_ctx_verify_depth(lua_State*L){
	SSL_CTX* ctx = CHECK_OBJECT(1, SSL_CTX, "openssl.ssl_ctx");
	int depth;
	if(!lua_isnoneornil(L, 2)){
		depth = luaL_checkint(L, 2);
		SSL_CTX_set_verify_depth(ctx, depth);
	}
	depth = SSL_CTX_get_verify_depth(ctx);
	lua_pushinteger(L, depth);
	return 1;
}


static int openssl_ssl_ctx_use_RSAPrivateKey(lua_State*L){
	SSL_CTX* ctx = CHECK_OBJECT(1, SSL_CTX, "openssl.ssl_ctx");
	int ret;
	if(lua_isstring(L,2)){
		size_t size;
		const char* d = luaL_checklstring(L, 2, &size);
		ret = SSL_CTX_use_RSAPrivateKey_ASN1(ctx, d, size);
	}else{
		RSA* rsa = CHECK_OBJECT(2, RSA, "openssl.rsa");
		ret = SSL_CTX_use_RSAPrivateKey(ctx, rsa);
	}
	lua_pushboolean(L, ret);
	return 1;
}

static int openssl_ssl_ctx_use_PrivateKey(lua_State*L){
	SSL_CTX* ctx = CHECK_OBJECT(1, SSL_CTX, "openssl.ssl_ctx");
	int ret;
	if(lua_isstring(L,2)){
		size_t size;
		const char* d = luaL_checklstring(L, 2, &size);
		int pk = luaL_checkint(L, 3);
		ret = SSL_CTX_use_PrivateKey_ASN1(pk, ctx, d, size);
	}else{
		EVP_PKEY* pkey = CHECK_OBJECT(2, EVP_PKEY, "openssl.evp_pkey");
		ret = SSL_CTX_use_PrivateKey(ctx, pkey);
	}
	lua_pushboolean(L, ret);
	return 1;
}

static int openssl_ssl_ctx_use_certificate(lua_State*L){
	SSL_CTX* ctx = CHECK_OBJECT(1, SSL_CTX, "openssl.ssl_ctx");
	int ret;
	if(lua_isstring(L,2)){
		size_t size;
		const char* d = luaL_checklstring(L, 2, &size);
		ret = SSL_CTX_use_certificate_ASN1(ctx, size, d);
	}else{
		X509* x = CHECK_OBJECT(2, X509, "openssl.x509");
		ret = SSL_CTX_use_certificate(ctx, x);
	}
	lua_pushboolean(L, ret);
	return 1;
}

static int openssl_ssl_ctx_check_private_key(lua_State*L){
	SSL_CTX* ctx = CHECK_OBJECT(1, SSL_CTX, "openssl.ssl_ctx");
	int ret = SSL_CTX_check_private_key(ctx);
	lua_pushboolean(L, ret);
	return 1;
}


static int openssl_ssl_ctx_set_purpose(lua_State*L){
	SSL_CTX* ctx = CHECK_OBJECT(1, SSL_CTX, "openssl.ssl_ctx");
	int purpose = luaL_checkint(L, 2);
	int ret = SSL_CTX_set_purpose(ctx, purpose);
	lua_pushboolean(L, ret);
	return 1;
}

static int openssl_ssl_ctx_set_trust(lua_State*L){
	SSL_CTX* ctx = CHECK_OBJECT(1, SSL_CTX, "openssl.ssl_ctx");
	int trust = luaL_checkint(L, 2);
	int ret = SSL_CTX_set_trust(ctx, trust);
	lua_pushboolean(L, ret);
	return 1;
}

static int openssl_ssl_ctx_quiet_shutdown(lua_State*L){
	SSL_CTX* s = CHECK_OBJECT(1, SSL_CTX, "openssl.ssl");
	if(lua_isnoneornil(L, 2)){
		int m = SSL_CTX_get_quiet_shutdown(s);
		lua_pushinteger(L, m);
		return 1;
	}else{
		int m = luaL_checkint(L, 2);
		SSL_CTX_set_quiet_shutdown(s, m);
		return 0;
	}
};

static int openssl_ssl_ctx_load_verify_locations(lua_State*L){
	SSL_CTX* ctx = CHECK_OBJECT(1, SSL_CTX, "openssl.ssl_ctx");
	const char* CAfile = luaL_optstring(L, 2, NULL);
	const char* CApath = luaL_optstring(L, 3, NULL);
	int ret = SSL_CTX_load_verify_locations(ctx, CAfile, CApath);
	lua_pushboolean(L, ret);
	return 1;
}

static int openssl_ssl_ctx_set_default_verify_paths(lua_State*L){
	SSL_CTX* ctx = CHECK_OBJECT(1, SSL_CTX, "openssl.ssl_ctx");
	int ret = SSL_CTX_set_default_verify_paths(ctx);
	lua_pushboolean(L, ret);
	return 1;
}

static int openssl_ssl_ctx_set_client_CA_list(lua_State*L){
	SSL_CTX* ctx = CHECK_OBJECT(1, SSL_CTX, "openssl.ssl_ctx");
	STACK_OF(X509_NAME) *name_list = CHECK_OBJECT(2,STACK_OF(X509_NAME),"openssl.stack_of_x509_name");
	SSL_CTX_set_client_CA_list(ctx, name_list);
	return 0;
}

static int openssl_ssl_ctx_add_client_CA(lua_State*L){
	SSL_CTX* ctx = CHECK_OBJECT(1, SSL_CTX, "openssl.ssl_ctx");
	X509* x = CHECK_OBJECT(2, X509, "openssl.x509");
	int ret = SSL_CTX_add_client_CA(ctx, x);
	lua_pushboolean(L, ret);
	return 1;
}

static int openssl_ssl_ctx_add_extra_chain_cert(lua_State*L){
	SSL_CTX* ctx = CHECK_OBJECT(1, SSL_CTX, "openssl.ssl_ctx");
	X509* x = CHECK_OBJECT(2, X509, "openssl.x509");
	int ret = SSL_CTX_add_extra_chain_cert(ctx, x);
	lua_pushboolean(L, ret);
	return 1;
}

/*
STACK_OF(X509_NAME) *SSL_dup_CA_list(STACK_OF(X509_NAME) *sk);
int (*SSL_CTX_get_verify_callback(const SSL_CTX *ctx))(int,X509_STORE_CTX *);
void SSL_CTX_set_verify(SSL_CTX *ctx,int mode,
	int (*callback)(int, X509_STORE_CTX *));
	void SSL_CTX_set_cert_verify_callback(SSL_CTX *ctx, int (*cb)(X509_STORE_CTX *,void *), void *arg);

	void SSL_CTX_set_default_passwd_cb(SSL_CTX *ctx, pem_password_cb *cb);
	void SSL_CTX_set_default_passwd_cb_userdata(SSL_CTX *ctx, void *u);
*/

static luaL_Reg ssl_ctx_funcs[] = {
	{"cert_store",		openssl_ssl_ctx_cert_store},
	{"cipher_list",		openssl_ssl_ctx_cipher_list},
	{"flush_sessions",	openssl_ssl_ctx_flush_sessions},
	{"timeout",			openssl_ssl_ctx_timeout},
	{"options",			openssl_ssl_ctx_options},
	{"session",			openssl_ssl_ctx_sessions},
	{"mode",			openssl_ssl_ctx_mode},
	
	{"add_client_CA",	openssl_ssl_ctx_add_client_CA},
	{"verify_mode",		openssl_ssl_ctx_verify_mode},
	{"verify_depth",	openssl_ssl_ctx_verify_depth},
	{"check_private_key",	openssl_ssl_ctx_check_private_key},
	{"use_PrivateKey",		openssl_ssl_ctx_use_PrivateKey},
	{"use_RSAPrivateKey",	openssl_ssl_ctx_use_RSAPrivateKey},
	{"use_certificate",		openssl_ssl_ctx_use_certificate},

	{"set_purpose",		openssl_ssl_ctx_set_purpose},
	{"set_trust",		openssl_ssl_ctx_set_trust},
	{"quiet_shutdown",	openssl_ssl_ctx_quiet_shutdown},
	{"load_verify_locations",	openssl_ssl_ctx_load_verify_locations},
	{"set_default_verify_paths",openssl_ssl_ctx_set_default_verify_paths},
	{"set_client_CA_list",		openssl_ssl_ctx_set_client_CA_list},
	{"add_extra_chain_cert",	openssl_ssl_ctx_add_extra_chain_cert},
	
	{"__gc",			openssl_ssl_ctx_gc},
	{"__tostring",		auxiliar_tostring},

	{NULL,			NULL},
};

/****************************SSL SESSION********************************/
/*
ECLARE_LHASH_OF(SSL_SESSION);
LHASH_OF(SSL_SESSION) *sessions;
int (*new_session_cb)(struct ssl_st *ssl,SSL_SESSION *sess);
void (*remove_session_cb)(struct ssl_ctx_st *ctx,SSL_SESSION *sess);
SSL_SESSION *(*get_session_cb)(struct ssl_st *ssl,
HASH_OF(SSL_SESSION) *SSL_CTX_sessions(SSL_CTX *ctx);
oid SSL_CTX_sess_set_new_cb(SSL_CTX *ctx, int (*new_session_cb)(struct ssl_st *ssl,SSL_SESSION *sess));
nt (*SSL_CTX_sess_get_new_cb(SSL_CTX *ctx))(struct ssl_st *ssl, SSL_SESSION *sess);
oid SSL_CTX_sess_set_remove_cb(SSL_CTX *ctx, void (*remove_session_cb)(struct ssl_ctx_st *ctx,SSL_SESSION *sess));
oid (*SSL_CTX_sess_get_remove_cb(SSL_CTX *ctx))(struct ssl_ctx_st *ctx, SSL_SESSION *sess);
oid SSL_CTX_sess_set_get_cb(SSL_CTX *ctx, SSL_SESSION *(*get_session_cb)(struct ssl_st *ssl, unsigned char *data,int len,int *copy));
SL_SESSION *(*SSL_CTX_sess_get_get_cb(SSL_CTX *ctx))(struct ssl_st *ssl, unsigned char *Data, int len, int *copy);
	/* These are the ones being used, the ones in SSL_SESSION are
	SSL_SESSION *session;
*/


int openssl_ssl_session_new(lua_State*L){
	SSL_SESSION *ss = SSL_SESSION_new();
	PUSH_OBJECT(ss,"openssl.ssl_session");
	return 1;
}

int openssl_ssl_session_read(lua_State*L){
	size_t size;
	const char* dat = luaL_checklstring(L, 1, &size);
	BIO *in = BIO_new_mem_buf((void*)dat, size);
	SSL_SESSION* ss = PEM_read_bio_SSL_SESSION(in,NULL,NULL,NULL);
	if(!ss){
		BIO_reset(in);
		ss = d2i_SSL_SESSION_bio(in,NULL);
	}
	BIO_free(in);
	if(ss){
	 	PUSH_OBJECT(ss,"openssl.ssl_session");
		return 1;
	}
	return 0;
}

static int openssl_ssl_session_time(lua_State*L){
	SSL_SESSION* session = CHECK_OBJECT(1, SSL_SESSION, "openssl.ssl_session");
	int time;
	if(!lua_isnoneornil(L, 2)){
		time = lua_tointeger(L, 2);
		time = SSL_SESSION_set_time(session, time);
		lua_pushinteger(L, time);
		return 1;
	}
	time = SSL_SESSION_get_time(session);
	lua_pushinteger(L, time);
	return 1;
}


static int openssl_ssl_session_timeout(lua_State*L){
	SSL_SESSION* session = CHECK_OBJECT(1, SSL_SESSION, "openssl.ssl_session");
	int time;
	if(!lua_isnoneornil(L, 2)){
		time = lua_tointeger(L, 2);
		time = SSL_SESSION_set_timeout(session, time);
		lua_pushinteger(L, time);
		return 1;
	}
	time = SSL_SESSION_get_timeout(session);
	lua_pushinteger(L, time);
	return 1;
}

static int openssl_ssl_session_gc(lua_State*L){
	SSL_SESSION* session = CHECK_OBJECT(1, SSL_SESSION, "openssl.ssl_session");
	SSL_SESSION_free(session);
	return 0;
}
#if OPENSSL_VERSION_NUMBER > 0x10000000L
static int openssl_ssl_session_peer(lua_State*L){
	SSL_SESSION* session = CHECK_OBJECT(1, SSL_SESSION, "openssl.ssl_session");
	X509 *x = SSL_SESSION_get0_peer(session);
	PUSH_OBJECT(x,"openssl.x509");
	return 1;
}
#endif
static int openssl_ssl_session_id(lua_State*L){
	SSL_SESSION* session = CHECK_OBJECT(1, SSL_SESSION, "openssl.ssl_session");
	
	if(lua_isnoneornil(L,2)){
		unsigned int len;
		const unsigned char* id = SSL_SESSION_get_id(session, &len);
		lua_pushlstring(L, id, len);
		return 1;
	}else{
#if OPENSSL_VERSION_NUMBER > 0x10000000L
		size_t len;
		const char* id = luaL_checklstring(L, 2, &len);
		int ret = SSL_SESSION_set1_id_context(session, id, len);
		lua_pushboolean(L, ret);
		return 1;
#else
		return 0;
#endif
	}
}
#if OPENSSL_VERSION_NUMBER > 0x10000000L
static int openssl_ssl_session_compress_id(lua_State*L){
	SSL_SESSION* session = CHECK_OBJECT(1, SSL_SESSION, "openssl.ssl_session");
	unsigned int id  = SSL_SESSION_get_compress_id(session);
	lua_pushinteger(L, id);
	return 1;
}
#endif
static int openssl_ssl_session_export(lua_State*L){
	SSL_SESSION* session = CHECK_OBJECT(1, SSL_SESSION, "openssl.ssl_session");
	int pem = lua_isnoneornil(L,2)?1:auxiliar_checkboolean(L,2);
	BIO* bio = BIO_new(BIO_s_mem());
	BUF_MEM *bio_buf;
	if(pem)
	{
		PEM_write_bio_SSL_SESSION(bio, session);
	}else{
		i2d_SSL_SESSION_bio(bio,session);
	}

	BIO_get_mem_ptr(bio, &bio_buf);
	lua_pushlstring(L,bio_buf->data, bio_buf->length);
	BIO_free(bio);
	return 1;
}

static luaL_Reg ssl_session_funcs[] = {
	{"id",				openssl_ssl_session_id},
	{"time",			openssl_ssl_session_time},
	{"timeout",			openssl_ssl_session_timeout},
#if OPENSSL_VERSION_NUMBER > 0x10000000L
	{"compress_id",		openssl_ssl_session_compress_id},
#endif
	{"export",			openssl_ssl_session_export},

	{"__gc",			openssl_ssl_session_gc},
	{"__tostring",		auxiliar_tostring},

	{NULL,			NULL},
};

#if 0
#define d2i_SSL_SESSION_bio(bp,s_id) ASN1_d2i_bio_of(SSL_SESSION,SSL_SESSION_new,d2i_SSL_SESSION,bp,s_id)
#define i2d_SSL_SESSION_bio(bp,s_id) ASN1_i2d_bio_of(SSL_SESSION,i2d_SSL_SESSION,bp,s_id)
DECLARE_PEM_rw(SSL_SESSION, SSL_SESSION)

int	SSL_SESSION_print_fp(FILE *fp,const SSL_SESSION *ses);
int	SSL_SESSION_print(BIO *fp,const SSL_SESSION *ses);

int	i2d_SSL_SESSION(SSL_SESSION *in,unsigned char **pp);

SSL_SESSION *d2i_SSL_SESSION(SSL_SESSION **a,const unsigned char **pp,
int SSL_SESSION_set_ex_data(SSL_SESSION *ss,int idx,void *data);
void *SSL_SESSION_get_ex_data(const SSL_SESSION *ss,int idx);
#endif

/***************************SSL**********************************/


static int openssl_ssl_gc(lua_State*L){
	SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
	SSL_free(s);
	return 0;
}

static int openssl_ssl_want(lua_State*L){
	SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
	lua_pushinteger(L, SSL_want(s));
	return 1;
}

static int openssl_ssl_clear(lua_State*L){
	SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
	lua_pushboolean(L, SSL_clear(s));
	return 1;
}


static int openssl_ssl_current_cipher(lua_State*L){
	SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
	const SSL_CIPHER* c = SSL_get_current_cipher(s);
	int bits;	
	luaL_Buffer B = {0};

	lua_newtable(L);

	lua_pushstring(L,SSL_CIPHER_get_name(c));
	lua_setfield(L, -2, "name");

	lua_pushstring(L,SSL_CIPHER_get_version(c));
	lua_setfield(L, -2, "version");
#if OPENSSL_VERSION_NUMBER > 0x10000000L
	lua_pushinteger(L, SSL_CIPHER_get_id(c));
	lua_setfield(L, -2, "id");
#endif
	if(SSL_CIPHER_get_bits(c,&bits)==1){
		lua_pushinteger(L, bits);
		lua_setfield(L, -2, "bits");
	};

	lua_pushstring(L, SSL_CIPHER_description(c, B.buffer, sizeof(B.buffer)));
	lua_setfield(L, -2, "description");

	return 1;
}

static int openssl_ssl_fd(lua_State*L){
	SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
	int fd,rfd,wfd;
	int ret = 1;
	fd =  luaL_optint(L, 2, -1);
	rfd = luaL_optint(L, 3, -1);
	wfd = luaL_optint(L, 4, -1);
	if(fd!=-1){
		fd = SSL_set_fd(s, fd);
	}else
		fd = SSL_get_fd(s);

	if(rfd!=-1){
		rfd = SSL_set_rfd(s, rfd);
	}else
		rfd = SSL_get_rfd(s);


	if(wfd!=-1){
		wfd = SSL_set_rfd(s, wfd);
	}else
		wfd = SSL_get_rfd(s);

	lua_pushinteger(L, fd);
	lua_pushinteger(L, rfd);
	lua_pushinteger(L, wfd);
	return 3;
}


static int openssl_ssl_bio(lua_State*L){
	SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
	BIO *rbio,*wbio;
	if(lua_gettop(L)>1){
		rbio = CHECK_OBJECT(2, BIO, "openssl.bio");
		wbio = CHECK_OBJECT(3, BIO, "openssl.bio");
		SSL_set_bio(s, rbio, wbio);
		return 0;
	}
	rbio = SSL_get_rbio(s);
	wbio = SSL_get_wbio(s);

	PUSH_OBJECT(rbio, "openssl.bio");
	PUSH_OBJECT(wbio, "openssl.bio");
	return 2;
}

static int openssl_ssl_pending(lua_State*L){
	SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
	lua_pushinteger(L, SSL_pending(s));
	return 1;
}

static int openssl_ssl_read_ahead(lua_State*L){
	SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
	if(lua_isnoneornil(L,2)){
		lua_pushinteger(L, SSL_get_read_ahead(s));
		return 1;
	}else{
		int yes = auxiliar_checkboolean(L, 2);
		SSL_set_read_ahead(s, yes);
	}
	return 0;
}

static int openssl_ssl_shared_ciphers(lua_State*L){
	SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
	luaL_Buffer buf = {0};
	lua_pushstring(L, SSL_get_shared_ciphers(s, buf.buffer, sizeof(buf.buffer)));
	return 1;
}

static int openssl_ssl_cipher_list(lua_State*L){
	SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
	if(lua_isstring(L, 2)){
		const char* list = lua_tostring(L, 2);
		int ret = SSL_set_cipher_list(s, list);
		lua_pushboolean(L, ret);
		return 1;
	}else{
		int n = luaL_optint(L, 2, 0);
		lua_pushstring(L, SSL_get_cipher_list(s, n));
		return 1;
	}
}

static int openssl_ssl_verify_mode(lua_State*L){
	SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
	lua_pushinteger(L, SSL_get_verify_mode(s));
	return 1;
}

static int openssl_ssl_verify_depth(lua_State*L){
	SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
	if(lua_isnoneornil(L, 2)){
		lua_pushinteger(L, SSL_get_verify_depth(s));
		return 1;
	}else{
		int depth = luaL_checkint(L, 2);
		SSL_set_verify_depth(s, depth);
		return 0;
	}
}

static int openssl_ssl_use_RSAPrivateKey(lua_State*L){
	SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
	int ret;
	if(lua_isstring(L,2)){
		size_t size;
		unsigned char* d = (unsigned char*)luaL_checklstring(L, 2, &size);
		ret = SSL_use_RSAPrivateKey_ASN1(s, d, size);
	}else{
		RSA* rsa = CHECK_OBJECT(2, RSA, "openssl.rsa");
		ret = SSL_use_RSAPrivateKey(s, rsa);
	}
	lua_pushboolean(L, ret);
	return 1;
}

static int openssl_ssl_use_PrivateKey(lua_State*L){
	SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
	int ret;
	if(lua_isstring(L,2)){
		size_t size;
		const char* d = luaL_checklstring(L, 2, &size);
		int pk = luaL_checkint(L, 3);
		ret = SSL_use_PrivateKey_ASN1(pk, s, d, size);
	}else{
		EVP_PKEY* pkey = CHECK_OBJECT(2, EVP_PKEY, "openssl.evp_pkey");
		ret = SSL_use_PrivateKey(s, pkey);
	}
	lua_pushboolean(L, ret);
	return 1;
}

static int openssl_ssl_use_certificate(lua_State*L){
	SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
	int ret;
	if(lua_isstring(L,2)){
		size_t size;
		const char* d = luaL_checklstring(L, 2, &size);
		ret = SSL_use_certificate_ASN1(s, d, (int)size);
	}else{
		X509* x = CHECK_OBJECT(2, X509, "openssl.x509");
		ret = SSL_use_certificate(s, x);
	}
	lua_pushboolean(L, ret);
	return 1;
}


static int openssl_ssl_check_private_key(lua_State*L){
	SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
	int ret = SSL_check_private_key(s);
	lua_pushboolean(L, ret);
	return 1;
}

static int openssl_ssl_state_string(lua_State*L){
	SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
	int l = lua_isnoneornil(L,2)?auxiliar_checkboolean(L,2):0;
	if(l){
		lua_pushstring(L, SSL_state_string_long(s));
	}else{
		lua_pushstring(L, SSL_state_string(s));
	}
	return 1;
}

static int openssl_ssl_rstate_string(lua_State*L){
	SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
	int l = lua_isnoneornil(L,2)?auxiliar_checkboolean(L,2):0;
	if(l){
		lua_pushstring(L, SSL_rstate_string_long(s));
	}else{
		lua_pushstring(L, SSL_rstate_string(s));
	}
	return 1;
}

static int openssl_ssl_peer_certificate(lua_State*L){
	SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
	X509* x = SSL_get_peer_certificate(s);
	PUSH_OBJECT(x,"openssl.x509");
	return 1;
}

static int openssl_ssl_peer_cert_chain(lua_State*L){
	SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
	STACK_OF(X509) *x = SSL_get_peer_cert_chain(s);
	PUSH_OBJECT(x,"openssl.stack_of_x509");
	return 1;
}

static int openssl_ssl_set_purpose(lua_State*L){
	SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
	int purpose = luaL_checkint(L, 2);
	int ret = SSL_set_purpose(s, purpose);
	lua_pushboolean(L, ret);
	return 1;
}

static int openssl_ssl_set_trust(lua_State*L){
	SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
	int trust = luaL_checkint(L, 2);
	int ret = SSL_set_trust(s, trust);
	lua_pushboolean(L, ret);
	return 1;
}

static int openssl_ssl_accept(lua_State*L){
	SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
	int ret = SSL_accept(s);
	lua_pushboolean(L, ret);
	return 1;
}

static int openssl_ssl_connect(lua_State*L){
	SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
	int ret = SSL_connect(s);
	lua_pushboolean(L, ret);
	return 1;
}

static int openssl_ssl_read(lua_State*L){
	SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
	int num = luaL_optint(L, 2, 4096);
	void* buf = malloc(num);
	int ret = SSL_read(s, buf, num);
	lua_pushinteger(L, ret);
	return 1;
}

static int openssl_ssl_peek(lua_State*L){
	SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
	int num = luaL_optint(L, 2, 4096);
	void* buf = malloc(num);
	int ret = SSL_peek(s, buf, num);
	lua_pushinteger(L, ret);
	return 1;
}

static int openssl_ssl_write(lua_State*L){
	SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
	size_t size;
	const char* buf = luaL_checklstring(L, 2, &size);
	int ret = SSL_write(s, buf, size);
	lua_pushinteger(L, ret);
	return 1;
}

static int openssl_ssl_ctrl(lua_State*L){
	SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
	/*
	int trust = luaL_checkint(L, 2);
	int ret = SSL_ctrl(s); (SSL *ssl,void *buf,int num);
	lua_pushboolean(L, ret);
	return 1;
	*/
	return 0;
}

static int openssl_ssl_error(lua_State*L){
	SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
	int ret = luaL_checkint(L,2);
	ret = SSL_get_error(s, ret);
	lua_pushinteger(L, ret);
	return 1;
}

static int openssl_ssl_version(lua_State*L){
	SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
	int iv = SSL_version(s);
	const char* v = SSL_get_version(s);
	lua_pushinteger(L, iv);
	lua_pushstring(L, v);
	return 1;
}

static int openssl_ssl_do_handshake(lua_State*L){
	SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
	int ret = SSL_do_handshake(s);
	lua_pushboolean(L, ret);
	return 1;
}

static int openssl_ssl_renegotiate(lua_State*L){
	SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
	int ret = SSL_renegotiate(s);
	lua_pushboolean(L, ret);
	return 1;
}
#if OPENSSL_VERSION_NUMBER > 0x10000000L
static int openssl_ssl_renegotiate_abbreviated(lua_State*L){
	SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
	int ret = SSL_renegotiate_abbreviated(s);
	lua_pushboolean(L, ret);
	return 1;
}
#endif
static int openssl_ssl_renegotiate_pending(lua_State*L){
	SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
	int ret = SSL_renegotiate_pending(s);
	lua_pushboolean(L, ret);
	return 1;
}

static int openssl_ssl_shutdown(lua_State*L){
	SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
	int ret = SSL_shutdown(s);
	lua_pushboolean(L, ret);
	return 1;
}

static int openssl_ssl_set_connect_state(lua_State*L){
	SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
	SSL_set_connect_state(s);
	return 0;
}

static int openssl_ssl_set_accept_state(lua_State*L){
	SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
	SSL_set_accept_state(s);
	return 0;
}

static int openssl_ssl_get_default_timeout(lua_State*L){
	SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
	long ret = SSL_get_default_timeout(s);
	lua_pushnumber(L, ret);
	return 1;
}

static int openssl_ssl_dup(lua_State*L){
	SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
	SSL* ss = SSL_dup(s);
	PUSH_OBJECT(ss,"openssl.ssl");
	return 1;
}

static int openssl_ssl_get_certificate(lua_State*L){
	SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
	X509 *x = SSL_get_certificate(s);
	PUSH_OBJECT(x,"openssl.x509");
	return 1;
}
#if OPENSSL_VERSION_NUMBER > 0x10000000L
static int openssl_ssl_cache_hit(lua_State*L){
	SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
	int ret = SSL_cache_hit(s);
	lua_pushboolean(L, ret==0);
	return 1;
}
static int openssl_ssl_set_debug(lua_State*L){
	SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
	int debug = luaL_checkint(L, 2);
	SSL_set_debug(s, debug);
	return 0;
}
#endif
static int openssl_ssl_ctx(lua_State*L){
	SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
	if(lua_isnoneornil(L, 2)){
		SSL_CTX *ctx = SSL_get_SSL_CTX(s);
		PUSH_OBJECT(ctx,"openssl.ssl_ctx");
	}else{
		SSL_CTX *ctx = CHECK_OBJECT(2, SSL_CTX, "openssl.ssl_ctx");
		ctx = SSL_set_SSL_CTX(s, ctx);
		PUSH_OBJECT(ctx,"openssl.ssl_ctx");
	}
	return 1;
}

static int openssl_ssl_verify_result(lua_State*L){
	SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
	if(lua_isnoneornil(L, 2)){
		long l = SSL_get_verify_result(s);
		lua_pushinteger(L, l);
		return 1;
	}else{
		long l = luaL_checkint(L, 2);
		SSL_set_verify_result(s, l);
		return 0;
	}
}

static int openssl_ssl_state(lua_State*L){
	SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
	if(lua_isnoneornil(L, 2)){
		int l = SSL_state(s);
		lua_pushinteger(L, l);
		return 1;
	}else{
#if OPENSSL_VERSION_NUMBER > 0x10000000L
		int l = luaL_checkint(L, 2);
		SSL_set_state(s, l);
#endif
		return 0;
	}
}

static int openssl_ssl_quiet_shutdown(lua_State*L){
	SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
	if(lua_isnoneornil(L, 2)){
		int m = SSL_get_quiet_shutdown(s);
		lua_pushinteger(L, m);
		return 1;
	}else{
		int m = luaL_checkint(L, 2);
		SSL_set_quiet_shutdown(s, m);
		return 0;
	}
};

static int openssl_ssl_get_shutdown(lua_State*L){
	SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
	int m = SSL_get_shutdown(s);
	lua_pushinteger(L, m);
	return 1;
};

static int openssl_ssl_set_shutdown(lua_State*L){
	SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
	int m = luaL_checkint(L, 2);
	SSL_set_shutdown(s, m);
	return 0;
};

static int openssl_ssl_add_client_CA(lua_State*L){
	SSL* s =  CHECK_OBJECT(1, SSL,  "openssl.ssl");
	X509* x = CHECK_OBJECT(2, X509, "openssl.x509");
	int ret = SSL_add_client_CA(s, x);
	lua_pushboolean(L, ret);
	return 1;
};

static int openssl_ssl_get_client_CA_list(lua_State*L){
	SSL* s =  CHECK_OBJECT(1, SSL,  "openssl.ssl");
	STACK_OF(X509_NAME)* ns = SSL_get_client_CA_list(s);
	PUSH_OBJECT(ns,"openssl.stack_of_x509_name");
	return 1;
};

static int openssl_ssl_alert_type_string(lua_State*L)
{
	SSL* s =  CHECK_OBJECT(1, SSL,  "openssl.ssl");
	int v = luaL_checkint(L, 2);
	int _long = lua_isnoneornil(L,3)?0:auxiliar_checkboolean(L, 3);
	const char* val;
	if(_long)
		val = SSL_alert_type_string_long(v);
	else
		val = SSL_alert_type_string(v);
	lua_pushstring(L, val);
	return 1;
}
static int openssl_ssl_alert_desc_string(lua_State*L)
{
	SSL* s =  CHECK_OBJECT(1, SSL,  "openssl.ssl");
	int v = luaL_checkint(L, 2);
	int _long = lua_isnoneornil(L,3)?0:auxiliar_checkboolean(L, 3);
	const char* val;
	if(_long)
		val = SSL_alert_desc_string_long(v);
	else
		val = SSL_alert_desc_string(v);
	lua_pushstring(L, val);
	return 1;
}


static int openssl_ssl_session(lua_State*L){
	SSL* s = CHECK_OBJECT(1, SSL, "openssl.ssl");
	SSL_SESSION*ss;

	if(lua_isnoneornil(L,2)){
		ss = SSL_get1_session(s);
		PUSH_OBJECT(ss,"openssl.ssl_session");
	}else{
		if(lua_isstring(L, 3))
		{
			size_t sz;
			const char* sid_ctx = luaL_checklstring(L, 2, &sz);
			int ret = SSL_set_session_id_context(s, sid_ctx, sz);
			lua_pushboolean(L, ret);
		}else{
			ss = CHECK_OBJECT(2, SSL_SESSION, "openssl.ssl_session");
			if(lua_isnoneornil(L, 3))
			{
				int ret = SSL_set_session(s, ss);
				lua_pushboolean(L, ret==0);
			}else {
#ifdef SSL_add_session
				int add = auxiliar_checkboolean(L, 3);
				if(add)
					add = SSL_add_session(s, ss);
				else
					add = SSL_remove_session(s, ss);
				lua_pushboolean(L, add);
#endif
			}
		}
	}
	return 1;
}

void SSL_set_info_callback(SSL *ssl, void (*cb)(const SSL *ssl,int type,int val));
void (*SSL_get_info_callback(const SSL *ssl))(const SSL *ssl,int type,int val);

static luaL_Reg ssl_funcs[] = {
	{"current_cipher",	openssl_ssl_current_cipher},
	{"read_ahead",		openssl_ssl_read_ahead},
	{"shared_ciphers",	openssl_ssl_shared_ciphers},
	{"cipher_list",		openssl_ssl_cipher_list},
	{"bio",				openssl_ssl_bio},
	{"fd",				openssl_ssl_fd},

	{"verify_mode",		openssl_ssl_verify_mode},
	{"verify_depth",	openssl_ssl_verify_depth},
	{"use_PrivateKey",		openssl_ssl_use_PrivateKey},
	{"use_RSAPrivateKey",	openssl_ssl_use_RSAPrivateKey},
	{"use_certificate",		openssl_ssl_use_certificate},
	{"check_private_key",	openssl_ssl_check_private_key},

	{"state_string",		openssl_ssl_state_string},
	{"rstate_string",		openssl_ssl_rstate_string},
	{"session",				openssl_ssl_session},
	{"peer_cert_chain",		openssl_ssl_peer_cert_chain},
	{"peer_certificate",	openssl_ssl_peer_certificate},
	{"get_certificate",		openssl_ssl_get_certificate},
	{"quiet_shutdown",		openssl_ssl_quiet_shutdown},
	{"alert_type",			openssl_ssl_alert_type_string},
	{"alert_desc",			openssl_ssl_alert_desc_string},

	{"dup",				openssl_ssl_dup},
	{"ctx",				openssl_ssl_ctx},
	
	{"clear",			openssl_ssl_clear},
	{"want",			openssl_ssl_want},
	{"pending",			openssl_ssl_pending},
	{"accept",			openssl_ssl_accept},
	{"connect",			openssl_ssl_connect},
	{"read",			openssl_ssl_read},
	{"peek",			openssl_ssl_peek},
	{"write",			openssl_ssl_write},
	{"ctrl",			openssl_ssl_ctrl},
	{"error",			openssl_ssl_error},
	{"version",			openssl_ssl_version},
	{"state",			openssl_ssl_state},
#if OPENSSL_VERSION_NUMBER > 0x10000000L	
	{"set_debug",		openssl_ssl_set_debug},
	{"cache_hit",		openssl_ssl_cache_hit},	
	{"renegotiate_abbreviated",	openssl_ssl_renegotiate_abbreviated},
#endif
	{"shutdown",			openssl_ssl_shutdown},
	{"set_shutdown",		openssl_ssl_set_shutdown},
	{"get_shutdown",		openssl_ssl_get_shutdown},
	{"version",				openssl_ssl_version},

	{"renegotiate_pending",		openssl_ssl_renegotiate_pending},
	{"renegotiate",				openssl_ssl_renegotiate},
	{"do_handshake",			openssl_ssl_do_handshake},

	{"set_connect_state",	openssl_ssl_set_connect_state},
	{"set_accept_state",	openssl_ssl_set_accept_state},
	{"get_default_timeout",	openssl_ssl_get_default_timeout},
	{"add_client_CA",		openssl_ssl_add_client_CA},
	{"get_client_CA_list",	openssl_ssl_get_client_CA_list},
	
	{"__gc",			openssl_ssl_gc},
	{"__tostring",		auxiliar_tostring},

	{NULL,			NULL},
};
/*
int	(*SSL_get_verify_callback(const SSL *s))(int,X509_STORE_CTX *);
void	SSL_set_verify(SSL *s, int mode,
int (*callback)(int ok,X509_STORE_CTX *ctx));
*/


int	SSL_use_RSAPrivateKey_file(SSL *ssl, const char *file, int type);
int	SSL_use_PrivateKey_file(SSL *ssl, const char *file, int type);
int	SSL_use_certificate_file(SSL *ssl, const char *file, int type);

int	SSL_CTX_use_RSAPrivateKey_file(SSL_CTX *ctx, const char *file, int type);
int	SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *file, int type);
int	SSL_CTX_use_certificate_file(SSL_CTX *ctx, const char *file, int type);
int	SSL_CTX_use_certificate_chain_file(SSL_CTX *ctx, const char *file); /* PEM type */
STACK_OF(X509_NAME) *SSL_load_client_CA_file(const char *file);
int	SSL_add_file_cert_subjects_to_stack(STACK_OF(X509_NAME) *stackCAs, const char *file);
int	SSL_add_dir_cert_subjects_to_stack(STACK_OF(X509_NAME) *stackCAs,  const char *dir);
int	SSL_CTX_set_generate_session_id(SSL_CTX *, GEN_SESSION_CB);
int	SSL_set_generate_session_id(SSL *, GEN_SESSION_CB);
int	SSL_has_matching_session_id(const SSL *ssl, const unsigned char *id, unsigned int id_len);
int	SSL_SESSION_print_fp(FILE *fp,const SSL_SESSION *ses);
int	SSL_SESSION_print(BIO *fp,const SSL_SESSION *ses);

int (*SSL_CTX_get_verify_callback(const SSL_CTX *ctx))(int,X509_STORE_CTX *);
void SSL_CTX_set_verify(SSL_CTX *ctx,int mode,	int (*callback)(int, X509_STORE_CTX *));
void SSL_CTX_set_cert_verify_callback(SSL_CTX *ctx, int (*cb)(X509_STORE_CTX *,void *), void *arg);

int openssl_register_ssl(lua_State* L){
	auxiliar_newclass(L,"openssl.ssl_ctx",		ssl_ctx_funcs);
	auxiliar_newclass(L,"openssl.ssl_session",	ssl_session_funcs);
	auxiliar_newclass(L,"openssl.ssl",			ssl_funcs);
	return 0;
}
