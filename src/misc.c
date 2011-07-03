#include "openssl.h"

/* {{{ check_cert */
int check_cert(X509_STORE *ctx, X509 *x, STACK_OF(X509) *untrustedchain, int purpose)
{
	int ret=0;
	X509_STORE_CTX *csc;

	csc = X509_STORE_CTX_new();
	if (csc == NULL) {
		printf("memory allocation -1");
		return 0;
	}
	X509_STORE_CTX_init(csc, ctx, x, untrustedchain);
	if(purpose >= 0) {
		X509_STORE_CTX_set_purpose(csc, purpose);
	}
	ret = X509_verify_cert(csc);
	X509_STORE_CTX_free(csc);

	return ret;
}
/* }}} */



/* {{{ setup_verify
 * calist is an array containing file and directory names.  create a
 * certificate store and add those certs to it for use in verification.
*/

X509_STORE * setup_verify(STACK_OF(X509)* calist)
{
	X509_STORE *store;
	X509_LOOKUP * dir_lookup, * file_lookup;
	int ndirs = 0, nfiles = 0;
	X509 *x;
	int i;

	store = X509_STORE_new();

	if (store == NULL) {
		return NULL;
	}



	for (i=0; i<sk_X509_num(calist); i++)
	{
		x=sk_X509_value(calist,i);
		X509_STORE_add_cert(store,x);
	}

	if (nfiles == 0) {
		file_lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
		if (file_lookup) {
			X509_LOOKUP_load_file(file_lookup, NULL, X509_FILETYPE_DEFAULT);
		}
	}
	if (ndirs == 0) {
		dir_lookup = X509_STORE_add_lookup(store, X509_LOOKUP_hash_dir());
		if (dir_lookup) {
			X509_LOOKUP_add_dir(dir_lookup, NULL, X509_FILETYPE_DEFAULT);
		}
	}
	return store;
}
/* }}} */


void add_index_bool(lua_State* L, int i, int b){
	lua_pushboolean(L,b);
	lua_rawseti(L,-2,i);
}

void add_assoc_int(lua_State* L, const char* name, int b){
	lua_pushinteger(L,b);
	lua_setfield(L,-2,name);
}

void add_assoc_string(lua_State *L, const char*name, const char*val, int flag) {
	lua_pushstring(L,val);
	lua_setfield(L,-2,name);
}

void add_assoc_name_entry(lua_State*L, char * key, X509_NAME * name, int shortname) /* {{{ */
{
	int i, j = -1, last = -1, obj_cnt = 0;
	char *sname;
	int nid;
	X509_NAME_ENTRY * ne;
	ASN1_STRING * str = NULL;
	ASN1_OBJECT * obj;

	lua_newtable(L);
	
	for (i = 0; i < X509_NAME_entry_count(name); i++) {
		unsigned char *to_add;
		int to_add_len;
		int tindex = 0;
		int utf8 = 0;

		ne  = X509_NAME_get_entry(name, i);
		obj = X509_NAME_ENTRY_get_object(ne);
		nid = OBJ_obj2nid(obj);
		obj_cnt = 0;

		if (shortname) {
			sname = (char *) OBJ_nid2sn(nid);
		} else {
			sname = (char *) OBJ_nid2ln(nid);
		}

		lua_newtable(L);

		last = -1;
		for (;;) {
			j = X509_NAME_get_index_by_OBJ(name, obj, last);
			if (j < 0) {
				if (last != -1) break;
			} else {
				obj_cnt++;
				ne  = X509_NAME_get_entry(name, j);
				str = X509_NAME_ENTRY_get_data(ne);
				if (ASN1_STRING_type(str) != V_ASN1_UTF8STRING) {
					to_add_len = ASN1_STRING_to_UTF8(&to_add, str);
					if (to_add_len != -1) {
						tindex++;
						utf8 = 1;
						lua_pushstring(L,"UTF8:");
						lua_pushlstring(L,(char *)to_add, to_add_len);
						lua_concat(L,2);
						lua_rawseti(L,-2,tindex);
					}
				} else {
					utf8 = 0;
					to_add = ASN1_STRING_data(str);
					to_add_len = ASN1_STRING_length(str);
					tindex++;
					lua_pushlstring(L,(char *)to_add, to_add_len);
					lua_rawseti(L,-2,tindex);
				}
			}
			last = j;
		}
		i = last;
		
		if (obj_cnt > 1) {
			lua_setfield(L,-2,sname);
		} else {
			lua_pop(L,1);
			if (obj_cnt && str && to_add_len > -1) {
				if(utf8){
					lua_pushstring(L,"UTF8:");
					lua_pushlstring(L,(char *)to_add, to_add_len);
					lua_concat(L,2);
				}else
					lua_pushlstring(L,(char *)to_add, to_add_len);
				lua_setfield(L,-2, sname);
			}
		}
	}

	if (key != NULL) {
		lua_setfield(L,-2,key);
	}
}

void add_assoc_asn1_string(lua_State*L, char * key, ASN1_STRING * str) /* {{{ */
{
	lua_pushlstring(L,(char *)str->data, str->length);
	lua_setfield(L,-2,key);
}


time_t asn1_time_to_time_t(ASN1_UTCTIME * timestr) /* {{{ */
{
/*
	This is how the time string is formatted:

   snprintf(p, sizeof(p), "%02d%02d%02d%02d%02d%02dZ",ts->tm_year%100,
      ts->tm_mon+1,ts->tm_mday,ts->tm_hour,ts->tm_min,ts->tm_sec);
*/

	time_t ret;
	struct tm thetime;
	char * strbuf;
	char * thestr;
	long gmadjust = 0;

	if (timestr->length < 13) {
		return (time_t)-1;
	}

	strbuf = strdup((char *)timestr->data);

	memset(&thetime, 0, sizeof(thetime));

	/* we work backwards so that we can use atoi more easily */

	thestr = strbuf + timestr->length - 3;

	thetime.tm_sec = atoi(thestr);
	*thestr = '\0';
	thestr -= 2;
	thetime.tm_min = atoi(thestr);
	*thestr = '\0';
	thestr -= 2;
	thetime.tm_hour = atoi(thestr);
	*thestr = '\0';
	thestr -= 2;
	thetime.tm_mday = atoi(thestr);
	*thestr = '\0';
	thestr -= 2;
	thetime.tm_mon = atoi(thestr)-1;
	*thestr = '\0';
	thestr -= 2;
	thetime.tm_year = atoi(thestr);

	if (thetime.tm_year < 68) {
		thetime.tm_year += 100;
	}

	thetime.tm_isdst = -1;
	ret = mktime(&thetime);

#if HAVE_TM_GMTOFF
	gmadjust = thetime.tm_gmtoff;
#else
	/*
	** If correcting for daylight savings time, we set the adjustment to
	** the value of timezone - 3600 seconds. Otherwise, we need to overcorrect and
	** set the adjustment to the main timezone + 3600 seconds.
	*/
	gmadjust = -(thetime.tm_isdst ? (long)timezone - 3600 : (long)timezone + 3600);
#endif
	ret += gmadjust;

	free(strbuf);

	return ret;
}
/* }}} */
void add_assoc_asn1_time(lua_State*L, char * key, ASN1_UTCTIME * timestr) /* {{{ */
{
	lua_pushinteger(L, (lua_Integer)asn1_time_to_time_t(timestr));
	lua_setfield(L,-2,key);
}


/* Pop all X509 from Stack and free them, free the stack afterwards */
void openssl_sk_X509_free(STACK_OF(X509) * sk) /* {{{ */
{
	for (;;) {
		X509* x = sk_X509_pop(sk);
		if (!x) break;
		X509_free(x);
	}
	sk_X509_free(sk);
}
/* }}} */


/* {{{ load_all_certs_from_file */
STACK_OF(X509) * load_all_certs_from_file(const char *certfile)
{
	STACK_OF(X509_INFO) *sk=NULL;
	STACK_OF(X509) *stack=NULL, *ret=NULL;
	BIO *in=NULL;
	X509_INFO *xi;

	if(!(stack = sk_X509_new_null())) {
		printf("memory allocation -1");
		goto end;
	}

	if(!(in=BIO_new_file(certfile, "r"))) {
		printf("error opening the file, %s", certfile);
		openssl_sk_X509_free(stack);
		goto end;
	}

	/* This loads from a file, a stack of x509/crl/pkey sets */
	if(!(sk=PEM_X509_INFO_read_bio(in, NULL, NULL, NULL))) {
		printf("error reading the file, %s", certfile);
		openssl_sk_X509_free(stack);
		goto end;
	}

	/* scan over it and pull out the certs */
	while (sk_X509_INFO_num(sk)) {
		xi=sk_X509_INFO_shift(sk);
		if (xi->x509 != NULL) {
			sk_X509_push(stack,xi->x509);
			xi->x509=NULL;
		}
		X509_INFO_free(xi);
	}
	if(!sk_X509_num(stack)) {
		printf("no certificates in file, %s", certfile);
		openssl_sk_X509_free(stack);
		goto end;
	}
	ret=stack;
end:
	BIO_free(in);
	sk_X509_INFO_free(sk);

	return ret;
}
/* }}} */




#define SSL_CONFIG_SYNTAX_CHECK(var) if (req->var && openssl_config_check_syntax(#var, \
			req->config_filename, req->var, req->req_config) == -1) return -1

#define SET_OPTIONAL_STRING_ARG(key, varname, defval, n)	\
	lua_getfield(L,n,key); \
	varname = luaL_optstring(L,-1,defval); \
	lua_pop(L,1)

#define SET_OPTIONAL_LONG_ARG(key, varname, defval, n)	\
	lua_getfield(L,n,key); \
	varname = luaL_optint(L,-1,defval); \
	lua_pop(L,1)


static int add_oid_section(struct x509_request * req) /* {{{ */
{
	char * str;
	STACK_OF(CONF_VALUE) * sktmp;
	CONF_VALUE * cnf;
	int i;

	str = CONF_get_string(req->req_config, NULL, "oid_section");
	if (str == NULL) {
		return 0;
	}
	sktmp = CONF_get_section(req->req_config, str);
	if (sktmp == NULL) {
		printf("problem loading oid section %s", str);
		return -1;
	}
	for (i = 0; i < sk_CONF_VALUE_num(sktmp); i++) {
		cnf = sk_CONF_VALUE_value(sktmp, i);
		if (OBJ_create(cnf->value, cnf->name, cnf->name) == NID_undef) {
			printf("problem creating object %s=%s", cnf->name, cnf->value);
			return -1;
		}
	}
	return 0;
}
/* }}} */

int openssl_parse_config(lua_State*L, struct x509_request * req, int n) /* {{{ */
{
	char * str;

	luaL_checktype(L,n, LUA_TTABLE);

	lua_getfield(L,n,"config");
	req->config_filename = (char*)luaL_optstring(L,-1,default_ssl_conf_filename);
	lua_pop(L,1);

	lua_getfield(L,n,"config_section_name");
	req->section_name = (char*)luaL_optstring(L,-1,"req");
	lua_pop(L,1);

	req->global_config = CONF_load(NULL, default_ssl_conf_filename, NULL);
	req->req_config = CONF_load(NULL, req->config_filename, NULL);

	if (req->req_config == NULL) {
		return -1;
	}

	/* read in the oids */
	str = CONF_get_string(req->req_config, NULL, "oid_file");
	if (str) {
		BIO *oid_bio = BIO_new_file(str, "r");
		if (oid_bio) {
			OBJ_create_objects(oid_bio);
			BIO_free(oid_bio);
		}
	}
	if (add_oid_section(req) == -1) {
		return -1;
	}

	lua_getfield(L,n,"config");
	req->config_filename = (char*)luaL_optstring(L,-1,default_ssl_conf_filename);
	lua_pop(L,1);

	SET_OPTIONAL_STRING_ARG("digest_alg", req->digest_name,
		CONF_get_string(req->req_config, req->section_name, "default_md"), n);
	SET_OPTIONAL_STRING_ARG("x509_extensions", req->extensions_section,
		CONF_get_string(req->req_config, req->section_name, "x509_extensions"), n);
	SET_OPTIONAL_STRING_ARG("req_extensions", req->request_extensions_section,
		CONF_get_string(req->req_config, req->section_name, "req_extensions"), n);
	SET_OPTIONAL_LONG_ARG("private_key_bits", req->priv_key_bits,
		CONF_get_number(req->req_config, req->section_name, "default_bits"), n);

	SET_OPTIONAL_LONG_ARG("private_key_type", req->priv_key_type, OPENSSL_KEYTYPE_DEFAULT, n);

	lua_getfield(L,n, "encrypt_key");
	if(lua_isnil(L,-1))
	{
		str = CONF_get_string(req->req_config, req->section_name, "encrypt_rsa_key");
		if (str == NULL) {
			str = CONF_get_string(req->req_config, req->section_name, "encrypt_key");
		}
		if (str && strcmp(str, "no") == 0) {
			req->priv_key_encrypt = 0;
		} else {
			req->priv_key_encrypt = 1;
		}
	}else
	{
		req->priv_key_encrypt = lua_tointeger(L,-1);
	}
	lua_pop(L,1);

	
	/* digest alg */
	if (req->digest_name == NULL) {
		req->digest_name = CONF_get_string(req->req_config, req->section_name, "default_md");
	}
	if (req->digest_name) {
		req->digest = req->md_alg = EVP_get_digestbyname(req->digest_name);
	}
	if (req->md_alg == NULL) {
		req->md_alg = req->digest = EVP_md5();
	}

	SSL_CONFIG_SYNTAX_CHECK(extensions_section);

	/* set the string mask */
	str = CONF_get_string(req->req_config, req->section_name, "string_mask");
	if (str && !ASN1_STRING_set_default_mask_asc(str)) {
		luaL_error(L,"Invalid global string mask setting %s", str);
		return -1;
	}

	SSL_CONFIG_SYNTAX_CHECK(request_extensions_section);
	
	return 0;
}
/* }}} */

void openssl_dispose_config(struct x509_request * req) /* {{{ */
{
	if (req->priv_key) {
		EVP_PKEY_free(req->priv_key);
		req->priv_key = NULL;
	}
	if (req->global_config) {
		CONF_free(req->global_config);
		req->global_config = NULL;
	}
	if (req->req_config) {
		CONF_free(req->req_config);
		req->req_config = NULL;
	}
}
/* }}} */

int openssl_load_rand_file(const char * file, int *egdsocket, int *seeded) /* {{{ */
{
	char buffer[MAX_PATH];


	*egdsocket = 0;
	*seeded = 0;

	if (file == NULL) {
		file = RAND_file_name(buffer, sizeof(buffer));
	} else if (RAND_egd(file) > 0) {
		/* if the given filename is an EGD socket, don't
		 * write anything back to it */
		*egdsocket = 1;
		return 0;
	}
	if (file == NULL || !RAND_load_file(file, -1)) {
		if (RAND_status() == 0) {
			printf("unable to load random state; not enough random data!");
			return -1;
		}
		return -1;
	}
	*seeded = 1;
	return 0;
}
/* }}} */

int openssl_write_rand_file(const char * file, int egdsocket, int seeded) /* {{{ */
{
	char buffer[MAX_PATH];

	if (egdsocket || !seeded) {
		/* if we did not manage to read the seed file, we should not write
		 * a low-entropy seed file back */
		return -1;
	}
	if (file == NULL) {
		file = RAND_file_name(buffer, sizeof(buffer));
	}
	if (file == NULL || !RAND_write_file(file)) {
		printf("unable to write random state");
		return -1;
	}
	return 0;
}
/* }}} */


void openssl_add_method_or_alias(const OBJ_NAME *name, void *arg) 
{
	lua_State *L = (lua_State *)arg;
	int i = lua_objlen(L,-1);
	lua_pushstring(L,name->name);
	lua_rawseti(L,-2,i+1);
}

void openssl_add_method(const OBJ_NAME *name, void *arg) 
{
	if (name->alias == 0) {
		openssl_add_method_or_alias(name,arg);
	}
}
