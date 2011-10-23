/* 
$Id:$ 
$Revision:$
*/

#include "openssl.h"


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

/* }}} */

void add_assoc_name_entry(lua_State*L, char * key, X509_NAME * name, int shortname) /* {{{ */
{
	int i, j = -1, last = -1, obj_cnt = 0;
	char *sname;
	int nid;
	X509_NAME_ENTRY * ne;
	ASN1_STRING * str = NULL;
	ASN1_OBJECT * obj;
	char* p;

	lua_newtable(L);
	
	p=X509_NAME_oneline(name,NULL,0);
	lua_pushstring(L, p);
	lua_rawseti(L, -2, 0);
	OPENSSL_free(p);

	for (i = 0; i < X509_NAME_entry_count(name); i++) {
		unsigned char *to_add;
		int to_add_len;
		int tindex = 0;
		//int utf8 = 0;

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

				/* Some Certificate not stardand
				if (ASN1_STRING_type(str) != V_ASN1_UTF8STRING) {
					to_add_len = ASN1_STRING_to_UTF8(&to_add, str);
				}
				*/

				to_add = ASN1_STRING_data(str);
				to_add_len = ASN1_STRING_length(str);
				tindex++;
				lua_pushlstring(L,(char *)to_add, to_add_len);
				lua_rawseti(L,-2,tindex);
			}
			last = j;
		}
		i = last;
		
		if (obj_cnt > 1) {
			lua_setfield(L,-2,sname);
		} else {
			lua_pop(L,1);
			if (obj_cnt && str && to_add_len > -1) {
				lua_pushlstring(L,(char *)to_add, to_add_len);
				lua_setfield(L,-2, sname);
			}
		}
	}

	if (key != NULL) {
		lua_setfield(L,-2,key);
	}
}


/*  openssl.object_create(string oid, string name[, string alias] | tables args ) -> boolean{{{1
*/
int openssl_object_create(lua_State* L) 
{
	int ret = 0;

	const char* oid;
	const char* name;
	const char* alias;

	if (!lua_istable(L,1))
	{
		oid = luaL_checkstring(L,1);
		name = luaL_checkstring(L,2);
		alias = luaL_optstring(L,3,name);

		ret = OBJ_create(oid, name, alias) != NID_undef;
		lua_pushboolean(L,ret);
		if(!ret)
		{
			lua_pushfstring(L,"create object(%s) with name(%s) failed",oid,name);
			ret = 2;
		}else
			ret = 1;
		return ret;
	}else
	{
		size_t i;
		for (i = 1; i <= lua_objlen(L,1); i++) {
			lua_rawgeti(L,-1, i);
			if(lua_istable(L,-1))
			{
				lua_getfield(L,-1,"oid");
				oid = luaL_checkstring(L,-1);
				lua_pop(L,1);
				lua_getfield(L,-2,"name");
				name = luaL_checkstring(L,-1);
				lua_pop(L,1);
				lua_getfield(L,-3,"alias");
				alias = luaL_optstring(L,-1,name);
				lua_pop(L,1);
				if(OBJ_create(oid, name, alias) == NID_undef)
				{
					luaL_error(L,"create object(%s) with name(%s) failed at %d",oid,name,i);
				}
			}
			lua_pop(L,1);
		}
		lua_pushboolean(L,1);
		return 1;
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

/* {{{ proto string openssl_random_bytes(integer length [, &bool returned_strong_result])
   Returns a string of the length specified filled with random pseudo bytes */
LUA_FUNCTION(openssl_random_bytes)
{
	long length = luaL_checkint(L,1);
	int strong = lua_isnil(L,2) ? 0 : lua_toboolean(L,2);

	unsigned char *buffer = NULL;
	int ret = 0;

	if (length <= 0) {
		luaL_error(L,"paramater 1 must not be nego");
	}

	buffer = malloc(length + 1);

#ifdef WINDOWS
        RAND_screen();
#endif
	if (strong)
	{
		ret = RAND_bytes(buffer,length);
		if(ret) {
			lua_pushlstring(L, buffer, length);
			lua_pushboolean(L, 1);
			ret = 2;
		} else {
			lua_pushboolean(L, 0);
			ret = 1;
		}
	}
	else {
		ret = RAND_pseudo_bytes(buffer, length);
		if(ret>=0) {
			lua_pushlstring(L, buffer, length);
			lua_pushboolean(L, ret);
			ret = 2;
		}else {
			lua_pushboolean(L, 0);
			ret = 1;
		}
	}
	free(buffer);
	return ret;
}

/* }}} */

LUA_FUNCTION(openssl_x509_algo_parse) {
	X509_ALGOR *algo = CHECK_OBJECT(1,X509_ALGOR,"openssl.x509_algor");
	BIO* bio = BIO_new(BIO_s_mem());
	lua_newtable(L);
	ADD_ASSOC_ASN1(ASN1_OBJECT,bio,algo->algorithm,"algorithm");
	//ADD_ASSOC_ASN1(ASN1_TYPE,bio,algo->parameter,"parameter");
	BIO_free(bio);
	return 1;
}

LUA_FUNCTION(openssl_x509_algo_tostring) {
	X509_ALGOR *algo = CHECK_OBJECT(1,X509_ALGOR,"openssl.x509_algor");
	lua_pushfstring(L,"openssl.x509_algor:%p");
	return 1;
}


LUA_FUNCTION(openssl_x509_extension_parse) {
	X509_EXTENSION *ext = CHECK_OBJECT(1,X509_EXTENSION,"openssl.x509_extension");
	BIO* bio = BIO_new(BIO_s_mem());
	lua_newtable(L);
	lua_pushboolean(L,ext->critical);
	lua_setfield(L,-2,"critical");
	ADD_ASSOC_ASN1(ASN1_OBJECT,bio,ext->object,"object");
	BIO_free(bio);
	{
		ASN1_OCTET_STRING *os = ext->value;
		lua_pushlstring(L,os->data, os->length);
		lua_setfield(L,-2,"value");
	}
	return 1;
}

LUA_FUNCTION(openssl_x509_extension_tostring) {
	X509_EXTENSION *ext = CHECK_OBJECT(1,X509_EXTENSION,"openssl.x509_extension");
	lua_pushfstring(L,"openssl.x509_extension:%p");
	return 1;
}

static luaL_Reg x509_algo_funs[] = {
	{"__tostring", openssl_x509_algo_tostring},
	{"parse", openssl_x509_algo_parse},

	{ NULL, NULL }
};

static luaL_Reg x509_extension_funs[] = {
	{"__tostring", openssl_x509_extension_tostring},
	{"parse", openssl_x509_extension_parse},

	{ NULL, NULL }
};

int openssl_register_misc(lua_State*L) {
   auxiliar_newclass(L,"openssl.x509_algor",		x509_algo_funs);
   auxiliar_newclass(L,"openssl.x509_extension",	x509_extension_funs);
   return 0;
}
