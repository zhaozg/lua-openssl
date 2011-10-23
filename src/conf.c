#include "openssl.h"
#include <openssl/conf.h>

static void table2data(lua_State*L, int idx,BIO* bio){
	lua_pushnil(L);
	while(lua_next(L,idx))
	{
		const char * key = lua_tostring(L,-2); 
		if(lua_istable(L,-1))
		{
			BIO_printf(bio,"[%s]\n",key);
			table2data(L,lua_gettop(L),bio);
		}else
		{
			const char * val = lua_tostring(L,-1);
			BIO_printf(bio,"%s=%s\n",key,val);
		}
		lua_pop(L,1);
	}
}

int openssl_conf_load_idx(lua_State*L, int idx) {
	long eline;
	BIO* bio;
	LHASH* conf;
	if(lua_isstring(L,idx))
	{
		int l;
		const char * data= luaL_checklstring(L,idx,&l);
		bio = BIO_new_mem_buf((void*)data,l);
	}else if(lua_istable(L,idx))
	{
		bio = BIO_new(BIO_s_mem());
		table2data(L,idx, bio);
	}else if(lua_isuserdata(L,idx))
	{
		conf = CHECK_OBJECT(1, LHASH, "openssl.conf");
	}else
	{
		luaL_error(L,"openssl.conf_load first paramater must be conf_context as string, table or openssl.conf object");
	}

	conf = CONF_load_bio(NULL, bio, &eline);
	if(!conf)
	{
		lua_pushnil(L);
		lua_pushinteger(L,eline);
		return 2;
	}
	PUSH_OBJECT(conf,"openssl.conf");
	return 1;
}

LUA_FUNCTION(openssl_conf_load){
	return openssl_conf_load_idx(L,1);
}

LUA_FUNCTION(openssl_conf_gc) {
	LHASH* conf = CHECK_OBJECT(1,LHASH,"openssl.conf");
	CONF_free(conf);
	return 0;
}

LUA_FUNCTION(openssl_conf_tostring) {
	LHASH* conf = CHECK_OBJECT(1,LHASH,"openssl.conf");
	lua_pushfstring(L,"openssl.conf:%p",conf);

	return 1;
}

LUA_FUNCTION(openssl_conf_get_number)
{
	LHASH* conf = CHECK_OBJECT(1,LHASH,"openssl.conf");
	const char* group = luaL_checkstring(L,2);
	const char* name = luaL_checkstring(L,3);
	long result = 0;
	lua_pushinteger(L,CONF_get_number(conf,group,name));
	return 1;
}


LUA_FUNCTION(openssl_conf_get_string)
{
	LHASH* conf = CHECK_OBJECT(1,LHASH,"openssl.conf");
	const char* group = luaL_checkstring(L,2);
	const char* name = luaL_checkstring(L,3);
	long result = 0;
	lua_pushstring(L,CONF_get_string(conf,group,name));

	return 1;
}

static void dump_value_doall_arg(CONF_VALUE *a, lua_State *L)
{
	if (a->name)
	{
		lua_getfield(L,-1,a->section);
		if(!lua_istable(L,-1))
		{
			lua_pop(L,1);
			lua_newtable(L);
			lua_setfield(L,-2,a->section);
			lua_getfield(L,-1,a->section);
		}
		lua_pushstring(L,a->value);
		lua_setfield(L,-2,a->name);
		lua_pop(L,1);
	}
	else
	{
		if(a->section)
		{
			lua_getfield(L,-1,a->section);
			if(lua_istable(L,-1))
				lua_pop(L,1);
			else
			{
				lua_pop(L,1);
				lua_newtable(L);
				lua_setfield(L,-2,a->section);
			}
		}else
		{
			lua_pushstring(L,a->value);
			lua_setfield(L,-2,a->name);
		}
	}
}
#if OPENSSL_VERSION_NUMBER >= 0x10000002L 
static IMPLEMENT_LHASH_DOALL_ARG_FN(dump_value, CONF_VALUE, lua_State)
#endif
#define LHM_lh_doall_arg(type, lh, fn, arg_type, arg) \
	lh_doall_arg(CHECKED_LHASH_OF(type, lh), fn, CHECKED_PTR_OF(arg_type, arg))

LUA_FUNCTION(openssl_conf_parse)
{
	LHASH* conf = CHECK_OBJECT(1,LHASH,"openssl.conf");

	if(lua_gettop(L)==1 || auxiliar_checkboolean(L,2)) {
		lua_newtable(L);
#if OPENSSL_VERSION_NUMBER >= 0x10000002L 
		lh_CONF_VALUE_doall_arg(conf, LHASH_DOALL_ARG_FN(dump_value), lua_State, L);
#else
		lh_doall_arg(conf,dump_value_doall_arg, L);
#endif
		
		return 1;
	}else
	{
		BIO *bio = BIO_new(BIO_s_mem());
		BUF_MEM *bptr = NULL;

		CONF_dump_bio(conf, bio);
		BIO_get_mem_ptr(bio, &bptr);

		lua_pushlstring(L,bptr->data,bptr->length);
		BIO_set_close(bio, BIO_NOCLOSE);
		BIO_free(bio);

		return 1;
	}
}


static luaL_Reg conf_funs[] = {
	{"__tostring", openssl_conf_tostring},
	{"__gc", openssl_conf_gc},

	{"parse", openssl_conf_parse},
	{"get_string", openssl_conf_get_string},
	{"get_number", openssl_conf_get_number},

	{ NULL, NULL }
};

int openssl_register_conf(lua_State* L)
{
	auxiliar_newclass(L,"openssl.conf",		conf_funs);
	return 0;
};
