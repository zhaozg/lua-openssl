/* 
$Id:$ 
$Revision:$
*/

#include "openssl.h"

LUA_FUNCTION(openssl_bio_new_mem){
	int l = 0;
	char* d = (char*)luaL_optlstring(L,1,NULL, &l);
	BIO *bio = d ? BIO_new_mem_buf(d, l) : BIO_new(BIO_s_mem());
	PUSH_OBJECT(bio, "openssl.bio");
	return 1;
}

LUA_FUNCTION(openssl_bio_new_file) {
	const char* f = luaL_checkstring(L,1);
	const char* m = luaL_optstring(L,2,"r");
	BIO *bio = BIO_new_file(f,m);
	if(!bio)
		luaL_error(L, "error opening the file(%s) for mode (%s)", f, m);
	PUSH_OBJECT(bio,"openssl.bio");
	return 1;
}

LUA_FUNCTION(openssl_bio_read) {
	BIO* bio = CHECK_OBJECT(1,BIO,"openssl.bio");
	int len = luaL_checkint(L,2);
	char* buf;
	int ret = 1;

	if(len<=0)
		luaL_error(L,"#2 paramater msut be positive number");
	buf = malloc(len);
	len = BIO_read(bio,buf, len);
	if(len>=0){
		lua_pushlstring(L,buf,len);
		ret = 1;
	}
	else{
		lua_pushnil(L);
		lua_pushinteger(L, len);
		ret = 2;
	};
	free(buf);
	return ret;
}

LUA_FUNCTION(openssl_bio_gets) {
	BIO* bio = CHECK_OBJECT(1,BIO,"openssl.bio");
	int len = luaL_optint(L,2,256);
	char* buf;
	int ret = 1;

	if(len<=0)
		luaL_error(L,"#2 paramater msut be positive number");
	buf = malloc(len);
	len = BIO_gets(bio,buf, len);
	if(len>=0){
		lua_pushlstring(L,buf,len);
		ret = 1;
	}
	else{
		lua_pushnil(L);
		lua_pushinteger(L, len);
		ret = 2;
	};
	free(buf);
	return ret;
}


LUA_FUNCTION(openssl_bio_write) {
	BIO* bio = CHECK_OBJECT(1,BIO,"openssl.bio");
	int len = 0;
	const char* d = luaL_checklstring(L,2, &len);
	int ret = 1;

	len = BIO_write(bio, d, len);
	if(len>=0){
		lua_pushinteger(L, len);
		ret = 1;
	}
	else{
		lua_pushnil(L);
		lua_pushinteger(L, len);
		ret = 2;
	};
	return ret;
}

LUA_FUNCTION(openssl_bio_puts) {
	BIO* bio = CHECK_OBJECT(1,BIO,"openssl.bio");
	const char* s = luaL_checkstring(L,2);
	int ret = 1;
	int len = BIO_puts(bio,s);

	if(len>=0){
		lua_pushinteger(L, len);
		ret = 1;
	}
	else{
		lua_pushnil(L);
		lua_pushinteger(L, len);
		ret = 2;
	};
	return ret;
}

LUA_FUNCTION(openssl_bio_get_mem) {
	BIO* bio = CHECK_OBJECT(1,BIO,"openssl.bio");
	if(BIO_method_type(bio)==BIO_TYPE_MEM)
	{
		BUF_MEM* mem;
		BIO_get_mem_ptr(bio, &mem);
		lua_pushlstring(L,mem->data, mem->length);
		return 1;
	}
	luaL_error(L,"#1 BIO must be memory type");
	return 0;
}


LUA_FUNCTION(openssl_bio_close) {
	BIO* bio = CHECK_OBJECT(1,BIO,"openssl.bio");
	BIO_set_close(bio,1);
	lua_pushnil(L);
	lua_replace(L,1);

	return 0;
}


LUA_FUNCTION(openssl_bio_free) {
	BIO* bio = CHECK_OBJECT(1,BIO,"openssl.bio");
	BIO_free(bio);
	return 0;
}


LUA_FUNCTION(openssl_bio_type) {
	BIO* bio = CHECK_OBJECT(1,BIO,"openssl.bio");
	lua_pushstring(L, BIO_method_name(bio));
	return 1;
};

LUA_FUNCTION(openssl_bio_reset) {
	BIO* bio = CHECK_OBJECT(1,BIO,"openssl.bio");
	BIO_reset(bio);
	return 0;
};


LUA_FUNCTION(openssl_bio_tostring) {
	BIO* bio = CHECK_OBJECT(1,BIO,"openssl.bio");
	lua_pushfstring(L, "openssl.bio:%p",bio);
	return 1;
};

static luaL_reg bio_funs[] = {
	{"read",	openssl_bio_read	},
	{"gets",	openssl_bio_gets	},
	{"write",	openssl_bio_write	},
	{"puts",	openssl_bio_puts	},

	{"get_mem",	openssl_bio_get_mem	},

	{"close",	openssl_bio_close	},
	{"type",	openssl_bio_type	},
	{"reset",	openssl_bio_reset	},

	{"__tostring",	openssl_bio_tostring	},
	{"__gc",	openssl_bio_free	},
	
	{NULL,		NULL}
};

int openssl_register_bio(lua_State* L) {
	auxiliar_newclass(L, "openssl.bio", bio_funs);
	return 0;
}
