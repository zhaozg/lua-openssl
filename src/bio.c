/*
   +----------------------------------------------------------------------+
   | PHP Version 5                                                        |
   +----------------------------------------------------------------------+
   | Copyright (c) 1997-2012 The PHP Group                                |
   +----------------------------------------------------------------------+
   | This source file is subject to version 3.01 of the PHP license,      |
   | that is bundled with this package in the file LICENSE, and is        |
   | available through the world-wide-web at the following url:           |
   | http://www.php.net/license/3_01.txt                                  |
   | If you did not receive a copy of the PHP license and are unable to   |
   | obtain it through the world-wide-web, please send a note to          |
   | license@php.net so we can mail you a copy immediately.               |
   +----------------------------------------------------------------------+
*/
/*=========================================================================*\
* bio routines
* lua-openssl toolkit
*
* This product includes PHP software, freely available from <http://www.php.net/software/>
* Author:  george zhao <zhaozg(at)gmail.com>
\*=========================================================================*/
#include "openssl.h"

LUA_FUNCTION(openssl_bio_new_mem) {
    size_t l = 0;
    char* d = (char*)luaL_optlstring(L,1,NULL, &l);
    BIO *bio = d ? BIO_new_mem_buf(d, l) : BIO_new(BIO_s_mem());
    PUSH_OBJECT(bio, "openssl.bio");
    return 1;
}

LUA_FUNCTION(openssl_bio_new_accept) {
	const char* port = lua_tostring(L,1);
	BIO* b = BIO_new_accept((char*)port);
	int ret;
	/* First call to BIO_accept() sets up accept BIO */
	ret = BIO_do_accept(b);
	if( ret <= 0) {
		lua_pushboolean(L, 0);
		lua_pushinteger(L, ret);
		BIO_free(b);
		return 2;
	}

	PUSH_OBJECT(b, "openssl.bio");
	return 1;
}


LUA_FUNCTION(openssl_accept){
	BIO* bio = CHECK_OBJECT(1,BIO,"openssl.bio");
	int ret = BIO_do_accept(bio);
	BIO *nb;
	if (ret<=0)
	{
		lua_pushnil(L);
		lua_pushinteger(L, ret);
		return 2;
	}

	nb = BIO_pop(bio);
	PUSH_OBJECT(nb,"openssl.bio");
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
    int len = luaL_optint(L,2, 2048);
    char* buf = malloc(len);
    int ret = 1;
    
    len = BIO_read(bio,buf, len);
    if(len>=0) {
        lua_pushlstring(L,buf,len);
        ret = 1;
    }
    else {
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
    if(len>=0) {
        lua_pushlstring(L,buf,len);
        ret = 1;
    }
    else {
        lua_pushnil(L);
        lua_pushinteger(L, len);
        ret = 2;
    };
    free(buf);
    return ret;
}


LUA_FUNCTION(openssl_bio_write) {
    BIO* bio = CHECK_OBJECT(1,BIO,"openssl.bio");
    size_t size = 0;
    const char* d = luaL_checklstring(L,2, &size);
	int ret = 1;
	int len = luaL_optint(L, 3, size);

    len = BIO_write(bio, d, len);
    if(len>=0) {
        lua_pushinteger(L, len);
        ret = 1;
    }
    else {
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

    if(len>=0) {
        lua_pushinteger(L, len);
        ret = 1;
    }
    else {
        lua_pushnil(L);
        lua_pushinteger(L, len);
        ret = 2;
    };
    return ret;
}

LUA_FUNCTION(openssl_bio_flush) {
	BIO* bio = CHECK_OBJECT(1,BIO,"openssl.bio");
	int ret = BIO_flush(bio);
	lua_pushinteger(L, ret);
	return 1;
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
    BIO_shutdown_wr(bio);
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
}

LUA_FUNCTION(openssl_bio_reset) {
    BIO* bio = CHECK_OBJECT(1,BIO,"openssl.bio");
    BIO_reset(bio);
    return 0;
}


LUA_FUNCTION(openssl_bio_tostring) {
    BIO* bio = CHECK_OBJECT(1,BIO,"openssl.bio");
    lua_pushfstring(L, "openssl.bio:%p",bio);
    return 1;
}

LUA_FUNCTION(openssl_bio_fd) {
	BIO* bio = CHECK_OBJECT(1,BIO,"openssl.bio");
	int typ = BIO_method_type(bio);
	if(typ & BIO_TYPE_FD){
		int fd = -1;
		if (!lua_isnoneornil(L, 2)){
			fd = lua_tointeger(L, 2);
			BIO_set_fd(bio, fd, BIO_NOCLOSE);
		}else
			fd = BIO_get_fd(bio, 0);
		lua_pushinteger(L, fd);
	}else
		luaL_error(L, "BIO type miss match");
	return 1;
}

LUA_FUNCTION(openssl_bio_accept_port) {
	BIO* bio = CHECK_OBJECT(1,BIO,"openssl.bio");
	int typ = BIO_method_type(bio);
	if(typ & BIO_TYPE_FD){
		lua_pushstring(L, BIO_get_accept_port(bio));
	}else
		luaL_error(L, "BIO type miss match");
	return 1;
}

int BIO_socket_ioctl(int fd, long type, void *arg);
int BIO_socket_nbio(int fd,int mode);
int BIO_get_port(const char *str, unsigned short *port_ptr);
int BIO_get_host_ip(const char *str, unsigned char *ip);
int BIO_get_accept_socket(char *host_port,int mode);

static luaL_reg bio_funs[] = {
    {"read",	openssl_bio_read	},
    {"gets",	openssl_bio_gets	},
    {"write",	openssl_bio_write	},
    {"puts",	openssl_bio_puts	},
	{"flush",	openssl_bio_flush	},

	{"accept",	openssl_accept		},
    {"get_mem",	openssl_bio_get_mem	},

    {"close",	openssl_bio_close	},
    {"type",	openssl_bio_type	},
    {"reset",	openssl_bio_reset	},

	{"accept_port",		openssl_bio_accept_port	},
	
    {"__tostring",	openssl_bio_tostring	},
    {"__gc",	openssl_bio_free	},

    {NULL,		NULL}
};

int openssl_register_bio(lua_State* L) {
    auxiliar_newclass(L, "openssl.bio", bio_funs);
    return 0;
}

