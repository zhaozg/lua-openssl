/*=========================================================================*\
* bio.c
* bio object for lua-openssl binding
*
* Author:  george zhao <zhaozg(at)gmail.com>
\*=========================================================================*/

#include "openssl.h"
#include "private.h"
#include <openssl/ssl.h>

#define MYNAME		"bio"
#define MYVERSION	MYNAME " library for " LUA_VERSION " / Nov 2014 / "\
	"based on OpenSSL " SHLIB_VERSION_NUMBER
#define MYTYPE			"bio"

/*
static const int* iMethods[] = {
	BIO_TYPE_NONE,
	BIO_TYPE_MEM,
	BIO_TYPE_SOCKET,
	BIO_TYPE_CONNECT,
	BIO_TYPE_ACCEPT,
	BIO_TYPE_FD,
	BIO_TYPE_BIO,
	BIO_TYPE_DGRAM,

	BIO_TYPE_BUFFER,

	-1
};
static const char* sMethods[] = {
	"none",
	"mem",
	"socket",
	"connect",
	"accept",
	"fd",
	"bio",
	"datagram",

	"buffer",
	NULL
};

static LUA_FUNCTION(openssl_bio_new) {

const char* f = luaL_checkstring(L,1);
const char* m = luaL_optstring(L,2,"r");
BIO *bio = BIO_new_file(f,m);
BIO_f_base64()
if(!bio)
luaL_error(L, "error opening the file(%s) for mode (%s)", f, m);
PUSH_OBJECT(bio,"openssl.bio");
return 1;
}

*/

static const char* close_flags[] = {
	"noclose",	/* #define BIO_NOCLOSE		0x00 */
	"close",	/* #define BIO_CLOSE		0x01 */
	NULL
};

static LUA_FUNCTION(openssl_bio_new_mem) {
    size_t l = 0;
    char* d = (char*)luaL_optlstring(L,1,NULL, &l);
	int closeflag = luaL_checkoption(L, 2, "close", close_flags);
	BIO *bio = BIO_new(BIO_s_mem());
	if(d) 
		BIO_write(bio,d,l);

	BIO_set_close(bio, closeflag);
    PUSH_OBJECT(bio, "openssl.bio");
    return 1;
}

static LUA_FUNCTION(openssl_bio_new_socket) {
	int s = luaL_checkint(L, 1);
	int closeflag = luaL_checkoption(L, 2, "noclose", close_flags);
	BIO *bio = BIO_new_socket(s,closeflag);

	PUSH_OBJECT(bio, "openssl.bio");
	return 1;
}

static LUA_FUNCTION(openssl_bio_new_dgram) {
	int s = luaL_checkint(L, 1);
	int closeflag = luaL_checkoption(L, 2, "noclose", close_flags);
	BIO *bio = BIO_new_dgram(s,closeflag);
	PUSH_OBJECT(bio, "openssl.bio");
	return 1;
}

static LUA_FUNCTION(openssl_bio_new_fd) {
	int fd = luaL_checkint(L, 1);
	int closeflag = luaL_checkoption(L, 2, "noclose", close_flags);
	BIO *bio = BIO_new_fd(fd,closeflag);

	PUSH_OBJECT(bio, "openssl.bio");
	return 1;
}

static LUA_FUNCTION(openssl_bio_new_file) {
    const char* f = luaL_checkstring(L,1);
    const char* m = luaL_optstring(L,2,"r");
    BIO *bio = BIO_new_file(f,m);
    if(!bio)
        luaL_error(L, "error opening the file(%s) for mode (%s)", f, m);
    PUSH_OBJECT(bio,"openssl.bio");
    return 1;
}

static LUA_FUNCTION(openssl_bio_new_accept) {
	const char* port = lua_tostring(L,1);
	BIO* b = BIO_new_accept((char*)port);

	PUSH_OBJECT(b, "openssl.bio");
	return 1;
}

static int openssl_bio_new_connect(lua_State *L)
{
	const char *host = luaL_checkstring(L, 1);
	BIO* bio = BIO_new_connect((char*)host);
	int doconn = 1;

	if(lua_isstring(L,2))
	{
		if(BIO_set_conn_port(bio,lua_tostring(L,2))<=0)
		{
			BIO_free(bio);
			bio = NULL;
		}else{
			doconn = lua_isnoneornil(L, 3)? doconn : auxiliar_checkboolean(L, 3);
		}
	}else
		doconn = auxiliar_checkboolean(L, 2);

	if(bio){
			int ret = 1;

			if(doconn)
			{
				ret = BIO_do_connect(bio);
			}

			if (ret == 1){
				PUSH_OBJECT(bio, "openssl.bio");
				return 1;
			}else{
				BIO_free(bio);
				luaL_error(L, "Error creating connection to remote machine");
			}
	}


	if(!bio)
		luaL_error(L, "Error creating connection BIO");
		
	return 0;
}

static int openssl_bio_new_filter(lua_State *L)
{								/* 0         1        2      3      4    5 */
	static const char* sType[] = {"base64","buffer","cipher","md","ssl",NULL};
	int type = luaL_checkoption(L, 1, NULL, sType);
	BIO* bio = NULL;
	int ret = 1;
	switch(type){
	case 0:
		bio = BIO_new(BIO_f_base64());
		break;
	case 1:
		bio = BIO_new(BIO_f_buffer());
		break;
	case 2:
		{
			const EVP_CIPHER* c = get_cipher(L, 2);
			size_t kl,il;
			const char* k = luaL_checklstring(L, 3, &kl);
			const char* v = luaL_checklstring(L, 4, &il);
			int encrypt = auxiliar_checkboolean(L, 5);

			bio = BIO_new(BIO_f_cipher());
			BIO_set_cipher(bio,c,(const unsigned char*)k,(const unsigned char*)v, encrypt);
		}
		break;
	case 3:
		{
			const EVP_MD* md = get_digest(L, 2);
			bio = BIO_new(BIO_f_md());
			ret = BIO_set_md(bio,md);
		}
	case 4:
		{
			const SSL* ssl = CHECK_OBJECT(1,SSL, "openssl.ssl");
			int closeflag = luaL_checkoption(L, 2, "noclose", close_flags);
			bio = BIO_new(BIO_f_ssl());
			ret = BIO_set_ssl(bio,ssl,closeflag);
		}
	default:
		ret = 0;
	}
	if(ret==1 && bio)
	{
		PUSH_OBJECT(bio,"openssl.bio");
		return 1;
	}
	if(bio)
		BIO_free(bio);
	return 0;
}

/* bio object method */
static LUA_FUNCTION(openssl_bio_read) {
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

static LUA_FUNCTION(openssl_bio_gets) {
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


static LUA_FUNCTION(openssl_bio_write) {
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

static LUA_FUNCTION(openssl_bio_puts) {
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

static LUA_FUNCTION(openssl_bio_flush) {
	BIO* bio = CHECK_OBJECT(1,BIO,"openssl.bio");
	int ret = BIO_flush(bio);
	lua_pushinteger(L, ret);
	return 1;
}

static LUA_FUNCTION(openssl_bio_close) {
    BIO* bio = CHECK_OBJECT(1,BIO,"openssl.bio");
    BIO_shutdown_wr(bio);
    BIO_set_close(bio,1);
    lua_pushnil(L);
    lua_replace(L,1);
    return 0;
}


static LUA_FUNCTION(openssl_bio_free) {
    BIO* bio = CHECK_OBJECT(1,BIO,"openssl.bio");
    BIO_free(bio);
    return 0;
}


static LUA_FUNCTION(openssl_bio_type) {
    BIO* bio = CHECK_OBJECT(1,BIO,"openssl.bio");
    lua_pushstring(L, BIO_method_name(bio));
    return 1;
}

static LUA_FUNCTION(openssl_bio_reset) {
    BIO* bio = CHECK_OBJECT(1,BIO,"openssl.bio");
    BIO_reset(bio);
    return 0;
}

/* filter bio object */
static LUA_FUNCTION(openssl_bio_push) {
	BIO* bio = CHECK_OBJECT(1, BIO, "openssl.bio");
	BIO* append = CHECK_OBJECT(1, BIO, "openssl.bio");
	BIO* end = BIO_push(bio,append);
	assert(bio==end);
	lua_pushvalue(L, 1);
	return 1;
}

static LUA_FUNCTION(openssl_bio_pop) {
	BIO* bio = CHECK_OBJECT(1, BIO, "openssl.bio");
	BIO* end = BIO_pop(bio);
	if(end){
		lua_pushnil(L);
	}else{
		end->references++;
		PUSH_OBJECT(end,"openssl.bio");
	}
	return 1;
}

static LUA_FUNCTION(openssl_bio_free_all) {
	BIO* bio = CHECK_OBJECT(1, BIO, "openssl.bio");
	BIO_free_all(bio);

	return 0;
}

/* mem */
static LUA_FUNCTION(openssl_bio_get_mem) {
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

/* network socket */

static LUA_FUNCTION(openssl_bio_accept){
	BIO* bio = CHECK_OBJECT(1,BIO,"openssl.bio");
	int ret = BIO_do_accept(bio);
	if(ret==1){
		BIO *nb = BIO_pop(bio);

		PUSH_OBJECT(nb,"openssl.bio");
		return 1;
	}else
		luaL_error(L,"BIO_do_accept fail");

	return 0;
}

static LUA_FUNCTION(openssl_bio_connect){
	BIO* bio = CHECK_OBJECT(1,BIO,"openssl.bio");
	int ret = BIO_do_connect(bio);
	if(ret==1){
		PUSH_OBJECT(bio,"openssl.bio");
		return 1;
	}else
		luaL_error(L,"BIO_do_connect fail");

	return 0;
}
static LUA_FUNCTION(openssl_bio_fd) {
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


int BIO_socket_ioctl(int fd, long type, void *arg);
int BIO_socket_nbio(int fd,int mode);
int BIO_get_port(const char *str, unsigned short *port_ptr);
int BIO_get_host_ip(const char *str, unsigned char *ip);
int BIO_get_accept_socket(char *host_port,int mode);

static luaL_reg bio_funs[] = {
	/* generate operation */
    {"read",	openssl_bio_read	},
    {"gets",	openssl_bio_gets	},
    {"write",	openssl_bio_write	},
    {"puts",	openssl_bio_puts	},
	{"flush",	openssl_bio_flush	},
	{"close",	openssl_bio_close	},
	{"type",	openssl_bio_type	},
    {"reset",	openssl_bio_reset	},

	/* for filter bio */
	{"push",	openssl_bio_push},
	{"pop",		openssl_bio_pop},
	{"free_all",		openssl_bio_free_all},
	
	/* for mem */
	{"get_mem",	openssl_bio_get_mem	},

	/* network socket */
	{"accept",	openssl_bio_accept },
	{"connect",	openssl_bio_connect },
	
    {"__tostring",	auxiliar_tostring	},
    {"__gc",	openssl_bio_free	},

    {NULL,		NULL}
};

static luaL_reg R[] = {
	{"mem",			openssl_bio_new_mem	   },
	{"socket",		openssl_bio_new_socket   },
	{"dgram",		openssl_bio_new_dgram	   },
	{"fd",			openssl_bio_new_fd	   },
	{"file",		openssl_bio_new_file   },
	{"filter",		openssl_bio_new_filter   },

	{"accept",		openssl_bio_new_accept },
	{"connect",		openssl_bio_new_connect},

	{"__call",		openssl_bio_new_mem},
	{NULL,		NULL}
};

LUALIB_API int luaopen_bio(lua_State *L)
{
	auxiliar_newclass(L,"openssl.bio", bio_funs);

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

