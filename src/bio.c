/*=========================================================================*\
* bio.c
* bio object for lua-openssl binding
*
* Author:  george zhao <zhaozg(at)gmail.com>
\*=========================================================================*/

#include "openssl.h"
#include "private.h"
#include <openssl/ssl.h>

#define MYNAME    "bio"
#define MYVERSION MYNAME " library for " LUA_VERSION " / Nov 2014 / "\
  "based on OpenSSL " SHLIB_VERSION_NUMBER

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

static const char* close_flags[] =
{
  "noclose",  /* #define BIO_NOCLOSE    0x00 */
  "close",  /* #define BIO_CLOSE    0x01 */
  NULL
};

static LUA_FUNCTION(openssl_bio_new_mem)
{
  size_t l = 0;
  BIO *bio = BIO_new(BIO_s_mem());
  if (lua_isnumber(L, 1))
  {
    l = lua_tointeger(L, 1);
    BIO_set_buffer_size(bio, l);
  }
  else if (lua_isstring(L, 1))
  {
    const char* d = (char*)luaL_checklstring(L, 1, &l);
    BIO_write(bio, d, l);
  }

  BIO_set_close(bio, BIO_CLOSE);
  PUSH_OBJECT(bio, "openssl.bio");
  return 1;
}

static LUA_FUNCTION(openssl_bio_new_socket)
{
  int s = luaL_checkint(L, 1);
  int closeflag = luaL_checkoption(L, 2, "noclose", close_flags);
  BIO *bio = BIO_new_socket(s, closeflag);

  PUSH_OBJECT(bio, "openssl.bio");
  return 1;
}

static LUA_FUNCTION(openssl_bio_new_dgram)
{
  int s = luaL_checkint(L, 1);
  int closeflag = luaL_checkoption(L, 2, "noclose", close_flags);
  BIO *bio = BIO_new_dgram(s, closeflag);
  PUSH_OBJECT(bio, "openssl.bio");
  return 1;
}

static LUA_FUNCTION(openssl_bio_new_fd)
{
  int fd = luaL_checkint(L, 1);
  int closeflag = luaL_checkoption(L, 2, "noclose", close_flags);
  BIO *bio = BIO_new_fd(fd, closeflag);

  PUSH_OBJECT(bio, "openssl.bio");
  return 1;
}

static LUA_FUNCTION(openssl_bio_new_file)
{
  const char* f = luaL_checkstring(L, 1);
  const char* m = luaL_optstring(L, 2, "r");
  BIO *bio = BIO_new_file(f, m);
  if (!bio)
    luaL_error(L, "error opening the file(%s) for mode (%s)", f, m);
  PUSH_OBJECT(bio, "openssl.bio");
  return 1;
}

static LUA_FUNCTION(openssl_bio_new_accept)
{
  const char* port = lua_tostring(L, 1);
  BIO* b = BIO_new_accept((char*)port);

  PUSH_OBJECT(b, "openssl.bio");
  return 1;
}

static int openssl_bio_new_connect(lua_State *L)
{
  const char *host = luaL_checkstring(L, 1);
  BIO* bio = BIO_new_connect((char*)host);
  int doconn = 1;

  if (lua_isstring(L, 2))
  {
    if (BIO_set_conn_port(bio, lua_tostring(L, 2)) <= 0)
    {
      BIO_free(bio);
      bio = NULL;
    }
    else
    {
      doconn = lua_isnoneornil(L, 3) ? doconn : auxiliar_checkboolean(L, 3);
    }
  }
  else
    doconn = auxiliar_checkboolean(L, 2);

  if (bio)
  {
    int ret = 1;
    if (doconn)
    {
      ret = BIO_do_connect(bio);
    }

    if (ret == 1)
    {
      PUSH_OBJECT(bio, "openssl.bio");
      openssl_newvalue(L, bio);

      lua_pushboolean(L, 1);
      openssl_setvalue(L, bio, "free_all");
      return 1;
    }
    else
    {
      BIO_free(bio);
      luaL_error(L, "Error creating connection to remote machine");
    }
  }

  if (!bio)
    luaL_error(L, "Error creating connection BIO");

  return 0;
}

static LUA_FUNCTION(openssl_bio_new_filter)
{
  /* 0         1        2      3      4    5 */
  static const char* sType[] = {"base64", "buffer", "cipher", "md", "ssl", NULL};
  int type = luaL_checkoption(L, 1, NULL, sType);
  BIO* bio = NULL;
  int ret = 1;
  int closeflag = 0;
  switch (type)
  {
  case 0:
    bio = BIO_new(BIO_f_base64());
    break;
  case 1:
    bio = BIO_new(BIO_f_buffer());
    break;
  case 2:
  {
    const EVP_CIPHER* c = get_cipher(L, 2, NULL);
    size_t kl, il;
    const char* k = luaL_checklstring(L, 3, &kl);
    const char* v = luaL_checklstring(L, 4, &il);
    int encrypt = auxiliar_checkboolean(L, 5);

    bio = BIO_new(BIO_f_cipher());
    BIO_set_cipher(bio, c, (const unsigned char*)k, (const unsigned char*)v, encrypt);
  }
  break;
  case 3:
  {
    const EVP_MD* md = get_digest(L, 2);
    bio = BIO_new(BIO_f_md());
    ret = BIO_set_md(bio, md);
  }
  case 4:
  {
    SSL* ssl = CHECK_OBJECT(2, SSL, "openssl.ssl");
    closeflag = luaL_checkoption(L, 3, "noclose", close_flags);
    bio = BIO_new(BIO_f_ssl());
    ret = BIO_set_ssl(bio, ssl, closeflag);
  }
  break;
  default:
    ret = 0;
  }
  if (ret == 1 && bio)
  {
    PUSH_OBJECT(bio, "openssl.bio");
    if (closeflag)
    {
      openssl_newvalue(L, bio);

      lua_pushboolean(L, 1);
      openssl_setvalue(L, bio, "free_all");
    }
    return 1;
  }
  else
  {
    if (bio)
      BIO_free(bio);
    return openssl_pushresult(L, ret);
  }
}

/* bio object method */
static LUA_FUNCTION(openssl_bio_read)
{
  BIO* bio = CHECK_OBJECT(1, BIO, "openssl.bio");
  int len = luaL_optint(L, 2, BIO_pending(bio));
  char* buf = NULL;
  int ret = 1;

  len = len > 0 ? len : 4096;
  buf = malloc(len);
  len = BIO_read(bio, buf, len);

  if (len > 0)
  {
    lua_pushlstring(L, buf, len);
    ret = 1;
  }
  else if (BIO_should_retry(bio))
  {
    lua_pushlstring(L, buf, 0);
    ret = 1;
  }
  else
  {
    lua_pushnil(L);
    lua_pushinteger(L, len);
    ret = 2;
  };
  free(buf);
  return ret;
}

static LUA_FUNCTION(openssl_bio_gets)
{
  BIO* bio = CHECK_OBJECT(1, BIO, "openssl.bio");
  int len = luaL_optint(L, 2, BIO_pending(bio));
  char* buf;
  int ret = 1;
  len = len > 0 ? len : 1024;

  buf = malloc(len);
  len = BIO_gets(bio, buf, len);
  if (len > 0)
  {
    lua_pushlstring(L, buf, len);
    ret = 1;
  }
  else if (BIO_should_retry(bio))
  {
    lua_pushstring(L, "");
    ret = 1;
  }
  else
  {
    lua_pushnil(L);
    lua_pushinteger(L, len);
    ret = 2;
  };
  free(buf);
  return ret;
}


static LUA_FUNCTION(openssl_bio_write)
{
  BIO* bio = CHECK_OBJECT(1, BIO, "openssl.bio");
  size_t size = 0;
  const char* d = luaL_checklstring(L, 2, &size);
  int ret = 1;
  int len = luaL_optint(L, 3, size);

  len = BIO_write(bio, d, len);
  if (len > 0)
  {
    lua_pushinteger(L, len);
    ret = 1;
  }
  else if (BIO_should_retry(bio))
  {
    lua_pushinteger(L, 0);
    ret = 1;
  }
  else
  {
    lua_pushnil(L);
    lua_pushinteger(L, len);
    ret = 2;
  };
  return ret;
}

static LUA_FUNCTION(openssl_bio_puts)
{
  BIO* bio = CHECK_OBJECT(1, BIO, "openssl.bio");
  const char* s = luaL_checkstring(L, 2);
  int ret = 1;
  int len = BIO_puts(bio, s);

  if (len > 0)
  {
    lua_pushinteger(L, len);
    ret = 1;
  }
  else if (BIO_should_retry(bio))
  {
    lua_pushinteger(L, 0);
    ret = 1;
  }
  else
  {
    lua_pushnil(L);
    lua_pushinteger(L, len);
    ret = 2;
  };
  return ret;
}

static LUA_FUNCTION(openssl_bio_flush)
{
  BIO* bio = CHECK_OBJECT(1, BIO, "openssl.bio");
  int ret = BIO_flush(bio);
  lua_pushinteger(L, ret);
  return 1;
}

static LUA_FUNCTION(openssl_bio_free)
{
  BIO* bio = CHECK_OBJECT(1, BIO, "openssl.bio");
  int all = 0;

  if (lua_isboolean(L, 2))
    all = lua_toboolean(L, 2);
  else
  {
    openssl_getvalue(L, bio, "free_all");
    all = lua_toboolean(L, -1);
    lua_pop(L, 1);
  }

  if (all)
    BIO_free_all(bio);
  else
    BIO_free(bio);
  lua_pushnil(L);
  lua_setmetatable(L, 1);
  return 0;
}

static LUA_FUNCTION(openssl_bio_type)
{
  BIO* bio = CHECK_OBJECT(1, BIO, "openssl.bio");
  lua_pushstring(L, BIO_method_name(bio));
  return 1;
}

static LUA_FUNCTION(openssl_bio_nbio)
{
  BIO* bio = CHECK_OBJECT(1, BIO, "openssl.bio");
  int nbio = lua_toboolean(L, 2);
  int ret = BIO_set_nbio(bio, nbio);
  return openssl_pushresult(L, ret);
}

static LUA_FUNCTION(openssl_bio_retry)
{
  BIO* bio = CHECK_OBJECT(1, BIO, "openssl.bio");
  int retry = BIO_should_retry(bio);
  if (retry)
  {
    lua_pushboolean(L, 1);
    lua_pushboolean(L, BIO_should_read(bio));
    lua_pushboolean(L, BIO_should_write(bio));
    lua_pushboolean(L, BIO_should_io_special(bio));
    return 4;
  }
  else
    lua_pushboolean(L, 0);
  return 1;
}



static LUA_FUNCTION(openssl_bio_reset)
{
  BIO* bio = CHECK_OBJECT(1, BIO, "openssl.bio");
  BIO_reset(bio);
  return 0;
}

/* filter bio object */
static LUA_FUNCTION(openssl_bio_push)
{
  BIO* bio = CHECK_OBJECT(1, BIO, "openssl.bio");
  BIO* append = CHECK_OBJECT(2, BIO, "openssl.bio");
  bio = BIO_push(bio, append);
  if (bio)
    lua_pushvalue(L, 1);
  else
    lua_pushnil(L);
  return 1;
}

static LUA_FUNCTION(openssl_bio_pop)
{
  BIO* bio = CHECK_OBJECT(1, BIO, "openssl.bio");
  BIO* end = BIO_pop(bio);
  if (end == NULL)
  {
    lua_pushnil(L);
  }
  else
  {
    BIO_up_ref(end);
    PUSH_OBJECT(end, "openssl.bio");
  }
  return 1;
}

/* mem */
static LUA_FUNCTION(openssl_bio_get_mem)
{
  BIO* bio = CHECK_OBJECT(1, BIO, "openssl.bio");
  if (BIO_method_type(bio) == BIO_TYPE_MEM)
  {
    BUF_MEM* mem;
    BIO_get_mem_ptr(bio, &mem);
    lua_pushlstring(L, mem->data, mem->length);
    return 1;
  }
  luaL_error(L, "#1 BIO must be memory type");
  return 0;
}

/* network socket */

static LUA_FUNCTION(openssl_bio_accept)
{
  BIO* bio = CHECK_OBJECT(1, BIO, "openssl.bio");
  int first = lua_isnoneornil(L, 2) ? 0 : lua_toboolean(L, 2);
  int ret = BIO_do_accept(bio);
  if (ret == 1)
  {
    if (!first)
    {
      BIO *nb = BIO_pop(bio);

      PUSH_OBJECT(nb, "openssl.bio");
      openssl_newvalue(L, nb);

      lua_pushboolean(L, 1);
      openssl_setvalue(L, nb, "free_all");
      return 1;
    }
    else
      return openssl_pushresult(L, ret);
  }
  else
    luaL_error(L, "BIO_do_accept fail");

  return 0;
}

static LUA_FUNCTION(openssl_bio_shutdown)
{
  BIO* bio = CHECK_OBJECT(1, BIO, "openssl.bio");

  if (BIO_method_type(bio) & BIO_TYPE_SSL)
  {
    BIO_ssl_shutdown(bio);
  }
  else if (BIO_method_type(bio) & (BIO_TYPE_SOCKET | BIO_TYPE_FD))
  {
    BIO_shutdown_wr(bio);;
  }
  else
    luaL_error(L, "don't know how to shutdown");
  return 0;
}


static LUA_FUNCTION(openssl_bio_get_ssl)
{
  BIO* bio = CHECK_OBJECT(1, BIO, "openssl.bio");
  SSL* ssl = NULL;
  int ret = BIO_get_ssl(bio, &ssl);
  if (ret == 1)
  {
    openssl_newvalue(L, ssl);
    PUSH_OBJECT(ssl, "openssl.ssl");
    openssl_refrence(L, ssl, +1);
    return 1;
  }
  return 0;
}

static LUA_FUNCTION(openssl_bio_connect)
{
  BIO* bio = CHECK_OBJECT(1, BIO, "openssl.bio");
  int ret = BIO_do_connect(bio);
  return openssl_pushresult(L, ret);
}

static LUA_FUNCTION(openssl_bio_handshake)
{
  BIO* bio = CHECK_OBJECT(1, BIO, "openssl.bio");
  int ret = BIO_do_handshake(bio);
  return openssl_pushresult(L, ret);
}

static LUA_FUNCTION(openssl_bio_fd)
{
  BIO* bio = CHECK_OBJECT(1, BIO, "openssl.bio");
  int typ = BIO_method_type(bio);
  if (typ & BIO_TYPE_FD)
  {
    int fd = -1;
    if (!lua_isnoneornil(L, 2))
    {
      fd = lua_tointeger(L, 2);
      BIO_set_fd(bio, fd, BIO_NOCLOSE);
    }
    else
      fd = BIO_get_fd(bio, 0);
    lua_pushinteger(L, fd);
  }
  else
    luaL_error(L, "BIO type miss match");
  return 1;
}

void BIO_info_callback(BIO *bio, int cmd, const char *argp,
                       int argi, long argl, long ret)
{
  BIO *b;
  char buf[256];
  char *p;
  long r = 1;
  size_t p_maxlen;
  (void) argl;
  (void) argp;
  if (BIO_CB_RETURN & cmd)
    r = ret;

  BIO_snprintf(buf, sizeof buf, "BIO[%08lX]:", (unsigned long)bio);
  p = &(buf[14]);
  p_maxlen = sizeof buf - 14;
  switch (cmd)
  {
  case BIO_CB_FREE:
    BIO_snprintf(p, p_maxlen, "Free - %s\n", BIO_method_name(bio));
    break;
  case BIO_CB_READ:
    if (BIO_method_type(bio) & BIO_TYPE_DESCRIPTOR)
      BIO_snprintf(p, p_maxlen, "read(%d,%lu) - %s fd=%d\n",
                   BIO_number_read(bio), (unsigned long)argi,
                   BIO_method_name(bio), BIO_number_read(bio));
    else
      BIO_snprintf(p, p_maxlen, "read(%d,%lu) - %s\n",
                   BIO_number_read(bio), (unsigned long)argi,
                   BIO_method_name(bio));
    break;
  case BIO_CB_WRITE:
    if (BIO_method_type(bio) & BIO_TYPE_DESCRIPTOR)
      BIO_snprintf(p, p_maxlen, "write(%d,%lu) - %s fd=%d\n",
                   BIO_number_written(bio), (unsigned long)argi,
                   BIO_method_name(bio), BIO_number_written(bio));
    else
      BIO_snprintf(p, p_maxlen, "write(%d,%lu) - %s\n",
                   BIO_number_written(bio), (unsigned long)argi,
                   BIO_method_name(bio));
    break;
  case BIO_CB_PUTS:
    BIO_snprintf(p, p_maxlen, "puts() - %s\n", BIO_method_name(bio));
    break;
  case BIO_CB_GETS:
    BIO_snprintf(p, p_maxlen, "gets(%lu) - %s\n", (unsigned long)argi, BIO_method_name(bio));
    break;
  case BIO_CB_CTRL:
    BIO_snprintf(p, p_maxlen, "ctrl(%lu) - %s\n", (unsigned long)argi, BIO_method_name(bio));
    break;
  case BIO_CB_RETURN|BIO_CB_READ:
    BIO_snprintf(p, p_maxlen, "read return %ld\n", ret);
    break;
  case BIO_CB_RETURN|BIO_CB_WRITE:
    BIO_snprintf(p, p_maxlen, "write return %ld\n", ret);
    break;
  case BIO_CB_RETURN|BIO_CB_GETS:
    BIO_snprintf(p, p_maxlen, "gets return %ld\n", ret);
    break;
  case BIO_CB_RETURN|BIO_CB_PUTS:
    BIO_snprintf(p, p_maxlen, "puts return %ld\n", ret);
    break;
  case BIO_CB_RETURN|BIO_CB_CTRL:
    BIO_snprintf(p, p_maxlen, "ctrl return %ld\n", ret);
    break;
  default:
    BIO_snprintf(p, p_maxlen, "bio callback - unknown type (%d)\n", cmd);
    break;
  }

  b = (BIO *)BIO_get_callback_arg(bio);
  if (b != NULL)
    BIO_write(b, buf, strlen(buf));
#if !defined(OPENSSL_NO_STDIO) && !defined(OPENSSL_SYS_WIN16)
  else
    fputs(buf, stderr);
#endif
}

static LUA_FUNCTION(openssl_bio_set_callback)
{
  BIO* bio = CHECK_OBJECT(1, BIO, "openssl.bio");
  int ret;
  luaL_argcheck(L, lua_isfunction(L, 2), 2, "need function");
  lua_pushvalue(L, 2);
  lua_rawsetp(L, LUA_REGISTRYINDEX, bio);
  ret = BIO_set_info_callback(bio, BIO_info_callback);
  return openssl_pushresult(L, ret);
}

static LUA_FUNCTION(openssl_bio_pending)
{
  BIO* bio = CHECK_OBJECT(1, BIO, "openssl.bio");

  int pending = BIO_pending(bio);
  int wpending = BIO_wpending(bio);
  lua_pushinteger(L, pending);
  lua_pushinteger(L, wpending);
  return 2;
}

static luaL_Reg bio_funs[] =
{
  /* generate operation */
  {"read",  openssl_bio_read  },
  {"gets",  openssl_bio_gets  },
  {"write", openssl_bio_write },
  {"puts",  openssl_bio_puts  },
  {"flush", openssl_bio_flush },
  {"close", openssl_bio_free  },
  {"type",  openssl_bio_type  },
  {"nbio",  openssl_bio_nbio  },
  {"reset", openssl_bio_reset },
  {"retry", openssl_bio_retry },
  {"pending", openssl_bio_pending },
  {"set_callback", openssl_bio_set_callback },

  /* for filter bio */
  {"push",  openssl_bio_push  },
  {"pop",   openssl_bio_pop   },
  {"free",    openssl_bio_free},

  /* for mem */
  {"get_mem", openssl_bio_get_mem },

  /* network socket */
  {"accept",    openssl_bio_accept },
  {"connect",   openssl_bio_connect },
  {"handshake", openssl_bio_handshake },

  {"shutdown",  openssl_bio_shutdown},
  {"fd",        openssl_bio_fd },
  {"ssl",       openssl_bio_get_ssl},

  {"__tostring",  auxiliar_tostring },
  {"__gc",  openssl_bio_free  },

  {NULL,    NULL}
};

static luaL_Reg R[] =
{
  {"mem",     openssl_bio_new_mem    },
  {"socket",  openssl_bio_new_socket   },
  {"dgram",   openssl_bio_new_dgram    },
  {"fd",      openssl_bio_new_fd     },
  {"file",    openssl_bio_new_file   },
  {"filter",  openssl_bio_new_filter   },

  {"accept",    openssl_bio_new_accept },
  {"connect",   openssl_bio_new_connect},

  {"__call",    openssl_bio_new_mem},
  {NULL,    NULL}
};

int luaopen_bio(lua_State *L)
{
  auxiliar_newclass(L, "openssl.bio", bio_funs);

  lua_newtable(L);
  luaL_setfuncs(L, R, 0);
  lua_pushliteral(L, "version");    /** version */
  lua_pushliteral(L, MYVERSION);
  lua_settable(L, -3);

  return 1;
}

