/* 
$Id:$ 
$Revision:$
*/

#include "openssl.h"

#define TAB2SK(TYPE, type) \
STACK_OF(TYPE)* sk_##type##_fromtable(lua_State*L, int idx) { \
	if (lua_istable(L,idx)) { \
		STACK_OF(TYPE) * sk = SKM_sk_new_null(TYPE); \
		int n = lua_objlen(L, idx); \
		int i; \
		for ( i=0; i<n; i++ ) { \
			TYPE *x;	\
			lua_rawgeti(L, idx, i+1);  \
			x = CHECK_OBJECT(-1,TYPE,"openssl." #type);  \
			SKM_sk_push(TYPE, sk, x); \
			sk_X509_push(sk,x); \
			lua_pop(L,1); \
		} \
		return sk;  \
	} \
	return NULL; \
}


#define SK2TAB(TYPE,type)  int _sk_##type##_totable(lua_State* L, STACK_OF(TYPE) *sk)  { \
	int i=0, n=0;  \
    lua_newtable(L); \
	n = SKM_sk_num(TYPE, sk); \
	for(i=0;i<n;i++) { \
		TYPE *x =  SKM_sk_value(TYPE, sk, i); \
		PUSH_OBJECT(TYPE##_dup(x),"openssl."#type); \
		lua_rawseti(L,-2, i+1); \
	}  \
	return 1; \
}

#define SK_TOTABLE(TYPE, type) static int sk_##type##_totable(lua_State* L)  { \
	STACK_OF(TYPE)* sk = CHECK_OBJECT(1, STACK_OF(TYPE), "openssl.stack_of_"#type); \
	return _sk_##type##_totable(L, sk);      \
}

#define SK_FREE(TYPE,type) static int sk_##type##_free(lua_State* L) { \
	STACK_OF(TYPE)* sk = CHECK_OBJECT(1, STACK_OF(TYPE), "openssl.stack_of_"#type); \
	SKM_sk_free(TYPE, sk); \
	return 0; \
}

#define SK_TOSTRING(TYPE, type) static int sk_##type##_tostring(lua_State* L) { \
	STACK_OF(TYPE)* sk = CHECK_OBJECT(1, STACK_OF(TYPE), "openssl.stack_of_"#type); \
	lua_pushfstring(L,"openssl.stack_of_"#type":%p",sk); \
	return 1; \
}

#define SK_PUSH(TYPE, type) static int sk_##type##_push(lua_State* L) { \
	STACK_OF(TYPE) * sk = CHECK_OBJECT(1,STACK_OF(TYPE), "openssl.stack_of_"#type); \
	TYPE* val = CHECK_OBJECT(2,TYPE, "openssl."#type);  \
	SKM_sk_push(TYPE, sk, val); \
	lua_pushvalue(L,1);  \
	return 1;   \
}

#define SK_POP(TYPE, type) static int sk_##type##_pop(lua_State*L) { \
	STACK_OF(TYPE) * certs = CHECK_OBJECT(1,STACK_OF(TYPE), "openssl.stack_of_"#type); \
	TYPE* cert = sk_X509_pop(certs);    \
	PUSH_OBJECT(cert,"openssl."#type); \
	return 1;   \
}

#define SK_INSERT(TYPE, type) static int sk_##type##_insert(lua_State*L) { \
	STACK_OF(TYPE) * st = CHECK_OBJECT(1, STACK_OF(TYPE), "openssl.stack_of_"#type); \
	TYPE* val = CHECK_OBJECT(2,TYPE, "openssl."#type); \
	int i = luaL_checkint(L,3); \
	sk_X509_insert(st,val,i);  \
	lua_pushvalue(L,1);  \
	return 1;  \
}


#define SK_DELETE(TYPE, type) static int sk_##type##_delete(lua_State*L) { \
	STACK_OF(TYPE) * st = CHECK_OBJECT(1, STACK_OF(TYPE), "openssl.stack_of_"#type); \
	int i = luaL_checkint(L,2);	\
	TYPE* val = sk_X509_delete(st,i); \
	PUSH_OBJECT(st,"openssl."#type); \
	return 1;  \
}

#define SK_SET(TYPE, type)  static int sk_##type##_set(lua_State*L) { \
	STACK_OF(TYPE) * st = CHECK_OBJECT(1, STACK_OF(TYPE), "openssl.stack_of_"#type); \
	TYPE* val = CHECK_OBJECT(2,TYPE, "openssl."#type);  \
	int i = luaL_checkint(L,3);   \
	SKM_sk_set(TYPE, st, i, val); \
	lua_pushvalue(L,1);  \
	return 1;   \
}

#define SK_GET(TYPE, type)  static int sk_##type##_get(lua_State*L) { \
	STACK_OF(TYPE) * st = CHECK_OBJECT(1, STACK_OF(TYPE), "openssl.stack_of_"#type); \
	int i = luaL_checkint(L,2);  \
	TYPE *x = SKM_sk_value(TYPE, st, i); \
	PUSH_OBJECT(TYPE##_dup(x),"openssl."#type);  \
	return 1;  \
}

#define SK_LENGTH(TYPE, type)  static int sk_##type##_length(lua_State*L) { \
	STACK_OF(TYPE) * st = CHECK_OBJECT(1, STACK_OF(TYPE), "openssl.stack_of_"#type); \
	lua_pushinteger(L, SKM_sk_num(TYPE, st));  \
	return 1; \
}

#define SK_SORT(TYPE, type)  static int sk_##type##_sort(lua_State*L) { \
	STACK_OF(TYPE) * st = CHECK_OBJECT(1, STACK_OF(TYPE), "openssl.stack_of_"#type); \
	SKM_sk_sort(TYPE, st); \
	return 0;  \
}

#define SK_SORTED(TYPE, type)  static int sk_##type##_sorted(lua_State*L) { \
	STACK_OF(TYPE) * st = CHECK_OBJECT(1, STACK_OF(TYPE), "openssl.stack_of_"#type); \
	lua_pushboolean(L, SKM_sk_is_sorted(TYPE,st)); \
	return 1; \
}


#define IMP_LUA_SK(TYPE,type) \
TAB2SK(TYPE,type); \
SK2TAB(TYPE,type);	\
	\
SK_TOTABLE(TYPE,type);	\
SK_FREE(TYPE,type);	\
SK_TOSTRING(TYPE,type);	\
SK_PUSH(TYPE,type);	\
SK_POP(TYPE,type);	\
SK_INSERT(TYPE,type);	\
SK_DELETE(TYPE,type);	\
SK_SET(TYPE,type);	\
SK_GET(TYPE,type);	\
SK_LENGTH(TYPE,type);	\
SK_SORT(TYPE,type); \
SK_SORTED(TYPE,type); \
\
\
static luaL_Reg sk_##type##_funcs[] = { \
	{"push",	sk_##type##_push },  \
	{"pop",		sk_##type##_pop },	\
	{"set",		sk_##type##_set },	\
	{"get",		sk_##type##_get },	\
	{"insert",	sk_##type##_insert },	\
	{"delete",	sk_##type##_delete },	\
	{"sort",	sk_##type##_sort },		\
	{"sorted",	sk_##type##_sorted },		\
	{"totable",	sk_##type##_totable},	\
	{"parse",	sk_##type##_totable},	\
	{"__len",	sk_##type##_length },	\
	{"__tostring",	sk_##type##_tostring },	\
	{"__gc",		sk_##type##_free },		\
	{NULL,		NULL}	\
}; \
\
int openssl_sk_##type##_new(lua_State*L) { \
	STACK_OF(TYPE) * sk = sk_##type##_fromtable(L,1); \
	PUSH_OBJECT(sk,"openssl.stack_of_"#type); \
	return 1; \
} \
\
int openssl_register_sk_##type(lua_State*L) { \
	auxiliar_newclass(L,"openssl.stack_of_"#type, sk_##type##_funcs); \
	return 0;  \
};

/************************************************************************/
/*                                                                      */
/************************************************************************/
