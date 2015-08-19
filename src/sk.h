/*=========================================================================*\
* sk.h
* stack routines(MACRO) for lua-openssl binding
*
* Author:  george zhao <zhaozg(at)gmail.com>
\*=========================================================================*/

#include "openssl.h"

#ifdef CRYPTO_LOCK_REF
#define REF_OR_DUP(TYPE, x)  CRYPTO_add(&x->references,1,CRYPTO_LOCK_##TYPE)
#else
#define REF_OR_DUP(TYPE, x) x = TYPE##_dup(x)
#endif

#define TAB2SK(TYPE, type)                                        \
STACK_OF(TYPE)* sk_##type##_fromtable(lua_State*L, int idx) {     \
  STACK_OF(TYPE) * sk;                                            \
  luaL_argcheck(L, lua_isnoneornil(L, idx)||lua_istable(L, idx),  \
    idx, "must be a table as array or nil");                      \
  sk = SKM_sk_new_null(TYPE);                                     \
  if (lua_istable(L,idx)) {                                       \
    int n = lua_rawlen(L, idx);                                   \
    int i;                                                        \
    for ( i=0; i<n; i++ ) {                                       \
      TYPE *x;                                                    \
      lua_rawgeti(L, idx, i+1);                                   \
      x = CHECK_OBJECT(-1,TYPE,"openssl." #type);                 \
      REF_OR_DUP(TYPE, x);                                        \
      SKM_sk_push(TYPE, sk, x);                                   \
      lua_pop(L,1);                                               \
    }                                                             \
  }                                                               \
  return sk;                                                      \
}


#define SK2TAB(TYPE,type)  int _sk_##type##_totable(lua_State* L, STACK_OF(TYPE) *sk)  {  \
  int i=0, n=0;                                                                           \
  lua_newtable(L);                                                                        \
  n = SKM_sk_num(TYPE, sk);                                                               \
  for(i=0;i<n;i++) {                                                                      \
    TYPE *x =  SKM_sk_value(TYPE, sk, i);                                                 \
    REF_OR_DUP(TYPE, x);                                                                  \
    PUSH_OBJECT(x,"openssl."#type);                                                       \
    lua_rawseti(L,-2, i+1);                                                               \
  }                                                                                       \
  return 1;                                                                               \
}

#define SK_TOTABLE(TYPE, type) static int sk_##type##_totable(lua_State* L)  {    \
  STACK_OF(TYPE)* sk = CHECK_OBJECT(1, STACK_OF(TYPE), "openssl.stack_of_"#type); \
  return _sk_##type##_totable(L, sk);                                             \
}

#define SK_FREE(TYPE,type) static int sk_##type##_free(lua_State* L) {            \
  STACK_OF(TYPE)* sk = CHECK_OBJECT(1, STACK_OF(TYPE), "openssl.stack_of_"#type); \
  if (sk) {                                                                       \
    sk_##TYPE##_pop_free(sk, TYPE##_free);                                        \
  }                                                                               \
  return 0;                                                                       \
}


#define SK_PUSH(TYPE, type) static int sk_##type##_push(lua_State* L) {           \
  STACK_OF(TYPE) * sk = CHECK_OBJECT(1,STACK_OF(TYPE), "openssl.stack_of_"#type); \
  TYPE* x = CHECK_OBJECT(2,TYPE, "openssl."#type);                                \
  REF_OR_DUP(TYPE, x);                                                            \
  SKM_sk_push(TYPE, sk, x);                                                       \
  lua_pushvalue(L,1);                                                             \
  return 1;                                                                       \
}

#define SK_POP(TYPE, type) static int sk_##type##_pop(lua_State*L) {                  \
  STACK_OF(TYPE) * certs = CHECK_OBJECT(1,STACK_OF(TYPE), "openssl.stack_of_"#type);  \
  TYPE* cert = SKM_sk_pop(TYPE,certs);                                                \
  PUSH_OBJECT(cert,"openssl."#type);                                                  \
  return 1;                                                                           \
}

#define SK_INSERT(TYPE, type) static int sk_##type##_insert(lua_State*L) {          \
  STACK_OF(TYPE) * st = CHECK_OBJECT(1, STACK_OF(TYPE), "openssl.stack_of_"#type);  \
  TYPE* x = CHECK_OBJECT(2,TYPE, "openssl."#type);                                  \
  int i = luaL_checkint(L,3);                                                       \
  i = openssl_sk_index(L, i, SKM_sk_num(TYPE, st), 3);                              \
  REF_OR_DUP(TYPE, x);                                                              \
  SKM_sk_insert(TYPE,st,x,i);                                                       \
  lua_pushvalue(L,1);                                                               \
  return 1;                                                                         \
}


#define SK_DELETE(TYPE, type) static int sk_##type##_delete(lua_State*L) {          \
  STACK_OF(TYPE) * st = CHECK_OBJECT(1, STACK_OF(TYPE), "openssl.stack_of_"#type);  \
  TYPE *val;                                                                        \
  int i = luaL_checkint(L,2);                                                       \
  i = openssl_sk_index(L, i, SKM_sk_num(TYPE, st), 2);                              \
  val = SKM_sk_delete(TYPE,st,i);                                                   \
  PUSH_OBJECT(val,"openssl."#type);                                                 \
  return 1;                                                                         \
}

#define SK_SET(TYPE, type)  static int sk_##type##_set(lua_State*L) {               \
  STACK_OF(TYPE) * st = CHECK_OBJECT(1, STACK_OF(TYPE), "openssl.stack_of_"#type);  \
  TYPE* x = CHECK_OBJECT(2,TYPE, "openssl."#type);                                  \
  int i = luaL_checkint(L,3);                                                       \
  i = openssl_sk_index(L, i, SKM_sk_num(TYPE, st), 3);                              \
  REF_OR_DUP(TYPE, x);                                                              \
  SKM_sk_set(TYPE, st, i, x);                                                       \
  lua_pushvalue(L,1);                                                               \
  return 1;                                                                         \
}

#define SK_GET(TYPE, type)  static int sk_##type##_get(lua_State*L) {               \
  STACK_OF(TYPE) * st = CHECK_OBJECT(1, STACK_OF(TYPE), "openssl.stack_of_"#type);  \
  TYPE *x;                                                                          \
  int i = luaL_checkint(L,2);                                                       \
  i = openssl_sk_index(L, i, SKM_sk_num(TYPE, st), 2);                              \
  x = SKM_sk_value(TYPE, st, i);                                                    \
  REF_OR_DUP(TYPE, x);                                                              \
  PUSH_OBJECT(x,"openssl."#type);                                                   \
  return 1;                                                                         \
}

#define SK_LENGTH(TYPE, type)  static int sk_##type##_length(lua_State*L) {         \
  STACK_OF(TYPE) * st = CHECK_OBJECT(1, STACK_OF(TYPE), "openssl.stack_of_"#type);  \
  lua_pushinteger(L, SKM_sk_num(TYPE, st));                                         \
  return 1;                                                                         \
}

#define SK_SORT(TYPE, type)  static int sk_##type##_sort(lua_State*L) {             \
  STACK_OF(TYPE) * st = CHECK_OBJECT(1, STACK_OF(TYPE), "openssl.stack_of_"#type);  \
  SKM_sk_sort(TYPE, st);                                                            \
  return 0;                                                                         \
}

#define SK_SORTED(TYPE, type)  static int sk_##type##_sorted(lua_State*L) {         \
  STACK_OF(TYPE) * st = CHECK_OBJECT(1, STACK_OF(TYPE), "openssl.stack_of_"#type);  \
  lua_pushboolean(L, SKM_sk_is_sorted(TYPE,st));                                    \
  return 1;                                                                         \
}

#define SK_DUP(TYPE, type) STACK_OF(TYPE)* openssl_sk_##type##_dup(STACK_OF(TYPE)* sk) {     \
  STACK_OF(TYPE)* s = sk_##TYPE##_new_null();       \
  int i;                                            \
  for(i=0; i<sk_##TYPE##_num(sk); i++) {            \
  TYPE* x = sk_##TYPE##_value(sk,i);                \
  REF_OR_DUP(TYPE,x);                               \
  sk_##TYPE##_push(s,x);                            \
  }                                                 \
  return s;                                         \
}

#define IMP_LUA_SK(TYPE,type)   \
TAB2SK(TYPE,type);              \
SK2TAB(TYPE,type);              \
                                \
SK_TOTABLE(TYPE,type);          \
SK_FREE(TYPE,type);             \
SK_PUSH(TYPE,type);             \
SK_POP(TYPE,type);              \
SK_INSERT(TYPE,type);           \
SK_DELETE(TYPE,type);           \
SK_SET(TYPE,type);              \
SK_GET(TYPE,type);              \
SK_LENGTH(TYPE,type);           \
SK_SORT(TYPE,type);             \
SK_SORTED(TYPE,type);           \
SK_DUP(TYPE, type)              \
                                \
static luaL_Reg sk_##type##_funcs[] = {   \
  {"push",  sk_##type##_push },           \
  {"pop",   sk_##type##_pop },            \
  {"set",   sk_##type##_set },            \
  {"get",   sk_##type##_get },            \
  {"insert",  sk_##type##_insert },       \
  {"delete",  sk_##type##_delete },       \
  {"sort",  sk_##type##_sort },           \
  {"sorted",  sk_##type##_sorted },       \
  {"totable", sk_##type##_totable},       \
  {"parse", sk_##type##_totable},         \
  {"__len", sk_##type##_length },         \
  {"__tostring",  auxiliar_tostring },    \
  {"__gc",  sk_##type##_free },           \
  {NULL,    NULL}                         \
};                                        \
                                                    \
int openssl_sk_##type##_new(lua_State*L) {          \
  STACK_OF(TYPE) * sk = sk_##type##_fromtable(L,1); \
  PUSH_OBJECT(sk,"openssl.stack_of_"#type);         \
  return 1;                                         \
}                                                   \
                                                                    \
int openssl_register_sk_##type(lua_State*L) {                       \
  auxiliar_newclass(L,"openssl.stack_of_"#type, sk_##type##_funcs); \
  return 0;                                                         \
}                                                                   \

#define DEF_LUA_SK(TYPE,type)               \
int openssl_sk_##type##_new(lua_State*L);   \
int openssl_register_sk_##type(lua_State*L)

