/* vim: set filetype=c : */

#ifndef EC_GROUP_POINT_H
#define EC_GROUP_POINT_H

#include "openssl.h"
#include "private.h"

#if !defined(OPENSSL_NO_EC)

/* Helper functions for ASN1 flags and conversion forms */
int openssl_to_group_asn1_flag(lua_State *L, int i, const char *defval);
int openssl_push_group_asn1_flag(lua_State *L, int flag);
point_conversion_form_t openssl_to_point_conversion_form(lua_State *L, int i, const char *defval);
int openssl_push_point_conversion_form(lua_State *L, point_conversion_form_t form);

/* EC_GROUP functions exported from group.c */
int openssl_group_parse(lua_State *L);
int openssl_group_free(lua_State *L);
int openssl_group_asn1_flag(lua_State *L);
int openssl_group_point_conversion_form(lua_State *L);
int openssl_group_equal(lua_State *L);
int openssl_group_point_new(lua_State *L);
int openssl_group_point_dup(lua_State *L);
int openssl_group_point_equal(lua_State *L);
int openssl_group_point2oct(lua_State *L);
int openssl_group_oct2point(lua_State *L);
int openssl_group_point2bn(lua_State *L);
int openssl_group_bn2point(lua_State *L);
int openssl_group_point2hex(lua_State *L);
int openssl_group_hex2point(lua_State *L);
int openssl_group_affine_coordinates(lua_State *L);
int openssl_group_generate_key(lua_State *L);

/* EC_POINT functions exported from point.c */
int openssl_point_copy(lua_State *L);
int openssl_point_free(lua_State *L);

#endif /* OPENSSL_NO_EC */

#endif /* EC_GROUP_POINT_H */
