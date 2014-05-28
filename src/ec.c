/*=========================================================================*\
* ec routines
* lua-openssl toolkit
*
* Author:  george zhao <zhaozg(at)gmail.com>
\*=========================================================================*/
#include "openssl.h"

#define lua_boxpointer(L,u) \
	(*(void **)(lua_newuserdata(L, sizeof(void *))) = (u))

#define PUSH_BN(x) \
lua_boxpointer(L,x);	\
luaL_getmetatable(L,"openssl.bn");	\
lua_setmetatable(L,-2);


#ifndef OPENSSL_NO_EC

static int openssl_ecpoint_affine_coordinates(lua_State *L){
	EC_GROUP* g = CHECK_OBJECT(1,EC_GROUP,"openssl.ec_group");
	EC_POINT* p = CHECK_OBJECT(2,EC_POINT,"openssl.ec_point");
	BN_CTX* ctx = BN_CTX_new();
	if(lua_gettop(L)==2){
		BIGNUM* x = BN_new();
		BIGNUM* y = BN_new();
		if(EC_POINT_get_affine_coordinates_GFp(g, p, x, y, ctx)==1)
		{
			PUSH_BN(x);
			PUSH_BN(y);
			BN_CTX_free(ctx);
			return 2;
		};
	}else{
		BIGNUM* x = CHECK_OBJECT(3,BIGNUM,"openssl.bn");
		BIGNUM* y = CHECK_OBJECT(4,BIGNUM,"openssl.bn");
		int ret = EC_POINT_set_affine_coordinates_GFp(g,p,x,y,ctx);
		BN_CTX_free(ctx);
		if(ret!=-1)
			luaL_error(L,"EC_POINT_set_affine_coordinates_GFp fail");
	}
	return 0;
}

static int openssl_eckey_group(lua_State *L){
	int nid = NID_undef;
	const EC_GROUP* g = NULL;
	if(lua_isnumber(L,1))
		nid = lua_tointeger(L,1);
	else if(lua_isstring(L,1))
	{
		const char* name = luaL_checkstring(L, 1);
		nid = OBJ_sn2nid(name);
	}else if(lua_isuserdata(L, 1)){
		if(auxiliar_isclass(L,"openssl.evp_pkey",1)){
			EVP_PKEY* pkey = CHECK_OBJECT(1,EVP_PKEY,"openssl.evp_pkey");
			EC_KEY* ec_key = EVP_PKEY_get1_EC_KEY(pkey);
			g = EC_KEY_get0_group(ec_key);
		}else if(auxiliar_isclass(L,"openssl.ec_key",1)){
			EC_KEY* ec_key = CHECK_OBJECT(1,EC_KEY,"openssl.ec_key");
			g = EC_KEY_get0_group(ec_key);
		}
	}
	if(nid!=NID_undef)
		g = EC_GROUP_new_by_curve_name(nid);

	if(g){
		const EC_POINT* p = EC_GROUP_get0_generator(g);
		PUSH_OBJECT(g,"openssl.ec_group");
		PUSH_OBJECT(p,"openssl.ec_point");
		return 2;
	}
	return 0;
};

#define OPENSSL_PKEY_GET_BN(bn, _name)  if (bn != NULL) {	\
	char *str = BN_bn2hex(bn);	\
	lua_pushstring(L,str);									\
	lua_setfield(L,-2,#_name);									\
	OPENSSL_free(str);									\
}
static int openssl_ec_group_parse(lua_State*L)
{
	const EC_GROUP* group = CHECK_OBJECT(1,EC_GROUP,"openssl.ec_group");
	const EC_POINT *generator = EC_GROUP_get0_generator(group);
	BN_CTX* ctx = BN_CTX_new();
	BIGNUM *X, *Y, *P, *order,*cofactor;

	lua_newtable(L);
	if(generator)
	{
		PUSH_OBJECT(generator,"openssl.ec_point");
		lua_setfield(L, -2, "generator");
	}

	order = BN_new();
	EC_GROUP_get_order(group,order,ctx);
	PUSH_OBJECT(order,"openssl.bn");
	lua_setfield(L, -2, "order");

	cofactor = BN_new();
	EC_GROUP_get_cofactor(group,cofactor,ctx);
	PUSH_OBJECT(cofactor,"openssl.bn");
	lua_setfield(L, -2, "cofactor");

	lua_pushinteger(L, EC_GROUP_get_asn1_flag(group));
	lua_setfield(L, -2, "asn1_flag");

	lua_pushinteger(L, EC_GROUP_get_degree(group));
	lua_setfield(L, -2, "degree");

	lua_pushlstring(L,EC_GROUP_get0_seed(group),EC_GROUP_get_seed_len(group));
	lua_setfield(L,-2,"seed");

	lua_pushinteger(L,EC_GROUP_get_curve_name(group));
	lua_setfield(L,-2,"curve_name");

	lua_pushinteger(L,EC_GROUP_get_point_conversion_form(group));
	lua_setfield(L,-2,"conversion_form");

	
	
	X = BN_new();
	Y = BN_new();
	P = BN_new();
	EC_GROUP_get_curve_GFp(group, P,X,Y,ctx);
	lua_newtable(L);
	{
		PUSH_OBJECT(P,"openssl.bn");
		lua_setfield(L, -2, "P");
		PUSH_OBJECT(X,"openssl.bn");
		lua_setfield(L, -2, "X");
		PUSH_OBJECT(Y,"openssl.bn");
		lua_setfield(L, -2, "Y");
	}
	lua_setfield(L,-2,"curve");
	BN_CTX_free(ctx);
	return 1;
}

static luaL_Reg ec_group_funs[] = {
	{"__tostring", auxiliar_tostring},
	{"affine_coordinates", openssl_ecpoint_affine_coordinates},
	{"parse", openssl_ec_group_parse},
	
	{ NULL, NULL }
};


static int openssl_ecdsa_sign(lua_State*L){
	EC_KEY* ec = CHECK_OBJECT(1,EC_KEY, "openssl.ec_key");
	size_t l;
	const char* s = luaL_checklstring(L,2,&l);
	ECDSA_SIG* sig = ECDSA_do_sign(s,l,ec);
	if(sig){
		PUSH_BN(BN_dup(sig->r));
		PUSH_BN(BN_dup(sig->s));
		ECDSA_SIG_free(sig);
		return 2;
	}
	return 0;
}

static int openssl_ecdsa_verify(lua_State*L){
	EC_KEY* ec = CHECK_OBJECT(1,EC_KEY, "openssl.ec_key");
	size_t l;
	const char* dgst = luaL_checklstring(L,2,&l);
	ECDSA_SIG* sig = ECDSA_SIG_new();
	BIGNUM *r,*s;
	int ret;
	r = CHECK_OBJECT(3,BIGNUM,"openssl.bn");
	s = CHECK_OBJECT(4,BIGNUM,"openssl.bn");
	BN_copy(sig->r,r);
	BN_copy(sig->s,s);

	ret = ECDSA_do_verify(dgst,l,sig,ec);
	if(ret==-1)
		lua_pushnil(L);
	else
		lua_pushboolean(L,ret);
	ECDSA_SIG_free(sig);
	return 1;
}

static luaL_Reg ec_key_funs[] = {
	{"__tostring", auxiliar_tostring},
	{"sign", openssl_ecdsa_sign},
	{"verify", openssl_ecdsa_verify},

	{ NULL, NULL }
};

static luaL_Reg ec_point_funs[] = {
	{"__tostring", auxiliar_tostring},

	{ NULL, NULL }
};

int openssl_register_ec(lua_State* L)
{
	auxiliar_newclass(L,"openssl.ec_point",		ec_point_funs);
	auxiliar_newclass(L,"openssl.ec_group",		ec_group_funs);
	auxiliar_newclass(L,"openssl.ec_key",		ec_key_funs);
	
	return 0;
};

#endif

