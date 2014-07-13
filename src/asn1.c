/*=========================================================================*\
* asn1.c
* asn1 routines for lua-openssl binding
*
* Author:  george zhao <zhaozg(at)gmail.com>
\*=========================================================================*/
#include "openssl.h"

#define MYNAME		"asn1"
#define MYVERSION	MYNAME " library for " LUA_VERSION " / Nov 2014 / "\
	"based on OpenSSL " SHLIB_VERSION_NUMBER
#define MYTYPE			"asn1"

/*** asn1_string routines ***/
const static char* string_type[] = {
	"integer",
	"enumerated",
	"bit",
	"octet",
	"utf8",

	"numeric",
	"printable",
	"t61",

	"teletex",
	"videotex",
	"ia5",
	"graphics",
	"iso64",
	"visible",
	"general",
	"unversal",
	"bmp",

	"utctime",

	NULL,
};

const int str_type[] = {
	V_ASN1_INTEGER,
	V_ASN1_ENUMERATED,
	V_ASN1_BIT_STRING,
	V_ASN1_OCTET_STRING,
	V_ASN1_UTF8STRING,

	V_ASN1_NUMERICSTRING,
	V_ASN1_PRINTABLESTRING,
	V_ASN1_T61STRING,

	V_ASN1_TELETEXSTRING,
	V_ASN1_VIDEOTEXSTRING,
	V_ASN1_IA5STRING,
	V_ASN1_GRAPHICSTRING,
	V_ASN1_ISO64STRING,
	V_ASN1_VISIBLESTRING,
	V_ASN1_GENERALSTRING,
	V_ASN1_UNIVERSALSTRING,
	V_ASN1_BMPSTRING,

	V_ASN1_UTCTIME,
	0
};

static int openssl_ans1string_length(lua_State* L){
	ASN1_STRING* s = CHECK_OBJECT(1,ASN1_STRING,"openssl.asn1_string");
	lua_pushinteger(L,ASN1_STRING_length(s));
	return 1;
}

static int openssl_ans1string_data(lua_State* L){
	ASN1_STRING* s = CHECK_OBJECT(1,ASN1_STRING,"openssl.asn1_string");
	if(lua_isnone(L,1))
		lua_pushlstring(L,(const char*)ASN1_STRING_data(s),ASN1_STRING_length(s));
	else{
		size_t l;
		const char*data = luaL_checklstring(L,2,&l);
		int ret = ASN1_STRING_set(s,data,l);
		lua_pushboolean(L,ret);
	}
	return 1;
}

static int openssl_ans1string_dup(lua_State* L){
	ASN1_STRING* s = CHECK_OBJECT(1,ASN1_STRING,"openssl.asn1_string");
	ASN1_STRING* ss = ASN1_STRING_dup(s);
	PUSH_OBJECT(ss,"openssl.asn1_string");
	return 1;
}

static int openssl_ans1string_toutf8(lua_State* L){
	ASN1_STRING* s = CHECK_OBJECT(1,ASN1_STRING,"openssl.asn1_string");
	unsigned char* out = NULL;
	int len =  ASN1_STRING_to_UTF8(&out, s);	
	lua_pushlstring(L,(const char*)out,len);
	OPENSSL_free(out);
	return 1;
}

static int openssl_ans1string_type(lua_State* L){
	ASN1_STRING* s = CHECK_OBJECT(1,ASN1_STRING,"openssl.asn1_string");
	int type = ASN1_STRING_type(s);
	int i;
	for(i=0; str_type[i] && str_type[i]!=type; i++);
	if(str_type[i])
		lua_pushstring(L, string_type[i]);
	else
		lua_pushnil(L);
	return 1;
}

static int openssl_ans1string_eq(lua_State* L){
	ASN1_STRING* s = CHECK_OBJECT(1,ASN1_STRING,"openssl.asn1_string");
	ASN1_STRING* ss = CHECK_OBJECT(2,ASN1_STRING,"openssl.asn1_string");
	if(ASN1_STRING_cmp(s,ss)==0)
		lua_pushboolean(L,1);
	else
		lua_pushboolean(L,0);
	return 1;
}

static int openssl_ans1string_free(lua_State* L){
	ASN1_STRING* s = CHECK_OBJECT(1,ASN1_STRING,"openssl.asn1_string");
	ASN1_STRING_free(s);
	return 0;
}

static int openssl_ans1string_tostring(lua_State* L){
	ASN1_STRING* s = CHECK_OBJECT(1,ASN1_STRING,"openssl.asn1_string");
	if(s){
		int type = ASN1_STRING_type(s);
		int i;
		for(i=0; str_type[i] && str_type[i]!=type; i++);

		if(str_type[i])
			lua_pushstring(L, string_type[i]);
		else
			lua_pushstring(L,"unknown");
		lua_pushstring(L,":");
		switch(type){
		case V_ASN1_INTEGER:
		case V_ASN1_BIT_STRING:
			{
				BIGNUM *bn = BN_bin2bn((const char*)ASN1_STRING_data(s),ASN1_STRING_length(s),NULL);
				const char* s = BN_bn2hex(bn);
				lua_pushstring(L,s);
				OPENSSL_free(s);
				break;
			}
		default:
			lua_pushlstring(L,(const char*)ASN1_STRING_data(s),ASN1_STRING_length(s));
			break;
		}


		lua_concat(L,3);
		return 1;
	}
	return 0;
}

static luaL_reg asn1str_funcs[] = {
	{"len",		openssl_ans1string_length	},
	{"__len",		openssl_ans1string_length	},

	{"data",		openssl_ans1string_data	},
	{"__tostring",	openssl_ans1string_tostring	},

	{"dup",		openssl_ans1string_dup	},
	{"toutf8",	openssl_ans1string_toutf8	},
	{"type",	openssl_ans1string_type	},
	{"__eq",	openssl_ans1string_eq	},
	{"equals",	openssl_ans1string_eq	},
	//{"__gc",	openssl_ans1string_free	},

	{NULL,		NULL}
};

/*** asn1_object routines ***/

static int openssl_ans1object_data(lua_State* L){
	ASN1_OBJECT* s = CHECK_OBJECT(1,ASN1_OBJECT,"openssl.asn1_object");
	BIO* bio = BIO_new(BIO_s_mem());
	BUF_MEM *buf;

	i2a_ASN1_OBJECT(bio,s);
	BIO_get_mem_ptr(bio, &buf);
	lua_pushlstring(L, buf->data, buf->length);
	BIO_free(bio);
	return 1;
}

static int openssl_ans1object_free(lua_State* L){
	ASN1_OBJECT* s = CHECK_OBJECT(1,ASN1_OBJECT,"openssl.asn1_object");
	ASN1_OBJECT_free(s);
	return 0;
}

static luaL_reg asn1obj_funcs[] = {
	{"data",		openssl_ans1object_data},
	//{"__gc",		openssl_ans1object_free},
	{"__tostring",	auxiliar_tostring},

	{NULL,		NULL}
};


/*** asn1_type object */

static int openssl_ans1type_free(lua_State* L){
	ASN1_TYPE* t = CHECK_OBJECT(1,ASN1_TYPE,"openssl.asn1_type");
	ASN1_TYPE_free(t);
	return 0;
}

static int openssl_asn1type_parse(lua_State *L)
{
	ASN1_TYPE* av = CHECK_OBJECT(1,ASN1_TYPE,"openssl.asn1_type");
	lua_newtable(L);

	switch(av->type) {
	case V_ASN1_BMPSTRING:
		{
#if OPENSSL_VERSION_NUMBER > 0x10000000L
			char *value = OPENSSL_uni2asc(av->value.bmpstring->data,av->value.bmpstring->length);
			AUXILIAR_SET(L,-1, "value", value,string);
			OPENSSL_free(value);
#else
			AUXILIAR_SETLSTR(L,-1,"value",
				(const char*)av->value.bmpstring->data,av->value.bmpstring->length);
#endif
			AUXILIAR_SET(L,-1, "type","bmpstring",string);
		}
		break;

	case V_ASN1_OCTET_STRING:
		AUXILIAR_SETLSTR(L,-1,"value",
			(const char *)av->value.octet_string->data, av->value.octet_string->length);
		AUXILIAR_SET(L,-1, "type","octet_string", string);
		break;

	case V_ASN1_BIT_STRING:
		AUXILIAR_SETLSTR(L,-1, "value",
			(const char *)av->value.bit_string->data, av->value.bit_string->length);

		AUXILIAR_SET(L,-1, "type","bit_string", string);
		break;

	default:
		AUXILIAR_SET(L,-1, "type", av->type, integer);
		AUXILIAR_SET(L,-1, "format", "der", string);

		{
			unsigned char* dat = NULL;
			int i = i2d_ASN1_TYPE(av,&dat);
			if(i>0) {
				AUXILIAR_SETLSTR(L,-1,"value",(const char *)dat,i);
				OPENSSL_free(dat);
			}
		}
	}
	return 1;
}
static luaL_reg asn1type_funcs[] = {
	{"parse",		openssl_asn1type_parse},
	{"__gc",		openssl_ans1type_free},
	{"__tostring",	auxiliar_tostring},

	{NULL,		NULL}
};

/*** modules function ***/
int openssl_push_ans1string_asstring(lua_State* L, ASN1_STRING* s){
	lua_pushlstring(L,(const char*)ASN1_STRING_data(s),ASN1_STRING_length(s));
	return 1;
}

static int openssl_ans1object_new(lua_State* L){
	ASN1_OBJECT* o = ASN1_OBJECT_new();
	PUSH_OBJECT(o,"openssl.asn1_object");
	return 1;
}

static int openssl_ans1string_new(lua_State* L){
	int type = auxiliar_checkoption(L, 1, "octet", string_type, str_type);
	ASN1_STRING* s = ASN1_STRING_type_new(type);
	PUSH_OBJECT(s,"openssl.asn1_string");
	return 1;
}

static luaL_reg R[] = {
	/*
	{"object_new",	openssl_ans1object_new},
	{"string_new",	openssl_ans1string_new	},
	*/

	{NULL,		NULL}
};

LUALIB_API int luaopen_asn1(lua_State *L)
{
	auxiliar_newclass(L,"openssl.asn1_object",asn1obj_funcs);
	auxiliar_newclass(L,"openssl.asn1_type", asn1type_funcs);
	auxiliar_newclass(L,"openssl.asn1_string",asn1str_funcs);
	

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
