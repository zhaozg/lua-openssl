/* 
$Id:$ 
$Revision:$
*/

#include "openssl.h"



static STACK_OF(X509) * load_all_certs_from_file(const char *certfile)
{
	STACK_OF(X509_INFO) *sk=NULL;
	STACK_OF(X509) *stack=NULL, *ret=NULL;
	BIO *in=NULL;
	X509_INFO *xi;

	if(!(stack = sk_X509_new_null())) {
		printf("memory allocation -1");
		goto end;
	}

	if(!(in=BIO_new_file(certfile, "r"))) {
		printf("error opening the file, %s", certfile);
		sk_X509_free(stack);
		goto end;
	}

	/* This loads from a file, a stack of x509/crl/pkey sets */
	if(!(sk=PEM_X509_INFO_read_bio(in, NULL, NULL, NULL))) {
		printf("error reading the file, %s", certfile);
		sk_X509_free(stack);
		goto end;
	}

	/* scan over it and pull out the certs */
	while (sk_X509_INFO_num(sk)) {
		xi=sk_X509_INFO_shift(sk);
		if (xi->x509 != NULL) {
			sk_X509_push(stack,xi->x509);
			xi->x509=NULL;
		}
		X509_INFO_free(xi);
	}
	if(!sk_X509_num(stack)) {
		printf("no certificates in file, %s", certfile);
		sk_X509_free(stack);
		goto end;
	}
	ret=stack;
end:
	BIO_free(in);
	sk_X509_INFO_free(sk);

	return ret;
}


int openssl_sk_x509_read(lua_State*L) {
	const char* file = luaL_checkstring(L,1);
	STACK_OF(X509) * certs = load_all_certs_from_file(file);
	if (certs) {
		PUSH_OBJECT(certs, "openssl.stack_of_x509");
	}else
		lua_pushnil(L);
	return 1;
}

int openssl_sk_x509_new(lua_State*L) {
	int top = lua_gettop(L);
	STACK_OF(X509) * sk = sk_X509_new_null();
	if(top>0 && lua_istable(L,1))
	{
		lua_pushnil(L);
		while(lua_next(L,1))
		{
			X509* x = CHECK_OBJECT(-1,X509,"openssl.x509");
			sk_X509_push(sk,x);
			lua_pop(L,1);
		}
	}
	PUSH_OBJECT(sk,"openssl.stack_of_x509");
	return 1;
}

int openssl_sk_x509_free(lua_State*L) {
	STACK_OF(X509) * certs = CHECK_OBJECT(1,STACK_OF(X509), "openssl.stack_of_x509");
	sk_X509_free(certs);
	return 1;
}

int openssl_sk_x509_tostring(lua_State*L) {
	STACK_OF(X509) * certs = CHECK_OBJECT(1,STACK_OF(X509), "openssl.stack_of_x509");
	lua_pushfstring(L, "openssl.stack_of_x509:%p");
	return 1;
}


int openssl_sk_x509_push(lua_State*L) {
	STACK_OF(X509) * certs = CHECK_OBJECT(1,STACK_OF(X509), "openssl.stack_of_x509");
	X509* cert = CHECK_OBJECT(2,X509, "openssl.x509");
	sk_X509_push(certs,cert);
	lua_pushvalue(L,1);
	return 1;
}

int openssl_sk_x509_pop(lua_State*L) {
	STACK_OF(X509) * certs = CHECK_OBJECT(1,STACK_OF(X509), "openssl.stack_of_x509");
	X509* cert = sk_X509_pop(certs);
	PUSH_OBJECT(cert,"openssl.x509");
	return 1;
}

int openssl_sk_x509_insert(lua_State*L) {
	STACK_OF(X509) * certs = CHECK_OBJECT(1,STACK_OF(X509), "openssl.stack_of_x509");
	X509* cert = CHECK_OBJECT(2,X509, "openssl.x509");
	int i = luaL_checkint(L,3);

	sk_X509_insert(certs,cert,i);
	lua_pushvalue(L,1);
	return 1;
}


int openssl_sk_x509_delete(lua_State*L) {
	STACK_OF(X509) * certs = CHECK_OBJECT(1,STACK_OF(X509), "openssl.stack_of_x509");
	int i = luaL_checkint(L,2);

	X509* cert = sk_X509_delete(certs,i);

	PUSH_OBJECT(cert,"openssl.x509");
	return 1;

}

int openssl_sk_x509_set(lua_State*L) {
	STACK_OF(X509) * certs = CHECK_OBJECT(1,STACK_OF(X509), "openssl.stack_of_x509");
	X509* cert = CHECK_OBJECT(2,X509, "openssl.x509");
	int i = luaL_checkint(L,3);

	sk_X509_set(certs,i,cert);
	lua_pushvalue(L,1);
	return 1;
}

int openssl_sk_x509_get(lua_State*L) {
	STACK_OF(X509) * certs = CHECK_OBJECT(1,STACK_OF(X509), "openssl.stack_of_x509");
	int i = luaL_checkint(L,2);
	X509 *x = sk_X509_value(certs,i);

	PUSH_OBJECT(x,"openssl.x509");
	return 1;
}

int openssl_sk_x509_length(lua_State*L) {
	STACK_OF(X509) * certs = CHECK_OBJECT(1,STACK_OF(X509), "openssl.stack_of_x509");
	lua_pushinteger(L, sk_X509_num(certs));
	return 1;
}

int openssl_sk_x509_sort(lua_State*L)
{
	STACK_OF(X509) * certs = CHECK_OBJECT(1,STACK_OF(X509), "openssl.stack_of_x509");
	sk_X509_sort(certs);
	return 0;
}

int openssl_sk_x509_totable(lua_State*L)
{
	STACK_OF(X509) * certs = CHECK_OBJECT(1,STACK_OF(X509), "openssl.stack_of_x509");
	int n = sk_X509_num(certs);
	int i=0;
	lua_newtable(L);
	for(i=0;i<n;i++)
	{
		X509 *x = sk_X509_value(certs,i);
		PUSH_OBJECT(x,"openssl.x509");
		lua_rawseti(L,-2, i+1);
	}
	return 1;
}

static luaL_Reg sk_x509_funcs[] = {
	{"push",	openssl_sk_x509_push },
	{"pop",		openssl_sk_x509_pop },

	{"set",		openssl_sk_x509_set },
	{"get",		openssl_sk_x509_get },

	{"insert",	openssl_sk_x509_insert },
	{"delete",	openssl_sk_x509_delete },

	{"sort",	openssl_sk_x509_sort },
	{"totable",	openssl_sk_x509_totable},

	{"__length",openssl_sk_x509_length },
	{"__tostring",	openssl_sk_x509_tostring },
	{"__gc",	openssl_sk_x509_free },
	{NULL,		NULL}
};

int openssl_register_sk_x509(lua_State*L)
{
	auxiliar_newclass(L,"openssl.stack_of_x509", sk_x509_funcs);
	return 0;
}
