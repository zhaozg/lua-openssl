/*=========================================================================*\
* xname.c
* * x509 name routines for lua-openssl binding
*
* Author:  george zhao <zhaozg(at)gmail.com>
\*=========================================================================*/

#include "openssl.h"
#include "compat.h"

int XNAME_from_ltable(lua_State*L,
    X509_NAME* name,
    int dn)
{
    /* table is in the stack at index 't' */
    lua_pushnil(L);  /* first key */
    while (lua_next(L, dn) != 0) {
        /* uses 'key' (at index -2) and 'value' (at index -1) */
        const char * strindex = lua_tostring(L,-2);
        const char * strval = lua_tostring(L,-1);

        if (strindex) {
            int nid = OBJ_txt2nid(strindex);
            if (nid != NID_undef) {
                if (!X509_NAME_add_entry_by_NID(name, nid, MBSTRING_ASC, (unsigned char*)strval, -1, -1, 0))
                {
                    luaL_error(L, "dn: add_entry_by_NID %d(%s) -> %s (failed)", nid, strindex, strval);
                }
            } else {
                luaL_error(L, "dn: %s is not a recognized name", strindex);
            }
        }
        /* removes 'value'; keeps 'key' for next iteration */
        lua_pop(L, 1);
    }
    return 0;
}

int XNAME_to_ltable(lua_State*L, X509_NAME * xname,int idx, int shortname){
	int i;
	int n = X509_NAME_entry_count(xname);
	for (i = 0; i < n; i++) {
        X509_NAME_ENTRY* ne = X509_NAME_get_entry(xname, i);
        ASN1_OBJECT * obj = X509_NAME_ENTRY_get_object(ne);
		ASN1_STRING * str = X509_NAME_ENTRY_get_data(ne);
        int nid = OBJ_obj2nid(obj);
		const char* name = shortname ? OBJ_nid2sn(nid) : OBJ_nid2ln(nid);

		lua_pushlstring(L, ASN1_STRING_data(str), ASN1_STRING_length(str));
		lua_setfield(L, idx, name);

		lua_pushstring(L,name);
		lua_rawseti(L, idx, i+1);
    }
	return i;
}

void add_assoc_name_entry(lua_State*L,const  char * key, X509_NAME * xname, int shortname)  
{
	char* p = X509_NAME_oneline(xname,NULL,0);
    lua_newtable(L);

	lua_pushstring(L, p);
	lua_rawseti(L, -2, 0);

	XNAME_to_ltable(L,xname, lua_absindex(L, -1), shortname);
    OPENSSL_free(p);
	
    if (key != NULL) {
        lua_setfield(L,-2,key);
    }
}
