/*=========================================================================*\
* x509 name routines
* lua-openssl toolkit
*
* This product includes PHP software, freely available from <http://www.php.net/software/>
* Author:  george zhao <zhaozg(at)gmail.com>
\*=========================================================================*/
#include "openssl.h"

int lo_lt2name(lua_State*L,
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