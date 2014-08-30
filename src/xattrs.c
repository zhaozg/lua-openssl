/*=========================================================================*\
* xattrs.c
* x509 attributes routines for lua-openssl binding
*
* Author:  george zhao <zhaozg(at)gmail.com>
\*=========================================================================*/

#include "openssl.h"

int XATTRS_from_ltable(lua_State*L,
                       STACK_OF(X509_ATTRIBUTE) **attributes,
                       int attr)
{
  /* table is in the stack at index 't' */
  lua_pushnil(L);  /* first key */
  while (lua_next(L, attr) != 0)
  {
    /* uses 'key' (at index -2) and 'value' (at index -1) */
    const char * strindex = lua_tostring(L, -2);
    const char * strval = lua_tostring(L, -1);

    if (strindex)
    {
      int nid = OBJ_txt2nid(strindex);
      if (nid != NID_undef)
      {
        if (!X509at_add1_attr_by_NID(attributes, nid,
                                     MBSTRING_ASC, (unsigned char*)strval, -1))
        {
          luaL_error(L, "attrib: X509at_add1_attr_by_NID %d(%s) -> %s (failed)", nid, strindex, strval);
        }
      }
      else
      {
        luaL_error(L, "attrib: %s is not a recognized name", strindex);
      }
    }
    /* removes 'value'; keeps 'key' for next iteration */
    lua_pop(L, 1);
  }
  return 0;
}
