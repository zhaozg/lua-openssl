/*=========================================================================*\
* misc.h
* misc routines for lua-openssl binding
*
* Author:  george zhao <zhaozg(at)gmail.com>
\*=========================================================================*/
#include "openssl.h"


time_t asn1_time_to_time_t(ASN1_UTCTIME * timestr) /* {{{ */
{
    /*
    	This is how the time string is formatted:

       snprintf(p, sizeof(p), "%02d%02d%02d%02d%02d%02dZ",ts->tm_year%100,
          ts->tm_mon+1,ts->tm_mday,ts->tm_hour,ts->tm_min,ts->tm_sec);
    */

    time_t ret;
    struct tm thetime;
    char * strbuf;
    char * thestr;
    long gmadjust = 0;

    if (timestr->length < 13) {
        return (time_t)-1;
    }

    strbuf = strdup((char *)timestr->data);

    memset(&thetime, 0, sizeof(thetime));

    /* we work backwards so that we can use atoi more easily */

    thestr = strbuf + timestr->length - 3;

    thetime.tm_sec = atoi(thestr);
    *thestr = '\0';
    thestr -= 2;
    thetime.tm_min = atoi(thestr);
    *thestr = '\0';
    thestr -= 2;
    thetime.tm_hour = atoi(thestr);
    *thestr = '\0';
    thestr -= 2;
    thetime.tm_mday = atoi(thestr);
    *thestr = '\0';
    thestr -= 2;
    thetime.tm_mon = atoi(thestr)-1;
    *thestr = '\0';
    thestr -= 2;
    thetime.tm_year = atoi(thestr);

    if (thetime.tm_year < 68) {
        thetime.tm_year += 100;
    }

    thetime.tm_isdst = -1;
    ret = mktime(&thetime);

#if HAVE_TM_GMTOFF
    gmadjust = thetime.tm_gmtoff;
#else
    /*
    ** If correcting for daylight savings time, we set the adjustment to
    ** the value of timezone - 3600 seconds. Otherwise, we need to overcorrect and
    ** set the adjustment to the main timezone + 3600 seconds.
    */
    gmadjust = -(thetime.tm_isdst ? (long)timezone - 3600 : (long)timezone + 3600);
#endif
    ret += gmadjust;

    free(strbuf);

    return ret;
}
/* }}} */

/* }}} */


void openssl_add_method_or_alias(const OBJ_NAME *name, void *arg)
{
    lua_State *L = (lua_State *)arg;
    int i = lua_objlen(L,-1);
    lua_pushstring(L,name->name);
    lua_rawseti(L,-2,i+1);
}

void openssl_add_method(const OBJ_NAME *name, void *arg)
{
    if (name->alias == 0) {
        openssl_add_method_or_alias(name,arg);
    }
}
