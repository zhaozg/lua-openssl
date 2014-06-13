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

void add_assoc_name_entry(lua_State*L,const  char * key, X509_NAME * name, int shortname) /* {{{ */
{
    int i, j = -1, last = -1, obj_cnt = 0;
    char *sname;
    int nid;
    X509_NAME_ENTRY * ne;
    ASN1_STRING * str = NULL;
    ASN1_OBJECT * obj;
    char* p;

    lua_newtable(L);

    p=X509_NAME_oneline(name,NULL,0);
    lua_pushstring(L, p);
    lua_rawseti(L, -2, 0);
    OPENSSL_free(p);

    for (i = 0; i < X509_NAME_entry_count(name); i++) {
        unsigned char *to_add = NULL;
        int to_add_len = -1;
        int tindex = 0;
        //int utf8 = 0;

        ne  = X509_NAME_get_entry(name, i);
        obj = X509_NAME_ENTRY_get_object(ne);
        nid = OBJ_obj2nid(obj);
        obj_cnt = 0;

        if (shortname) {
            sname = (char *) OBJ_nid2sn(nid);
        } else {
            sname = (char *) OBJ_nid2ln(nid);
        }

        lua_newtable(L);

        last = -1;
        for (;;) {
            j = X509_NAME_get_index_by_OBJ(name, obj, last);
            if (j < 0) {
                if (last != -1) break;
            } else {
                obj_cnt++;
                ne  = X509_NAME_get_entry(name, j);
                str = X509_NAME_ENTRY_get_data(ne);

                /* Some Certificate not stardand
                if (ASN1_STRING_type(str) != V_ASN1_UTF8STRING) {
                	to_add_len = ASN1_STRING_to_UTF8(&to_add, str);
                }
                */

                to_add = ASN1_STRING_data(str);
                to_add_len = ASN1_STRING_length(str);
                tindex++;
                lua_pushlstring(L,(char *)to_add, to_add_len);
                lua_rawseti(L,-2,tindex);
            }
            last = j;
        }
        i = last;

        if (obj_cnt > 1) {
            lua_setfield(L,-2,sname);
        } else {
            lua_pop(L,1);
            if (obj_cnt && str && to_add_len > -1) {
                lua_pushlstring(L,(char *)to_add, to_add_len);
                lua_setfield(L,-2, sname);
            }
        }
    }

    if (key != NULL) {
        lua_setfield(L,-2,key);
    }
}

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
