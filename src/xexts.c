/*=========================================================================*\
* x509 name routines
*
* This product includes PHP software, freely available from <http://www.php.net/software/>
* Author:  george zhao <zhaozg(at)gmail.com>
\*=========================================================================*/
#include <ctype.h>
#include "openssl.h"
#include "private.h"

#define MYNAME "x509.extension"


static int openssl_xext_totable(lua_State* L, X509_EXTENSION *x, int utf8)
{
  lua_newtable(L);
  openssl_push_asn1object(L, x->object);
  lua_setfield(L, -2, "object");

  PUSH_ASN1_OCTET_STRING(L, x->value);
  lua_setfield(L,-2, "value");

  AUXILIAR_SET(L, -1, "critical", x->critical, boolean);

  switch (x->object->nid) 
  {
  case NID_subject_alt_name:
    {
      int i;
      int n_general_names;
      
      STACK_OF(GENERAL_NAME) *values = X509V3_EXT_d2i(x);

      if (values == NULL)
        break;

       /* Push ret[oid] */
      openssl_push_asn1object(L, x->object);
      lua_newtable(L);
      n_general_names = sk_GENERAL_NAME_num(values);
      for (i = 0; i < n_general_names; i++) {
        GENERAL_NAME *general_name = sk_GENERAL_NAME_value(values, i);
        switch (general_name->type) {
        case GEN_OTHERNAME:
          {
          OTHERNAME *otherName = general_name->d.otherName;

          lua_newtable(L);
          openssl_push_asn1object(L, otherName->type_id);
          PUSH_ASN1_STRING(L, otherName->value->value.asn1_string, utf8);
          lua_settable(L, -3);
          lua_setfield(L, -2, "otherName");

          lua_pushstring(L, "otherName");
          lua_rawseti(L, -2, i+1);
          break;
          }
        case GEN_EMAIL:
          lua_newtable(L);
          PUSH_ASN1_STRING(L, general_name->d.rfc822Name, utf8);
          lua_pushstring(L, "rfc822Name");
          lua_settable(L, -3);

          lua_pushstring(L, "rfc822Name");
          lua_rawseti(L, -2, i+1);
          break;
        case GEN_DNS:
          lua_newtable(L);
          PUSH_ASN1_STRING(L, general_name->d.dNSName, utf8);
          lua_setfield(L, -2, "dNSName");
          lua_pushstring(L, "dNSName");
          lua_rawseti(L, -2, i+1);
          break;
        case GEN_X400:
          lua_newtable(L);
          openssl_push_asn1type(L, general_name->d.x400Address);
          lua_setfield(L, -2, "x400Address");
          lua_pushstring(L, "x400Address");
          lua_rawseti(L, -2, i+1);
          break;
        case GEN_DIRNAME:
          lua_newtable(L);
          push_x509_name(L, general_name->d.directoryName, utf8);
          lua_setfield(L, -2, "directoryName");
          lua_pushstring(L, "directoryName");
          lua_rawseti(L, -2, i+1);
          break;
        case GEN_URI:
          lua_newtable(L);
          PUSH_ASN1_STRING(L, general_name->d.uniformResourceIdentifier, utf8);
          lua_setfield(L, -2, "uniformResourceIdentifier");
          lua_pushstring(L, "uniformResourceIdentifier");
          lua_rawseti(L, -2, i+1);
          break;
        case GEN_IPADD:
          lua_newtable(L);
          PUSH_ASN1_OCTET_STRING(L, general_name->d.iPAddress);
          lua_setfield(L, -2, "iPAddress");
          lua_pushstring(L, "iPAddress");
          lua_rawseti(L, -2, i+1);
          break;
        case GEN_EDIPARTY:
          lua_newtable(L);
          lua_newtable(L);
          PUSH_ASN1_STRING(L, general_name->d.ediPartyName->nameAssigner,utf8);
          lua_setfield(L, -2, "nameAssigner");
          PUSH_ASN1_STRING(L, general_name->d.ediPartyName->partyName,utf8);
          lua_setfield(L, -2, "partyName");
          lua_setfield(L, -2, "ediPartyName");

          lua_pushstring(L, "ediPartyName");
          lua_rawseti(L, -2, i+1);
          break;
        case GEN_RID:
          lua_newtable(L);
          openssl_push_asn1object(L, general_name->d.registeredID);
          lua_setfield(L, -2, "registeredID");
          lua_pushstring(L, "registeredID");
          lua_rawseti(L, -2, i+1);
          break;
        }
       }
      lua_settable(L, -3);
    }
  default:
    break;
  }
  return 1;
};

int openssl_x509_extensions(lua_State* L)
{
  int i = -1;
  
  X509 *peer = CHECK_OBJECT(1, X509, "openssl.x509");
  int utf8 = lua_isnoneornil(L, 2) ? 0 : lua_toboolean(L, 2);

  /* Return (ret) */
  lua_newtable(L);

  while ((i = X509_get_ext_by_NID(peer, NID_subject_alt_name, i)) != -1) {
    X509_EXTENSION *extension = X509_get_ext(peer, i);
    STACK_OF(GENERAL_NAME) *values;
    if (extension == NULL)
      break;
    values = X509V3_EXT_d2i(extension);
    if (values == NULL)
      break;

    openssl_xext_totable(L, extension, utf8);
    lua_rawseti(L, -2, i+1);
    i++;           /* Next extension */
  }
  return 1;
}

static int openssl_xext_info(lua_State* L)
{
  X509_EXTENSION *x = CHECK_OBJECT(1, X509_EXTENSION, "openssl.x509_extension");
  int utf8 = lua_isnoneornil(L, 2) ? 0 : lua_toboolean(L, 2);
  return openssl_xext_totable(L,x,utf8);
};

static luaL_Reg x509_extension_funs[] =
{
  {"info",          openssl_xext_info},
  {"__tostring",    auxiliar_tostring},

  { NULL, NULL }
};

static X509_EXTENSION* openssl_new_xextension(lua_State*L, X509_EXTENSION** x, int idx, int utf8)
{
  ASN1_OBJECT* obj;
  ASN1_OCTET_STRING* value;
  int critical;

  lua_setfield(L, idx, "object");
  obj = CHECK_OBJECT(-1, ASN1_OBJECT, "openssl.asn1_object");
  lua_pop(L, 1);
  lua_setfield(L, idx, "value");
  value = CHECK_OBJECT(-1, ASN1_STRING, "openssl.asn1_string");
  lua_pop(L, 1);
  lua_setfield(L, idx, "critical");
  critical = lua_isnil(L,-1) ? 0 : lua_toboolean(L, -1);
  lua_pop(L, 1);

  return X509_EXTENSION_create_by_NID(x, obj->nid, critical, ASN1_STRING_dup(value));
}

static int openssl_xext_new(lua_State* L)
{
  X509_EXTENSION *x=NULL;
  int utf8;
  luaL_checktable(L,1);
  utf8 = lua_isnoneornil(L, 2) ? 1 : lua_toboolean(L, 2);

  x = openssl_new_xextension(L, &x, 1, utf8);
  PUSH_OBJECT(x,"openssl.x509_extension");
  return 1;
};

static luaL_Reg R[] =
{
  {"new",         openssl_xext_new},

  {NULL,          NULL},
};

int openssl_register_xextension(lua_State*L)
{
  auxiliar_newclass(L, "openssl.x509_extension", x509_extension_funs);
  luaL_register(L, MYNAME, R);
  return 1;
}

int openssl_push_x509_exts(lua_State*L, STACK_OF(X509_EXTENSION) *exts, int utf8)
{
  int i;
  int n = sk_X509_EXTENSION_num(exts);
  lua_newtable(L);

  for (i = 0; i < n; i++)
  {
    X509_EXTENSION* ext = sk_X509_EXTENSION_value(exts, i);

    openssl_xext_totable(L, ext, utf8);
    lua_rawseti(L, -2, i+1);
  };
  return 1;
}

int openssl_new_xexts(lua_State* L, STACK_OF(X509_EXTENSION) *exts, int idx, int utf8)
{
  size_t i;
  X509_EXTENSION *x=NULL;
  luaL_checktable(L,idx);
  for (i=0; i<lua_objlen(L, idx); i++)
  {
    lua_rawget(L, i+1);
    x = openssl_new_xextension(L, NULL, 1, utf8);
    sk_X509_EXTENSION_push(exts, x);
  }

  return 0;
};
