lua-openssl toolkit - A free, MIT-licensed OpenSSL binding for Lua.

[![Build Status](https://travis-ci.org/zhaozg/lua-openssl.svg)](https://travis-ci.org/zhaozg/lua-openssl)
[![Build status](https://ci.appveyor.com/api/projects/status/f8xchhlj035yqq88/branch/master?svg=true)](https://ci.appveyor.com/project/zhaozg/lua-openssl/branch/master)

#Index

1. [Introduction](#introduction)
2. [Documentation](#documentation)
2. [Howto](#a---howto)
3. [Examples](#b--example-usage) 

# Introduction

I needed a full OpenSSL binding for Lua, after googled, I couldn't find a version to fit my needs.
I found the PHP openssl binding is a good implementation, and it inspired me.
So I decided to write this OpenSSL toolkit for Lua.

The goal is to fully support the listed items.Below you can find the development progress of lua-openssl. 

* Symmetrical encrypt/decrypt. (Finished)
* Message digest. (Finished)
* Asymmetrical encrypt/decrypt/sign/verify/seal/open. (Finished)
* X509 certificate. (Finished)
* PKCS7/CMS. (Developing)
* SSL/TLS. (Finished)

Most of the lua-openssl functions require a key or certificate as argument; to make things easy to use OpenSSL,
This rule allow you to specify certificates or keys in the following ways:

1. As an openssl.x509 object returned from openssl.x509.read
2. As an openssl.evp_pkey object return from openssl.pkey.read or openssl.pkey.new

Similarly, you can also specify a public key as a key object returned from x509:get_public().

## lua-openssl modules
digest,cipher, x509, cms and so on, be write as modules.

```lua
   local digest = require'openssl'.digest
   local cipher = require'openssl'.cipher
   local crypto = require'crypto'
   local ssl    = require'ssl'
```

digest() equals with digest.digest(), same cipher() equals with cipher.cipher().

## documentation

Document please see [here](http://zhaozg.github.io/lua-openssl/)

## compat with others

**crypto** is a compat module with [LuaCrypto](https://github.com/mkottman/luacrypto),
document should to [reference](http://mkottman.github.io/luacrypto/manual.html#reference)

**ssl** is a compat module with [luasec](https://github.com/brunoos/luasec),
document should to [refrence](https://github.com/brunoos/luasec/wiki/LuaSec-0.5).
NYI list: conn:settimeout,...

## lua-openssl Objects

The following are some important lua-openssl object types:

```
	openssl.bio,
	openssl.x509,
	openssl.stack_of_x509,
	openssl.x509_req,
	openssl.evp_pkey,
	openssl.evp_digest,
	openssl.evp_cipher,
	openssl.engine,
	openssl.pkcs7,
	openssl.cms,
	openssl.evp_cipher_ctx,
	openssl.evp_digest_ctx
	...
```

They are shortened as bio, x509, sk_x509, csr, pkey, digest, cipher,
	engine, cipher_ctx, and digest_ctx.


## openssl.bn
* ***openssl.bn*** come from [http://www.tecgraf.puc-rio.br/~lhf/ftp/lua/](http://www.tecgraf.puc-rio.br/~lhf/ftp/lua/),thanks.

openssl.bn is a big-number library for Lua 5.1. It handles only integers and is
suitable for number-theoretical and cryptographic applications. It is based
on the bn subsystem of OpenSSL cryptographic library:
	http://www.openssl.org/docs/crypto/bn.html
If you're running Unix, you probably already have OpenSSL installed.

To try the library, just edit Makefile to reflect your installation of Lua and
then run make. This will build the library and run a simple test. For detailed
installation instructions, see
	http://www.tecgraf.puc-rio.br/~lhf/ftp/lua/install.html

There is no manual but the library is simple and intuitive; see the summary
below.

bn library:
```
 __add(x,y)		compare(x,y)		pow(x,y) 
 __div(x,y)		div(x,y)			powmod(x,y,m) 
 __eq(x,y)		divmod(x,y)			random(bits) 
 __lt(x,y)		gcd(x,y)			rmod(x,y) 
 __mod(x,y)		invmod(x)			sqr(x) 
 __mul(x,y)		isneg(x)			sqrmod(x) 
 __pow(x,y)		isodd(x)			sqrtmod(x) 
 __sub(x,y)		isone(x)			sub(x,y) 
 __tostring(x)	isprime(x,[checks])	submod(x,y,m) 
 __unm(x)		iszero(x)			text(t) 
 abs(x)			mod(x,y)			tohex(x) 
 add(x,y)		mul(x,y)			tonumber(x) 
 addmod(x,y,m)	mulmod(x,y,m)		tostring(x) 
 aprime(bits)	neg(x)				totext(x) 
 bits(x)		number(x)			version 
```

## Version

This lua-openssl toolkit works with Lua 5.1/5.2 or LuaJIT 2.0/2.1, and OpenSSL (0.9.8 or above 1.0.0). 
It is recommended to use the most up-to-date OpenSSL version because of the recent security fixes.

If you want to get the lua-openssl and OpenSSL versions from a Lua script, here is how:

```lua
openssl = require "openssl"
lua_openssl_version, lua_version, openssl_version = openssl.version()
```

## Bugs

Lua-Openssl is heavily updated, if you find bug, please report to [here](https://github.com/zhaozg/lua-openssl/issues/)

#A.   Howto

### Howto 1: Build on Linux/Unix System.

	make
	make install
	make clean

### Howto 2: Build on Windows with MSVC.

Before building, please change the setting in the config.win file.
Works with Lua5.1 (should support Lua5.2 by updating the config.win file).

	nmake -f makefile.win
	nmake -f makefile.win install
	nmake -f makefile.win clean


### Howto 3: Build on Windows with mingw.

	make
	make install
	make clean

### Howto 4: Install using luarocks.
	
	luarocks install openssl --server=https://rocks.moonscript.org/dev

### Howto 5: Handle fail or error

  Most lua-openssl function or methods return nil or false when error or 
failed, followed by string type error _reason_ and number type error _code_, 
_code_ can pass to openssl.error() to get more error information.

  All SSL object IO operation methods return nil or false when fail or error.
When nil returned, it followed by 'ssl' or 'syscall', means SSL layer or 
system layer error. When false returned, it followed by number 0, 'want_read',
'want_write','want_x509_lookup','want_connect','want_accept'. Numnber 0 means
SSL connection closed, others means you should do some SSL operation.

  Please remeber that when lua-openssl function or methods failed without 
error code, you can get last error by openssl.error(), and repeat call 
openssl.error() will walk through error stacks of current threads. 
openssl.error(true) will also clear error stacks after get last error code,
this is very useful to free memory when lua-openssl repeat calls or run long times.

#B.  Example usage

### Example 1: short encrypt/decrypt

```lua
local evp_cipher = openssl.cipher.get('des')
m = 'abcdefghick'
key = m
cdata = evp_cipher:encrypt(m,key)
m1  = evp_cipher:decrypt(cdata,key)
assert(m==m1)
```

### Example 2: quick evp_digest

```lua
md = openssl.digest.get('md5')
m = 'abcd'
aa = md:digest(m)

mdc=md:new()
mdc:update(m)
bb = mdc:final()
assert(openssl.hex(aa,true)==bb)
```

### Example 3:  Iterate a openssl.stack_of_x509(sk_x509) object

```lua
n = #sk
for i=1, n do
	x = sk:get(i)
end
```

### Example 4: read and parse certificate

```lua
local openssl = require('openssl')

function dump(t,i)
	for k,v in pairs(t) do
		if(type(v)=='table') then
			print( string.rep('\t',i),k..'={')
			dump(v,i+1)
			print( string.rep('\t',i),k..'=}')
		else
			print( string.rep('\t',i),k..'='..tostring(v))
		end
	end
end

function test_x509()
	local x = openssl.x509.read(certasstring)
	print(x)
	t = x:parse()
	dump(t,0)
	print(t)
end

test_x509()
```

###Example 5: bio network handle(TCP)

 * server
 
```lua
local openssl = require'openssl'
local bio = openssl.bio

host = host or "127.0.0.1"; --only ip
port = port or "8383";

local srv = assert(bio.accept(host..':'..port))
print('listen at:'..port)
local cli = assert(srv:accept())
while 1 do
    cli = assert(srv:accept())
    print('CLI:',cli)
    while cli do
        local s = assert(cli:read())
        print(s)
        assert(cli:write(s))
    end
    print(openssl.error(true))
end
```

 * client
```lua
local openssl = require'openssl'
local bio = openssl.bio
io.read()

host = host or "127.0.0.1"; --only ip
port = port or "8383";

local cli = assert(bio.connect(host..':'..port,true))

    while cli do
        s = io.read()
        if(#s>0) then
            print(cli:write(s))
            ss = cli:read()
            assert(#s==#ss)
        end
    end
    print(openssl.error(true))
```

For more examples, please see test lua script file.


--------------------------------------------------------------------
***lua-openssl License***

Copyright (c) 2011 - 2014 zhaozg, zhaozg(at)gmail.com

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to
deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
sell copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

--------------------------------------------------------------------

This product includes PHP software, freely available from <http://www.php.net/software/>

