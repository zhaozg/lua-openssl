This is a big-number library for Lua 5.1. It handles only integers and is
suitable for number-theoretical and cryptographic applications. It is based
on the bn subsystem of OpenSSL cryptographic library:
	http://www.openssl.org/docs/crypto/bn.html
If you're running Unix, you probably already have OpenSSL installed.

To try the library, just edit Makefile to reflect your installation of Lua and
then run make. This will build the library and run a simple test. For detailed
installation instructions, see
	http://www.tecgraf.puc-rio.br/~lhf/ftp/lua/install.html

There is no manual but the library is simple and intuitive; see the summary
below. Read also test.lua, which shows the library in action.

This code is hereby placed in the public domain.
Please send comments, suggestions, and bug reports to lhf@tecgraf.puc-rio.br .

-------------------------------------------------------------------------------

bn library:
 __add(x,y) 		 compare(x,y) 		 pow(x,y) 
 __div(x,y) 		 div(x,y) 		 powmod(x,y,m) 
 __eq(x,y) 		 divmod(x,y) 		 random(bits) 
 __lt(x,y) 		 gcd(x,y) 		 rmod(x,y) 
 __mod(x,y) 		 invmod(x) 		 sqr(x) 
 __mul(x,y) 		 isneg(x) 		 sqrmod(x) 
 __pow(x,y) 		 isodd(x) 		 sqrtmod(x) 
 __sub(x,y) 		 isone(x) 		 sub(x,y) 
 __tostring(x) 		 isprime(x,[checks]) 	 submod(x,y,m) 
 __unm(x) 		 iszero(x) 		 text(t) 
 abs(x) 		 mod(x,y) 		 tohex(x) 
 add(x,y) 		 mul(x,y) 		 tonumber(x) 
 addmod(x,y,m) 		 mulmod(x,y,m) 		 tostring(x) 
 aprime(bits) 		 neg(x) 		 totext(x) 
 bits(x) 		 number(x) 		 version 

-------------------------------------------------------------------------------
