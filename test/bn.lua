-- test bn library
local openssl=require"openssl"
local bn = openssl.bn
------------------------------------------------------------------------------
print(bn.version)
print()

p=bn.aprime(100)
q=bn.aprime(250)
	print("p",p)
	print("q",q)
m=p*q
	print("m",m)
mx=(p-1)*(q-1)
	print("mx",mx)
e=bn.number"X10001"
	print("e",e)
d=bn.invmod(e,mx)
	print("d",d)
	assert(bn.mulmod(e,d,mx):isone())
t=bn.number(2)
x=bn.powmod(t,e,m)
y=bn.powmod(x,d,m)
	assert(t==y)
	print()

message="The quick brown fox jumps over the lazy dog"
	print("message as text")
	print(message)

encoded=bn.text(message)
	print("encoded message")
	print(encoded)
	assert(encoded<m)
	assert(message==bn.totext(encoded))

x=bn.powmod(encoded,e,m)
	print("encrypted message")
	print(x)

y=bn.powmod(x,d,m)
	print("decrypted message as number")
	print(y)
	assert(y==encoded)
y=bn.totext(y)
	print("decrypted message as text")
	print(y)
	assert(y==message)

print()
print(bn.version)

d=bn.number"X816f0d36f0874f9f2a78acf5643acda3b59b9bcda66775b7720f57d8e9015536160e728230ac529a6a3c935774ee0a2d8061ea3b11c63eed69c9f791c1f8f5145cecc722a220d2bc7516b6d05cbaf38d2ab473a3f07b82ec3fd4d04248d914626d2840b1bd337db3a5195e05828c9abf8de8da4702a7faa0e54955c3a01bf121"
m=bn.number"Xbfedeb9c79e1c6e425472a827baa66c1e89572bbfe91e84da94285ffd4c7972e1b9be3da762444516bb37573196e4bef082e5a664790a764dd546e0d167bde1856e9ce6b9dc9801e4713e3c8cb2f12459788a02d2e51ef37121a0f7b086784f0e35e76980403041c3e5e98dfa43ab9e6e85558c5dc00501b2f2a2959a11db21f"
t=bn.number(2)
x=bn.powmod(t,e,m)
y=bn.powmod(x,d,m)
	assert(t==y)
