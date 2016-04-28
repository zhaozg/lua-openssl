local openssl = require'openssl'
local pkey = require('openssl').pkey
local unpack = unpack or table.unpack

local function mk_key(args)
        assert(type(args),'table')

        local k = assert(pkey.new(unpack(args)))
        return k
end

TestPKEYMY = {}

    function TestPKEYMY:setUp()
        self.genalg = {
                {nil}, --default to create rsa 1024 bits with 65537
                {'rsa',1024,3}, --create rsa with give bits length and e
                {'dsa',256},
                {'dh',256},
                {'ec','prime256v1'}
        }
    end

    function TestPKEYMY:testModule()
        for i,v in ipairs(self.genalg ) do
                --print(v)
                local k = mk_key(v)
                local k1 = pkey.get_public(k)
                assert(not k1:is_private())

                local t= k:parse()
                local len = t.bits/8
                --print_r(t)

                local msg = openssl.random(len-11)
                if t.type=='rsa' then
                        local out = pkey.encrypt(k1,msg)
                        local raw = pkey.decrypt(k,out)

                        assertEquals(len,#out)
                        assertEquals(msg,raw)

                        local out,sk,iv = pkey.seal(k1,msg)
                        local raw = pkey.open(k,out,sk,iv)
                        assertEquals(msg,raw)
                end
                if t.type ~='ec' and t.type ~='dh' then
                        local sig = assert(pkey.sign(k,msg))
                        assert(true==pkey.verify(k1,msg,sig))
                end

                assert(string.len(k1:export())>0)
                assert(string.len(k:export())>0)

                assert(k1:export():find('^-----BEGIN PUBLIC KEY-----'))

                assert(string.len(k:export(true,true))>0)

                assert(string.len(k:export(true,true))>0)
                assert(string.len(k:export(true,false))>0)
                assert(string.len(k:export(false))>0)

                assert(string.len(k:export(true,true,'secret'))>0)

                assert(string.len(k:export(true,false,'secret'))>0)
                assert(string.len(k:export(false,'secret'))>0)

        end
    end

    function testRSA()
        local nrsa =  {'rsa',1024,3}
        local rsa = pkey.new(unpack(nrsa))

        local k1 = pkey.get_public(rsa)
        assert(not k1:is_private())
        local t = k1:parse ()
        assert(t.bits==1024)
        assert(t.type=='rsa')
        assert(t.size==128)
        local r = t.rsa
        t = r:parse()
        assert(t.n)
        assert(t.e)
        t.alg = 'rsa'
        local r2 = pkey.new(t)
        assert(r2:is_private()==false)
        local msg = openssl.random(128-11)

        local out = pkey.encrypt(r2,msg)
        local raw = pkey.decrypt(rsa,out)
        assert(msg==raw)
    end

    function testRsaFmt()
    local keys = {

RSA= {[[
-----BEGIN PRIVATE KEY-----
MIICdQIBADALBgkqhkiG9w0BAQEEggJhMIICXQIBAAKBgQC7JHoJfg6yNzLMOWet
8Z49a4KD0dCspMAYvo2YAMB7/wdEycocujbhJ2n/seONi+5XqTqqFkM5VBl8rmkk
FPZk/7x0xmdsTPECSWnHK+HhoaNDFPR3j8jQhVo1laxiqcEhAHegi5cwtFosuJAv
SKAFKEvyD43si00DQnXWrYHAEQIDAQABAoGAAPy5SiYHiVErU3KR4Bg+pl4x75wM
FiRC0Cgz+frQPFQEBsAV9RuasyQxqzxrR0Ow0qncBeGBWbYE6WZhqtcLAI895b+i
+F4lbB4iD7T9QeIDMV/aIMXA81UO4cns1z4qDAHKeyLLrPQrJ/B4X7XC+egUWm5+
hr1qmyAMusyXIBECQQDJWZ8piluf4yrYfsJAn6hF5T4RjTztbqvO0GVG2McHY7Uj
NPSffhzHx/ll0fQEQji+OgydCCX8o3HZrgw5YfSJAkEA7e+rqdU5nO5ZG//PSEQb
tjLnRiTzBH/elQhtdZ5nF7pcpNTi4k13zutmKcWW4GK75azcRGJUhu1kDM7QYAOd
SQJAVNkYcifkvna7GmooL5VYEsQsqLbM4v0NF2TIGNfG3z1MGp75KrC5LhL97MNR
we2p/bd2k0HYyCKUGnf2nMPDiQJBAI75pwittSoE240EobUGIDTSz8CJsXIxuDmL
z+KOpdpPRR5TQmbEMEspjsFpFymMiuYPgmihQbO2cJl1qScY5OkCQQCJ6m5tcN8l
Xxg/SNpjEIv+qAyUD96XVlOJlOIeLHQ8kYE0C6ZA+MsqYIzgAreJk88Yn0lU/X0/
mu/UpE/BRZmR
-----END PRIVATE KEY-----
]],
"3082025D02010002818100BB247A097E0EB23732CC3967ADF19E3D6B8283D1D0ACA4C018BE8D9800C07BFF0744C9CA1CBA36E12769FFB1E38D8BEE57A93AAA16433954197CAE692414F664FFBC74C6676C4CF1024969C72BE1E1A1A34314F4778FC8D0855A3595AC62A9C1210077A08B9730B45A2CB8902F48A005284BF20F8DEC8B4D034275D6AD81C011020301000102818000FCB94A260789512B537291E0183EA65E31EF9C0C162442D02833F9FAD03C540406C015F51B9AB32431AB3C6B4743B0D2A9DC05E18159B604E96661AAD70B008F3DE5BFA2F85E256C1E220FB4FD41E203315FDA20C5C0F3550EE1C9ECD73E2A0C01CA7B22CBACF42B27F0785FB5C2F9E8145A6E7E86BD6A9B200CBACC972011024100C9599F298A5B9FE32AD87EC2409FA845E53E118D3CED6EABCED06546D8C70763B52334F49F7E1CC7C7F965D1F4044238BE3A0C9D0825FCA371D9AE0C3961F489024100EDEFABA9D5399CEE591BFFCF48441BB632E74624F3047FDE95086D759E6717BA5CA4D4E2E24D77CEEB6629C596E062BBE5ACDC44625486ED640CCED060039D49024054D9187227E4BE76BB1A6A282F955812C42CA8B6CCE2FD0D1764C818D7C6DF3D4C1A9EF92AB0B92E12FDECC351C1EDA9FDB7769341D8C822941A77F69CC3C3890241008EF9A708ADB52A04DB8D04A1B5062034D2CFC089B17231B8398BCFE28EA5DA4F451E534266C4304B298EC16917298C8AE60F8268A141B3B6709975A92718E4E902410089EA6E6D70DF255F183F48DA63108BFEA80C940FDE9756538994E21E2C743C9181340BA640F8CB2A608CE002B78993CF189F4954FD7D3F9AEFD4A44FC1459991",
"30818902818100BB247A097E0EB23732CC3967ADF19E3D6B8283D1D0ACA4C018BE8D9800C07BFF0744C9CA1CBA36E12769FFB1E38D8BEE57A93AAA16433954197CAE692414F664FFBC74C6676C4CF1024969C72BE1E1A1A34314F4778FC8D0855A3595AC62A9C1210077A08B9730B45A2CB8902F48A005284BF20F8DEC8B4D034275D6AD81C0110203010001"
},

EC={
[[
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgYirTZSx+5O8Y6tlG
cka6W6btJiocdrdolfcukSoTEk+hRANCAAQkvPNu7Pa1GcsWU4v7ptNfqCJVq8Cx
zo0MUVPQgwJ3aJtNM1QMOQUayCrRwfklg+D/rFSUwEUqtZh7fJDiFqz3
-----END PRIVATE KEY-----
]],
'30770201010420622AD3652C7EE4EF18EAD9467246BA5BA6ED262A1C76B76895F72E912A13124FA00A06082A8648CE3D030107A1440342000424BCF36EECF6B519CB16538BFBA6D35FA82255ABC0B1CE8D0C5153D0830277689B4D33540C39051AC82AD1C1F92583E0FFAC5494C0452AB5987B7C90E216ACF7',
'0424BCF36EECF6B519CB16538BFBA6D35FA82255ABC0B1CE8D0C5153D0830277689B4D33540C39051AC82AD1C1F92583E0FFAC5494C0452AB5987B7C90E216ACF7'
},
--]=]
DSA={
[[
-----BEGIN PRIVATE KEY-----
MIIBTAIBADCCASwGByqGSM44BAEwggEfAoGBAKoJMMwUWCUiHK/6KKwolBlqJ4M9
5ewhJweRaJQgd3Si57I4sNNvGySZosJYUIPrAUMpJEGNhn+qIS3RBx1NzrJ4J5St
OTzAik1K2n9o1ug5pfzTS05ALYLLioy0D+wxkRv5vTYLA0yqy0xelHmSVzyekAmc
Gw8FlAyr5dLeSaFnAhUArcDoabNvCsATpoH99NSJnWmCBFECgYEAjGtFia+lOk0Q
SL/DRtHzhsp1UhzPct2qJRKGiA7hMgH/SIkLv8M9ebrK7HHnp3hQe9XxpmQi45QV
vgPnEUG6Mk9bkxMZKRgsiKn6QGKDYGbOvnS1xmkMfRARBsJAq369VOTjMB/Qhs5q
2ski+ycTorCIfLoTubxozlz/8kHNMkYEFwIVAKU1qOHQ2Rvq/IvuHZsqOo3jMRID
-----END PRIVATE KEY-----
]],
'308201BC02010002818100AA0930CC145825221CAFFA28AC2894196A27833DE5EC212707916894207774A2E7B238B0D36F1B2499A2C2585083EB01432924418D867FAA212DD1071D4DCEB2782794AD393CC08A4D4ADA7F68D6E839A5FCD34B4E402D82CB8A8CB40FEC31911BF9BD360B034CAACB4C5E947992573C9E90099C1B0F05940CABE5D2DE49A167021500ADC0E869B36F0AC013A681FDF4D4899D69820451028181008C6B4589AFA53A4D1048BFC346D1F386CA75521CCF72DDAA251286880EE13201FF48890BBFC33D79BACAEC71E7A778507BD5F1A66422E39415BE03E71141BA324F5B93131929182C88A9FA4062836066CEBE74B5C6690C7D101106C240AB7EBD54E4E3301FD086CE6ADAC922FB2713A2B0887CBA13B9BC68CE5CFFF241CD32460281802B260EA97DC6A12AE932C640E7DF3D8FF04A8A05A0324F8D5F1B23F15FA170FF3F42061124EFF2586CB11B49A82DCDC1B90FC6A84FB10109CB67DB5D2DA971AEAF17BE5E37284563E4C64D9E5FC8480258B319F0DE29D54D835070D9E287914D77DF81491F4423B62DA984EB3F45EB2A29FCEA5DAE525AC6AB6BCCE04BFDF5B6021500A535A8E1D0D91BEAFC8BEE1D9B2A3A8DE3311203',
'0281802B260EA97DC6A12AE932C640E7DF3D8FF04A8A05A0324F8D5F1B23F15FA170FF3F42061124EFF2586CB11B49A82DCDC1B90FC6A84FB10109CB67DB5D2DA971AEAF17BE5E37284563E4C64D9E5FC8480258B319F0DE29D54D835070D9E287914D77DF81491F4423B62DA984EB3F45EB2A29FCEA5DAE525AC6AB6BCCE04BFDF5B6'
}
}

        for k,v in pairs(keys) do
                print(string.format('Test %s export format',k))

                local pri = pkey.read(v[1], true, 'pem')
                local pub = assert(pri:get_public())
                -- evp_pkey:export ([pem=true[, raw_key=false[, passphrase]]])

                --begin test pem format
                -- pem=true, raw_key=false, passphrase=nil
                local pem1  = pri:export()
                assertStrContains(pem1,'-----BEGIN PRIVATE KEY-----')
                assertStrContains(pem1,'-----END PRIVATE KEY-----')

                local pem1  = pri:export(true)
                assertStrContains(pem1,'-----BEGIN PRIVATE KEY-----')
                assertStrContains(pem1,'-----END PRIVATE KEY-----')

                local pem1  = pri:export(true, false)
                assertStrContains(pem1,'-----BEGIN PRIVATE KEY-----')
                assertStrContains(pem1,'-----END PRIVATE KEY-----')

                local k1 = pkey.read(pem1,true)
                assertEquals(pri:export(),k1:export())

                -- pem=true, raw_key=false, export_private=false, passphrase=nil
                local pem1  = pub:export(true)
                assertStrContains(pem1,'-----BEGIN PUBLIC KEY-----')
                assertStrContains(pem1,'-----END PUBLIC KEY-----')

                local k2 = pkey.read(pem1,false)
                assertEquals(pub:export(),k2:export())

                -- pem=true, raw_key=false, export_private=true, passphrase='secret'
                local pem3  = pri:export(true, false,'secret')
                assertStrContains(pem3,'-----BEGIN ENCRYPTED PRIVATE KEY-----')
                assertStrContains(pem3,'-----END ENCRYPTED PRIVATE KEY-----')

                --ispriv = true,
                local k2 = pkey.read(pem3, true, 'pem','secret')
                assertEquals(pri:export(),k2:export())

                -- pem=true, raw_key=true, passphrase=nil
                local pem2  = pri:export(true, true)
                assertStrContains(pem2,'-----BEGIN '..k..' PRIVATE KEY-----')
                assertStrContains(pem2,'-----END '..k..' PRIVATE KEY-----')
                assertNotStrContains(pem2,'Proc-Type: 4,ENCRYPTED')
                assertNotStrContains(pem2,'DEK-Info: DES-EDE3-CBC,')

                local k2 = pkey.read(pem2,true,'pem')
                assertEquals(pri:export(),k2:export())

                -- pem=true, raw_key=true, passphrase=nil
                if k~='EC' and k~='DSA' then
                        local pem2  = pub:export(true, true)
                        assertStrContains(pem2,'-----BEGIN '..k..' PUBLIC KEY-----')
                        assertStrContains(pem2,'-----END '..k..' PUBLIC KEY-----')
                        local k2 = pkey.read(pem2, false,'pem',k)
                        --pem=true,raw_key=true
                        assertEquals(pem2,k2:export(true,true))
                end
                -- pem=true, raw_key=true, export_private=true, passphrase='secret'
                local pem4  = pri:export(true, true, 'secret')
                assertStrContains(pem4,'-----BEGIN '..k..' PRIVATE KEY-----')
                assertStrContains(pem4,'Proc-Type: 4,ENCRYPTED')
                assertStrContains(pem4,'DEK-Info: DES-EDE3-CBC,')
                assertStrContains(pem4,'-----END '..k..' PRIVATE KEY-----')
                local k2 = pkey.read(pem4,true,'pem','secret')
                assertEquals(pri:export(),k2:export())
                --end of pem test

                --test der
                -- pem=false, export_private=true, passphrase=nil
                local export = pri:export(false)
                local hex = openssl.hex(export)
                assertEquals(hex:upper(),v[2])

                local k2 = pkey.read(export,true,'der')
                assertEquals(pri:export(),k2:export())

                -- pem=false, export_private=false, passphrase=nil
                local export = pub:export(false)
                local hex = openssl.hex(export)
                assertEquals(hex:upper(),v[3])

                if k~='EC' and k~='DSA' then
                        local k1 = assert(pkey.read(export, false,'der',k))
                        local p1 = k1:export()
                        assertEquals(p1,pub:export())
                end
                -- pkcs8 der
                -- pem=false, raw=true, passphrase='secret'
                local export = pri:export(false,false,'secret')
                local k1 = pkey.read(export,true,'der','secret')
                assertEquals(pri:export(),k1:export())
        end
    end
