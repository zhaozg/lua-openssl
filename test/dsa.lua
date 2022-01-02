local openssl = require 'openssl'
local dsa = require'openssl'.dsa
local helper = require'helper'

-- FIXME
--[[
=================================================================
==3406==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 24 byte(s) in 1 object(s) allocated from:
    #0 0x102215750 in wrap_malloc+0xa0 (libclang_rt.asan_osx_dynamic.dylib:x86_64+0x44750)
    #1 0x103ec94a5 in CRYPTO_zalloc+0xe (libcrypto.3.dylib:x86_64+0x1354a5)
    #2 0x103dd95f2 in BN_new+0x1b (libcrypto.3.dylib:x86_64+0x455f2)
    #3 0x103dd9790 in BN_dup+0x19 (libcrypto.3.dylib:x86_64+0x45790)
    #4 0x103ebf65f in ossl_ffc_params_FIPS186_2_gen_verify+0x7af (libcrypto.3.dylib:x86_64+0x12b65f)
    #5 0x103ebf7da in ossl_ffc_params_FIPS186_2_generate+0x26 (libcrypto.3.dylib:x86_64+0x12b7da)
    #6 0x103e1ed30 in ossl_dsa_generate_ffc_parameters+0x39 (libcrypto.3.dylib:x86_64+0x8ad30)
    #7 0x103e1edf7 in DSA_generate_parameters_ex+0xa1 (libcrypto.3.dylib:x86_64+0x8adf7)
    #8 0x103bbdb91  (<unknown module>)
    #9 0x102160785  (luajit:x86_64+0x100006785)

Direct leak of 24 byte(s) in 1 object(s) allocated from:
    #00x102215750 in wrap_malloc+0xa0 (libclang_rt.asan_osx_dynamic.dylib:x86_64+0x44750)
    #1 0x103ec94a5 in CRYPTO_zalloc+0xe (libcrypto.3.dylib:x86_64+0x1354a5)
    #2 0x103dd95f2 in BN_new+0x1b (libcrypto.3.dylib:x86_64+0x455f2)
    #3 0x103dd9790 in BN_dup+0x19 (libcrypto.3.dylib:x86_64+0x45790)
    #4 0x103ebf638 in ossl_ffc_params_FIPS186_2_gen_verify+0x788 (libcrypto.3.dylib:x86_64+0x12b638)
    #5 0x103ebf7da in ossl_ffc_params_FIPS186_2_generate+0x26 (libcrypto.3.dylib:x86_64+0x12b7da)
    #6 0x103e1ed30 in ossl_dsa_generate_ffc_parameters+0x39 (libcrypto.3.dylib:x86_64+0x8ad30)
    #7 0x103e1edf7 in DSA_generate_parameters_ex+0xa1 (libcrypto.3.dylib:x86_64+0x8adf7)
    #8 0x103bbdb91  (<unknown module>)
    #9 0x102160785  (luajit:x86_64+0x100006785)

Direct leak of 24 byte(s) in 1 object(s) allocated from:
    #0 0x102215750 in wrap_malloc+0xa0 (libclang_rt.asan_osx_dynamic.dylib:x86_64+0x44750)
    #1 0x103ec94a5 in CRYPTO_zalloc+0xe (libcrypto.3.dylib:x86_64+0x1354a5)
    #2 0x103dd95f2 in BN_new+0x1b (libcrypto.3.dylib:x86_64+0x455f2)
    #3 0x103dd9790 in BN_dup+0x19 (libcrypto.3.dylib:x86_64+0x45790)
    #4 0x103ebf687 in ossl_ffc_params_FIPS186_2_gen_verify+0x7d7 (libcrypto.3.dylib:x86_64+0x12b687)
    #5 0x103ebf7da in ossl_ffc_params_FIPS186_2_generate+0x26 (libcrypto.3.dylib:x86_64+0x12b7da)
    #6 0x103e1ed30 in ossl_dsa_generate_ffc_parameters+0x39 (libcrypto.3.dylib:x86_64+0x8ad30)
    #7 0x103e1edf7 in DSA_generate_parameters_ex+0xa1 (libcrypto.3.dylib:x86_64+0x8adf7)
    #8 0x103bbdb91  (<unknown module>)
    #9 0x102160785  (luajit:x86_64+0x100006785)

Direct leak of 20 byte(s) in 1 object(s) allocated from:
    #0 0x102215750 in wrap_malloc+0xa0 (libclang_rt.asan_osx_dynamic.dylib:x86_64+0x44750)
    #1 0x103eca9a8 in CRYPTO_memdup+0x2c (libcrypto.3.dylib:x86_64+0x1369a8)
    #2 0x103ebd657 in ossl_ffc_params_set_seed+0x62 (libcrypto.3.dylib:x86_64+0x129657)
    #3 0x103ebd6e3 in ossl_ffc_params_set_validate_params+0x11 (libcrypto.3.dylib:x86_64+0x1296e3)
    #4 0x103ebf6ce in ossl_ffc_params_FIPS186_2_gen_verify+0x81e (libcrypto.3.dylib:x86_64+0x12b6ce)
    #5 0x103ebf7da in ossl_ffc_params_FIPS186_2_generate+0x26 (libcrypto.3.dylib:x86_64+0x12b7da)
    #6 0x103e1ed30 in ossl_dsa_generate_ffc_parameters+0x39 (libcrypto.3.dylib:x86_64+0x8ad30)
    #7 0x103e1edf7 in DSA_generate_parameters_ex+0xa1 (libcrypto.3.dylib:x86_64+0x8adf7)
    #8 0x103bbdb91  (<unknown module>)
    #9 0x102160785  (luajit:x86_64+0x100006785)

Indirect leak of 128 byte(s) in 1 object(s) allocated from:
    #0 0x102215750 in wrap_malloc+0xa0 (libclang_rt.asan_osx_dynamic.dylib:x86_64+0x44750)
    #1 0x103ec94a5 in CRYPTO_zalloc+0xe (libcrypto.3.dylib:x86_64+0x1354a5)
    #2 0x103dd96c5 in bn_expand2+0x71 (libcrypto.3.dylib:x86_64+0x456c5)
    #3 0x103dd97ff in BN_copy+0x31 (libcrypto.3.dylib:x86_64+0x457ff)
    #4 0x103dd97b6 in BN_dup+0x3f (libcrypto.3.dylib:x86_64+0x457b6)
    #5 0x103ebf638 in ossl_ffc_params_FIPS186_2_gen_verify+0x788 (libcrypto.3.dylib:x86_64+0x12b638)
    #6 0x103ebf7da in ossl_ffc_params_FIPS186_2_generate+0x26 (libcrypto.3.dylib:x86_64+0x12b7da)
    #7 0x103e1ed30 in ossl_dsa_generate_ffc_parameters+0x39 (libcrypto.3.dylib:x86_64+0x8ad30)
    #8 0x103e1edf7 in DSA_generate_parameters_ex+0xa1 (libcrypto.3.dylib:x86_64+0x8adf7)
    #9 0x103bbdb91  (<unknown module>)
    #10 0x102160785  (luajit:x86_64+0x100006785)

Indirect leak of 128 byte(s) in 1 object(s) allocated from:
    #0 0x102215750 in wrap_malloc+0xa0 (libclang_rt.asan_osx_dynamic.dylib:x86_64+0x44750)
    #1 0x103ec94a5 in CRYPTO_zalloc+0xe (libcrypto.3.dylib:x86_64+0x1354a5)
    #2 0x103dd96c5 in bn_expand2+0x71 (libcrypto.3.dylib:x86_64+0x456c5)
    #3 0x103dd97ff in BN_copy+0x31 (libcrypto.3.dylib:x86_64+0x457ff)
    #4 0x103dd97b6 in BN_dup+0x3f (libcrypto.3.dylib:x86_64+0x457b6)
    #5 0x103ebf687 in ossl_ffc_params_FIPS186_2_gen_verify+0x7d7 (libcrypto.3.dylib:x86_64+0x12b687)
    #6 0x103ebf7da in ossl_ffc_params_FIPS186_2_generate+0x26 (libcrypto.3.dylib:x86_64+0x12b7da)
    #7 0x103e1ed30 in ossl_dsa_generate_ffc_parameters+0x39 (libcrypto.3.dylib:x86_64+0x8ad30)
    #8 0x103e1edf7 in DSA_generate_parameters_ex+0xa1 (libcrypto.3.dylib:x86_64+0x8adf7)
    #9 0x103bbdb91  (<unknown module>)
    #10 0x102160785  (luajit:x86_64+0x100006785)

Indirect leak of 24 byte(s) in 1 object(s) allocated from:
    #0 0x102215750 in wrap_malloc+0xa0 (libclang_rt.asan_osx_dynamic.dylib:x86_64+0x44750)
    #1 0x103ec94a5 in CRYPTO_zalloc+0xe (libcrypto.3.dylib:x86_64+0x1354a5)
    #2 0x103dd96c5 in bn_expand2+0x71 (libcrypto.3.dylib:x86_64+0x456c5)
    #3 0x103dd97ff in BN_copy+0x31 (libcrypto.3.dylib:x86_64+0x457ff)
    #4 0x103dd97b6 in BN_dup+0x3f (libcrypto.3.dylib:x86_64+0x457b6)
    #5 0x103ebf65f in ossl_ffc_params_FIPS186_2_gen_verify+0x7af (libcrypto.3.dylib:x86_64+0x12b65f)
    #6 0x103ebf7da in ossl_ffc_params_FIPS186_2_generate+0x26 (libcrypto.3.dylib:x86_64+0x12b7da)
    #7 0x103e1ed30 in ossl_dsa_generate_ffc_parameters+0x39 (libcrypto.3.dylib:x86_64+0x8ad30)
    #8 0x103e1edf7 in DSA_generate_parameters_ex+0xa1 (libcrypto.3.dylib:x86_64+0x8adf7)
    #9 0x103bbdb91  (<unknown module>)
    #10 0x102160785  (luajit:x86_64+0x100006785)

SUMMARY: AddressSanitizer: 372 byte(s) leaked in 7 allocation(s). 
--]]
if helper.openssl3 then
  return
end

TestDSA = {}
function TestDSA:Testdsa()
  local k = dsa.generate_key(1024)

  local t = k:parse()
  assert(t.bits == 1024)

  k:set_engine(openssl.engine('openssl'))
end
