//! Cryptographic Hash Algorithms

/*
 INFALLIBILITY COMMENTARY

 ---- SHA3 / KECCAK FAMILY

 -- InitSha3

 Src: https://github.com/wolfSSL/wolfssl/blob/master/wolfcrypt/src/sha3.c#L620

 Under all possible paths this returns 0.

 -- Sha3Update

 Src: https://github.com/wolfSSL/wolfssl/blob/master/wolfcrypt/src/sha3.c#L670

 Under all possible paths this returns 0.

 -- Sha3Final

 Src: https://github.com/wolfSSL/wolfssl/blob/master/wolfcrypt/src/sha3.c#L745

 Under all possible paths this returns 0.

 -- wc_InitSha3

 Src: https://github.com/wolfSSL/wolfssl/blob/master/wolfcrypt/src/sha3.c#L808

 This will always return 0 unless WOLFSSL_ASYNC_CRYPT /\ WC_ASYNC_ENABLE_SHA3 are enabled, which
 neither of these are. So this is also infallible.

 This depends on the infallibility of InitSha3, which we have already pointed out, returns
 zero under all possible paths.

 -- wc_Sha3Update

 Src: https://github.com/wolfSSL/wolfssl/blob/master/wolfcrypt/src/sha3.c#L840

 This will always return zero unless WOLF_CRYPTO_CB \/ (WOLFSSL_ASYNC_CRYPT /\ WC_ASYNC_ENABLE_SHA3)
 are enabled. Async crypt will never be enabled so this is ruled out. Though WOLF_CRYPTO_CB may
 eventually be enabled via a feature flag. Currently, the upgrade guide, found in the workspace
 root, requires that if this feature is being enabled that the introduced fallibility must be
 handled in some way, shape, or form. The upgrade guide allows current implementations to make the
 assumption that this is not to be enabled, and that methods made fallible due to the potential
 enabling of this feature do not need to handle the potential error.

 This is also fallible via the functions preconditions which are handled via the type system and
 borrow checker. These being the sha3 instance being null, and the data being null if the length is
 greater than zero.

 This propagates any error encountered in Sha3Update, which we have already shown to be infallible,
 regardless of WOLF_CRYPTO_CB.

 So, this is currently to be considered infallible.

 -- wc_Sha3Final

 Src: https://github.com/wolfSSL/wolfssl/blob/master/wolfcrypt/src/sha3.c#L899

 This carries the same dependencies in enabled features as the above wc_Sha3Update commentary.

 This function is fallible via the preconditions, which are handled via the type system and
 borrow checker. These being the sha3 instance being null, and the data being null if the length
 is greater than zero.

 This then depends on the infallibility of Sha3Final, and Sha3Init, which we have already shown
 to be infallible.

 -- wc_Sha3Copy

 Src: https://github.com/wolfSSL/wolfssl/blob/master/wolfcrypt/src/sha3.c#L973

 This is only fallible if the WOLFSSL_ASYNC_CRYPT /\ WC_ASYNC_ENABLE_SHA3 features are enabled,
 which we have already discussed are not to be enabled as there's no practical advantage we have
 for them.

 They are OK for cheaper, old, processors where hardware acceleration with things such as AESNI
 are shared between cores, as then they somewhat operate asynchronously at the hardware level,
 but beyond this there's just no value, only complexity.

 Then, there's the functions preconditions, which are handled via the type system and borrow
 checker, these being the source or destination being null.

 -- wc_Sha3_[224 | 256 | 384 | 512]_[Update | Final | Copy]

 All the specific variants simply invoke the underlying associated wc_Sha3[Update | Final | Copy]
 function, propagating any error encountered. We have already shown that these functions are
 infallible.

 -- Conclusion

 All of wolfcrypt's Sha3 has been shown to be infallible under current conditions, related
 functions (SHAKE), while out of scope of this particular module, are also infallible due to their
 dependence on what we have already shown infallible. Their preconditions are all handled by the
 type system under all cases.

 ---- SHA2 FAMILY

 Src: https://github.com/wolfSSL/wolfssl/blob/master/wolfcrypt/src/sha256.c

 -- wc_InitSha[224 | 256 | 384 | 512 | 512_224 | 512_256]_ex

 This function is infallible under standard configurations. The only potential points of
 fallibility are:

 1. If (WOLFSSL_ASYNC_CRYPT /\ WC_ASYNC_ENABLE_SHA256) is enabled, which as discussed in the SHA3
    section, will not be enabled due to lack of practical advantage.
 2. On IMXRT1170 processors with WOLFSSL_IMXRT1170_CAAM enabled, the wc_CAAM_HashInit call could
    fail. Though this is discussed in the update checklist, and currently is considered infallible.

 Given this, wc_InitSha256_ex is to be considered infallible for our purposes.

 -- wc_Sha[224 | 256 | 384 | 512 | 512_224 | 512_256]Update

 This function's infallibility depends on the same conditions as wc_Sha3Update:

 It will always return zero unless (WOLF_CRYPTO_CB \/ (WOLFSSL_ASYNC_CRYPT /\ WC_ASYNC_ENABLE_SHA256))
 are enabled. As discussed in the SHA3 section, async crypt will not be enabled, and WOLF_CRYPTO_CB,
 while potentially enabled via a feature flag, is currently considered infallible per the upgrade
 guide.

 The function's preconditions (non-null sha256, len > 0 -> non-null data) are handled by the type
 system and borrow checker.

 The underlying Sha256Update function, which this calls, is infallible under all paths.

 Therefore, wc_Sha256Update is to be considered infallible.

 -- wc_Sha[224 | 256 | 384 | 512 | 512_224 | 512_256]Final

 This function's infallibility analysis is similar to wc_Sha256Update. It depends on the same 
 conditions regarding WOLF_CRYPTO_CB and async crypto, which we've established are currently 
 considered infallible.

 The function's preconditions (non-null sha256, non-null hash) are handled by the type system and 
 borrow checker.

 It calls Sha256Final, which is infallible under all paths, and InitSha256, which we've shown to be 
 infallible.

 Thus, wc_Sha256Final is to be considered infallible.

 -- wc_Sha[224 | 256 | 384 | 512 | 512_224 | 512_256]GetHash

 This function's infallibility depends on wc_Sha256Copy and wc_Sha256Final, both of which we have 
 shown to be infallible. Therefore, wc_Sha256GetHash is also infallible.

 -- wc_Sha[224 | 256 | 384 | 512 | 512_224 | 512_256]Copy

 This function is infallible under standard configurations. The only potential points of fallibility
 are:

 1. If WOLFSSL_ASYNC_CRYPT /\ WC_ASYNC_ENABLE_SHA256 are enabled, which we've established will not 
    be the case.
 2. For PIC32MZ platforms with WOLFSSL_PIC32MZ_HASH enabled, this is discussed in the wolfcrypt-sys
    update guidelines.
 3. If HAVE_ARIA is enabled and MC_CopySession fails. This is covered under the WOLF_CRYPTO_CB case.

 The function's preconditions (non-null src and dst) are handled by the type system and borrow 
 checker.

 Given these conditions, wc_Sha256Copy can be considered infallible for our purposes.

 -- Conclusion

 All of wolfcrypt's SHA2 functions have been shown to be infallible under current conditions and 
 standard configurations. The potential sources of fallibility (async crypto, specific platform 
 implementations, and certain cryptographic library integrations) are either not enabled or 
 outlined in the upgrade checklist and are to currently be considered infallible.
 
 All preconditions are handled by the type system and borrow checker. Therefore, for the purposes of
 this analysis, the SHA2 family can be considered infallible.
 
 END COMMENTARY
 
 Currently, this analysis is only acted on the HMAC implementation. Though, it is likely this 
 analysis will be taken advantage of in the `hash` module in an upcoming update.
*/
#[macro_use]
mod api_gen;

hidden! {
    pub mod sha224;
    pub mod sha256;
    pub mod sha384;
    pub mod sha512;
    pub mod sha512_256;
    pub mod sha512_224;
    pub mod sha3_224;
    pub mod sha3_256;
    pub mod sha3_384;
    pub mod sha3_512;
}

#[macro_use]
mod shake_api;

hidden! {
    pub mod shake128;
    pub mod shake256;
}

pub use {
    sha224::Sha224,
    sha256::Sha256,
    sha384::Sha384,
    sha512::Sha512,
    sha512_224::Sha512_224,
    sha512_256::Sha512_256,
    sha3_224::Sha3_224,
    sha3_256::Sha3_256,
    sha3_384::Sha3_384,
    sha3_512::Sha3_512,
    shake128::Shake128,
    shake256::Shake256
};

non_fips! {
    #[doc(hidden)]
    pub mod ripemd_160;
    pub use ripemd_160::RipeMd;

    #[doc(hidden)]
    pub mod md5;
    #[doc(hidden)]
    pub mod md4;

    pub use md5::Md5;
    pub use md4::Md4;

    #[doc(hidden)]
    pub mod sha;
    pub use sha::Sha;

    #[macro_use]
    mod blake_api;

    #[doc(hidden)]
    pub mod blake2b;
    pub use blake2b::Blake2b;

    #[doc(hidden)]
    pub mod blake2s;
    pub use blake2s::Blake2s;
}