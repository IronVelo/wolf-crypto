use wolf_crypto_sys::{
    wc_Sha3,
    wc_Sha3_224_Update, wc_Sha3_224_Final,
    wc_InitSha3_224, wc_Sha3_224_Free,
    wc_Sha3_224_Copy
};

mark_fips! { Sha3_224, Sealed }

make_api! {
    name: Sha3_224,
    wc: wc_Sha3,
    bs: 28,
    init: wc_InitSha3_224, heap: core::ptr::null_mut(), devid: wolf_crypto_sys::INVALID_DEVID,
    update: wc_Sha3_224_Update,
    finalize: wc_Sha3_224_Final,
    free: wc_Sha3_224_Free,
    copy: wc_Sha3_224_Copy
}