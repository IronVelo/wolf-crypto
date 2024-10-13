use wolf_crypto_sys::{
    wc_Sha3,
    wc_Sha3_512_Update, wc_Sha3_512_Final,
    wc_InitSha3_512, wc_Sha3_512_Free,
    wc_Sha3_512_Copy
};

mark_fips! { Sha3_512, Sealed }

make_api! {
    name: Sha3_512,
    wc: wc_Sha3,
    bs: 64,
    init: wc_InitSha3_512, heap: core::ptr::null_mut(), devid: wolf_crypto_sys::INVALID_DEVID,
    update: wc_Sha3_512_Update,
    finalize: wc_Sha3_512_Final,
    free: wc_Sha3_512_Free,
    copy: wc_Sha3_512_Copy
}
