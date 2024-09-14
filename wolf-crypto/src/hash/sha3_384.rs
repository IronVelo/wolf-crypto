use wolf_crypto_sys::{
    wc_Sha3,
    wc_Sha3_384_Update, wc_Sha3_384_Final,
    wc_InitSha3_384, wc_Sha3_384_Free,
    wc_Sha3_384_Copy
};

make_api! {
    name: Sha3_384,
    wc: wc_Sha3,
    bs: 48,
    init: wc_InitSha3_384, heap: core::ptr::null_mut(), devid: wolf_crypto_sys::INVALID_DEVID,
    update: wc_Sha3_384_Update,
    finalize: wc_Sha3_384_Final,
    free: wc_Sha3_384_Free,
    copy: wc_Sha3_384_Copy
}