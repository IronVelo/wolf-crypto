use wolf_crypto_sys::{
    wc_Sha3,
    wc_Sha3_256_Update, wc_Sha3_256_Final,
    wc_InitSha3_256, wc_Sha3_256_Free,
};

make_api! {
    name: Sha3_256,
    wc: wc_Sha3,
    bs: 32,
    init: wc_InitSha3_256, heap: core::ptr::null_mut(), devid: wolf_crypto_sys::INVALID_DEVID,
    update: wc_Sha3_256_Update,
    finalize: wc_Sha3_256_Final,
    free: wc_Sha3_256_Free
}