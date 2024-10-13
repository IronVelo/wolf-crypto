use wolf_crypto_sys::{
    wc_Shake,
    wc_Shake256_Update, wc_Shake256_Final,
    wc_InitShake256, wc_Shake256_Free,
    wc_Shake256_Copy
};

mark_fips! { Shake256, Sealed }

shake_api! {
    name: Shake256,
    wc: wc_Shake,
    ds: 64,
    init: wc_InitShake256, heap: core::ptr::null_mut(), devid: wolf_crypto_sys::INVALID_DEVID,
    update: wc_Shake256_Update,
    finalize: wc_Shake256_Final,
    free: wc_Shake256_Free,
    copy: wc_Shake256_Copy
}