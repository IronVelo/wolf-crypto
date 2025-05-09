use wolf_crypto_sys::{
    wc_Shake,
    wc_Shake128_Update, wc_Shake128_Final,
    wc_InitShake128, wc_Shake128_Free, wc_Shake128_Copy
};

mark_fips! { Shake128, Sealed }

shake_api! {
    name: Shake128,
    wc: wc_Shake,
    ds: 32,
    init: wc_InitShake128, heap: core::ptr::null_mut(), devid: wolf_crypto_sys::INVALID_DEVID,
    update: wc_Shake128_Update,
    finalize: wc_Shake128_Final,
    free: wc_Shake128_Free,
    copy: wc_Shake128_Copy
}