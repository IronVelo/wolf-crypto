use wolf_crypto_sys::{
    wc_Sha256,
    wc_Sha256Update, wc_Sha256Final,
    wc_InitSha256, wc_Sha256Free,
    wc_Sha256Copy
};

mark_fips! { Sha256, Sealed }

make_api! {
    name: Sha256,
    wc: wc_Sha256,
    bs: 32,
    init: wc_InitSha256,
    update: wc_Sha256Update,
    finalize: wc_Sha256Final,
    free: wc_Sha256Free,
    copy: wc_Sha256Copy
}
