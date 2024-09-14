use wolf_crypto_sys::{
    wc_Sha384,
    wc_Sha384Update, wc_Sha384Final,
    wc_InitSha384, wc_Sha384Free,
    wc_Sha384Copy
};

make_api! {
    name: Sha384,
    wc: wc_Sha384,
    bs: 48,
    init: wc_InitSha384,
    update: wc_Sha384Update,
    finalize: wc_Sha384Final,
    free: wc_Sha384Free,
    copy: wc_Sha384Copy
}