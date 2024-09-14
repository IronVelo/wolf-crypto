use wolf_crypto_sys::{
    wc_Sha224,
    wc_Sha224Update, wc_Sha224Final,
    wc_InitSha224, wc_Sha224Free,
    wc_Sha224Copy
};

make_api! {
    name: Sha224,
    wc: wc_Sha224,
    bs: 28,
    init: wc_InitSha224,
    update: wc_Sha224Update,
    finalize: wc_Sha224Final,
    free: wc_Sha224Free,
    copy: wc_Sha224Copy
}