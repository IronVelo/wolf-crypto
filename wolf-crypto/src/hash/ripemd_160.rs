use wolf_crypto_sys::{
    RipeMd as wc_RipeMd,
    wc_RipeMdUpdate, wc_RipeMdFinal,
    wc_InitRipeMd
};

make_api! {
    anecdote: "-160",
    name: RipeMd,
    wc: wc_RipeMd,
    bs: 20,
    init: wc_InitRipeMd,
    update: wc_RipeMdUpdate,
    finalize: wc_RipeMdFinal
}