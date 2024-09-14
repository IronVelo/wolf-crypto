use wolf_crypto_sys::{
    wc_Sha,
    wc_ShaUpdate, wc_ShaFinal,
    wc_InitSha, wc_ShaFree,
    wc_ShaCopy
};

make_api! {
    sec_warning: "",
    "The SHA-1 algorithm is included in this library for legacy reasons only. It is \
    cryptographically broken and should not be used for any security-critical applications, \
    especially digital signatures or certificate validation.",
    "",
    "The U.S. National Institute of Standards and Technology (NIST) has officially deprecated SHA-1 \
    for all digital signature uses as of 2011. As of 2022, NIST recommends transitioning all \
    applications to use SHA-2, Keccak (SHA-3) family hash functions.",
    "",
    "For more information, refer to \
    [NIST's policy on hash functions](https://csrc.nist.gov/projects/hash-functions/nist-policy-on-hash-functions).",
    "",
    "Use this algorithm only if absolutely necessary for backwards compatibility with legacy \
    systems. For all other purposes, please use more secure alternatives such as the SHA-2, SHA-3, \
    and Blake2 family hash functions.",
    anecdote: "-1",
    name: Sha,
    wc: wc_Sha,
    bs: 20,
    init: wc_InitSha,
    update: wc_ShaUpdate,
    finalize: wc_ShaFinal,
    free: wc_ShaFree,
    copy: wc_ShaCopy
}