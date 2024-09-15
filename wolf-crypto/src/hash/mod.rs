//! Cryptographic Hash Algorithms

#[macro_use]
mod api_gen;

hidden! {
    pub mod sha224;
    pub mod sha256;
    pub mod sha384;
    pub mod sha512;
    pub mod sha512_256;
    pub mod sha512_224;
    pub mod sha3_224;
    pub mod sha3_256;
    pub mod sha3_384;
    pub mod sha3_512;
}

#[macro_use]
mod shake_api;

hidden! {
    pub mod shake128;
    pub mod shake256;
}

pub use {
    sha224::Sha224,
    sha256::Sha256,
    sha384::Sha384,
    sha512::Sha512,
    sha512_224::Sha512_224,
    sha512_256::Sha512_256,
    sha3_224::Sha3_224,
    sha3_256::Sha3_256,
    sha3_384::Sha3_384,
    sha3_512::Sha3_512,
    shake128::Shake128,
    shake256::Shake256
};

non_fips! {
    #[doc(hidden)]
    pub mod ripemd_160;
    pub use ripemd_160::RipeMd;

    #[doc(hidden)]
    pub mod md5;
    #[doc(hidden)]
    pub mod md4;

    pub use md5::Md5;
    pub use md4::Md4;

    #[doc(hidden)]
    pub mod sha;
    pub use sha::Sha;

    #[macro_use]
    mod blake_api;

    #[doc(hidden)]
    pub mod blake2b;
    pub use blake2b::Blake2b;

    #[doc(hidden)]
    pub mod blake2s;
    pub use blake2s::Blake2s;
}