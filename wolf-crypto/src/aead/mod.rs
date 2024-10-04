mod aad;
mod tag;
mod aes_gcm;

pub use aad::{Aad, AadSlice};
pub use tag::Tag;

#[doc(inline)]
pub use aes_gcm::AesGcm;

non_fips! { // unfortunate
    pub mod chacha20_poly1305;
    #[doc(inline)]
    pub use chacha20_poly1305::ChaCha20Poly1305;
}