//! Message Authentication Codes

non_fips! {
    pub mod poly1305;
    pub use poly1305::Poly1305;
}