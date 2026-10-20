//! Optional Verus-verified layer over wolf-crypto.
//!
//! Prototype: AES-GCM with a proved nonce-uniqueness discipline. See
//! `README.org` in this crate's directory for the design, the trusted base
//! and the roadmap.
//!
//! Without Verus this crate builds as ordinary Rust: the `verus!` macro erases
//! specifications, proofs and ghost state, leaving the executable code
//! (runtime length checks, the counter sealer, zeroization) unchanged.
//!
//! Module trust levels:
//!
//! - [`spec`]: TRUSTED abstract model of AES-GCM (uninterpreted functions and
//!   functional axioms).
//! - [`ffi`]: TRUSTED `external_body` contracts over wolf-crypto.
//! - [`nonce`], [`gcm`], [`sealer`]: VERIFIED wrapper logic; the only trusted
//!   item in [`sealer`] is `DurableMark::assume_persisted`.
#![no_std]
#![forbid(unsafe_code)]

pub mod spec;
pub mod ffi;
pub mod nonce;
pub mod gcm;
pub mod sealer;

#[cfg(verus)]
mod client_checks;

pub use ffi::{CryptoError, Gcm, NonceLedger};
pub use gcm::OpenError;
pub use sealer::{ConfigError, CounterSealer, DurableMark, SealError};
