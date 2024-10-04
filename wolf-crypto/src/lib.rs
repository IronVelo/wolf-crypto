#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![warn(
    clippy::pedantic,
    clippy::nursery,
    clippy::all
)]
// requirements for lower level things, these are all checked, just not checked in the unsafe
// api.
#![allow(clippy::cast_possible_truncation)]
// stupid lint IMO
#![allow(clippy::module_name_repetitions)]
// always checked in safe api
#![allow(clippy::cast_possible_wrap)]
// this devalues things which actually require the must-use attribute
#![allow(clippy::must_use_candidate)]
// I am passing something which is 32 bits, so either half the size (more frequently) or the same
// size as the reference. This lint needs to be more context aware as this is just bad.
#![allow(clippy::needless_pass_by_value)]
// I don't care for the assertion in my panic API where I am checking if OK. This is just for
// more controlled error messages. Again, should be disabled
#![allow(clippy::manual_assert)]
// I don't need a linter lecturing me on performance
#![allow(clippy::inline_always)]
// I am doing constant time bitwise hacks
#![allow(clippy::cast_sign_loss)]

#[cfg(any(test, feature = "alloc"))]
extern crate alloc;

#[cfg(test)]
extern crate std;
// extern crate core;

#[macro_use]
mod macros;

mod ptr;
pub mod buf;
pub mod opaque_res;
mod sealed;

// TODO: FURTHER TESTING.
// pub mod random;
pub mod aes;
pub mod hash;
mod error;

non_fips! { // unfortunate
    pub mod chacha;
}

pub mod aead;
pub mod mac;

pub use error::Unspecified;
pub use error::MakeOpaque;

#[must_use]
pub(crate) const fn const_can_cast_u32<const S: usize>() -> bool {
    const_lte::<S, { u32::MAX }>()
}

#[inline]
#[must_use]
pub(crate) const fn can_cast_u32(len: usize) -> bool {
    len <= (u32::MAX as usize)
}

#[must_use]
pub(crate) const fn const_lte<const L: usize, const MAX: u32>() -> bool {
    L <= (MAX as usize)
}

#[must_use]
pub(crate) const fn const_gte<const L: usize, const MIN: usize>() -> bool {
    L >= MIN
}

#[allow(dead_code)]
#[inline]
#[must_use]
pub(crate) const fn lte<const MAX: usize>(value: usize) -> bool {
    value <= MAX
}

#[inline]
#[must_use]
pub(crate) const fn gte<const MIN: usize>(value: usize) -> bool {
    value >= MIN
}

#[inline]
#[must_use]
pub(crate) const fn to_u32(num: usize) -> Option<u32> {
    if can_cast_u32(num) {
        Some(num as u32)
    } else {
        None
    }
}