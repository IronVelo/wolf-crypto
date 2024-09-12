#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_builtins)]

#[macro_use]
mod macros;

pub mod ptr;
pub mod buf;
pub mod opaque_res;
mod sealed;

// TODO: FURTHER TESTING.
// pub mod random;
pub mod aes;
pub mod hash;

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