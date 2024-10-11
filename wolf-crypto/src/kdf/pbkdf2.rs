//! The Password Based Key Derivation Function 2 (PBKDF2)

use wolf_crypto_sys::{wc_PBKDF2};

use crate::{can_cast_i32, const_can_cast_i32, Unspecified};
use crate::kdf::{Salt, Iters};

#[cfg(feature = "allow-non-fips")]
use crate::kdf::salt::NonEmpty as MinSize;

#[cfg(not(feature = "allow-non-fips"))]
use crate::kdf::salt::Min16 as MinSize;

use crate::mac::hmac::algo::Hash;

/// The minimum output key length as stated in [SP 800-132, Section 5][1].
///
/// ```text
/// The kLen value shall be at least 112 bits in length.
/// ```
///
/// [1]: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf#%5B%7B%22num%22%3A16%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22XYZ%22%7D%2C0%2C399%2Cnull%5D
pub const FIPS_MIN_KEY: usize = 14;

unsafe fn pbkdf2_unchecked<H: Hash>(
    password: &[u8],
    salt: impl Salt<MinSize>,
    iters: Iters,
    out: &mut [u8]
) {
    debug_assert!(
        can_cast_i32(out.len())
            && can_cast_i32(password.len())
            && salt.i_is_valid_size()
            && iters.is_valid_size()
    );
    #[cfg(not(feature = "allow-non-fips"))] {
        debug_assert!(out.len() >= FIPS_MIN_KEY);
    }

    // Infallible, see HMAC internal commentary as well as this crates hash module's infallibility
    // commentary.
    let _res = wc_PBKDF2(
        out.as_mut_ptr(),
        password.as_ptr(),
        password.len() as i32,
        salt.ptr(),
        salt.i_size(),
        iters.get() as i32,
        out.len() as i32,
        H::type_id()
    );

    debug_assert_eq!(_res, 0);
}

#[cfg(not(feature = "allow-non-fips"))]
#[inline]
#[must_use]
const fn check_key_len(len: usize) -> bool {
    can_cast_i32(len) && len >= FIPS_MIN_KEY
}

#[cfg(feature = "allow-non-fips")]
#[inline]
#[must_use]
const fn check_key_len(len: usize) -> bool {
    can_cast_i32(len)
}

#[cfg(not(feature = "allow-non-fips"))]
#[inline]
#[must_use]
const fn const_check_key_len<const L: usize>() -> bool {
    const_can_cast_i32::<L>() && L >= FIPS_MIN_KEY
}

#[cfg(feature = "allow-non-fips")]
#[inline]
#[must_use]
const fn const_check_key_len<const L: usize>() -> bool {
    const_can_cast_i32::<L>()
}

pub fn pbkdf2_into<H: Hash>(
    password: &[u8],
    salt: impl Salt<MinSize>,
    iters: Iters,
    out_key: &mut [u8]
) -> Result<(), Unspecified> {
    if can_cast_i32(password.len())
        && salt.i_is_valid_size()
        && iters.is_valid_size()
        && check_key_len(out_key.len()) {
        unsafe { pbkdf2_unchecked::<H>(password, salt, iters, out_key) };
        Ok(())
    } else {
        Err(Unspecified)
    }
}

pub fn pbkdf2<const KL: usize, H: Hash>(
    password: &[u8],
    salt: impl Salt<MinSize>,
    iters: Iters
) -> Result<[u8; KL], Unspecified> {
    if const_check_key_len::<KL>()
        && can_cast_i32(password.len())
        && salt.i_is_valid_size()
        && iters.is_valid_size() {
        let mut out = [0u8; KL];
        unsafe { pbkdf2_unchecked::<H>(password, salt, iters, out.as_mut_slice()) };
        Ok(out)
    } else {
        Err(Unspecified)
    }
}