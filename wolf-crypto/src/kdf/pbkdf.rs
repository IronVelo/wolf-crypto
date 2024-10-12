//! The Password Based Key Derivation Function 1 and 2

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

/// Performs PBKDF2 and writes the result into the provided `out_key` buffer.
///
/// # Arguments
///
/// * `password` - The password to use for the key derivation.
/// * `salt`     - The salt to use for key derivation.
/// * `iters`    - The number of times to process the hash.
/// * `out_key`  - The buffer to write the generated key into.
///
/// # Errors
///
/// - The length of the `password` was greater than [`i32::MAX`].
/// - The length of the `salt` was greater than [`i32::MAX`].
/// - The number of `iters` was greater than [`i32::MAX`].
/// - The length of the `out_key` was greater than [`i32::MAX`].
///
/// ## FIPS Errors
///
/// If the `allow-non-fips` feature flag is disabled this will return an error if the `out_key`
/// length is not at least [`FIPS_MIN_KEY`] (14 bytes).
///
/// # Example
///
/// ```
/// use wolf_crypto::kdf::{pbkdf2_into, Sha256, Iters};
///
/// let password = b"my secret password";
/// let salt = [42; 16];
/// let iters = Iters::new(600_000).unwrap();
/// let mut out_key = [0u8; 32];
///
/// pbkdf2_into::<Sha256>(password, salt, iters, out_key.as_mut_slice()).unwrap();
/// ```
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

/// Performs PBKDF2 and returns the result as a fixed-size array.
///
/// # Arguments
///
/// * `password` - The password to use for the key derivation.
/// * `salt`     - The salt to use for key derivation.
/// * `iters`    - The number of times to process the hash.
///
/// # Errors
///
/// - The length of the `password` was greater than [`i32::MAX`].
/// - The length of the `salt` was greater than [`i32::MAX`].
/// - The number of `iters` was greater than [`i32::MAX`].
/// - The `KL` generic was greater than [`i32::MAX`].
///
/// ## FIPS Errors
///
/// If the `allow-non-fips` feature flag is disabled this will return an error if the `KL`
/// generic is not at least [`FIPS_MIN_KEY`] (14 bytes).
///
/// # Example
///
/// ```
/// use wolf_crypto::kdf::{pbkdf2, Sha256, Iters};
///
/// let password = b"my secret password";
/// let salt = [42; 16];
/// let iters = Iters::new(600_000).unwrap();
///
/// let key = pbkdf2::<32, Sha256>(password, salt, iters).unwrap();
/// assert_eq!(key.len(), 32);
/// ```
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

non_fips! {
    use wolf_crypto_sys::wc_PBKDF1;

    unsafe fn pbkdf1_unchecked<H: Hash>(
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

        // Infallible, see HMAC internal commentary as well as this crates hash module's infallibility
        // commentary.
        let _res = wc_PBKDF1(
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

    /// Performs PBKDF1 and writes the result into the provided `out_key` buffer.
    ///
    /// # Arguments
    ///
    /// * `password` - The password to use for the key derivation.
    /// * `salt`     - The salt to use for key derivation.
    /// * `iters`    - The number of times to process the hash.
    /// * `out_key`  - The buffer to write the generated key into.
    ///
    /// # Errors
    ///
    /// - The length of the `password` was greater than [`i32::MAX`].
    /// - The length of the `salt` was greater than [`i32::MAX`].
    /// - The number of `iters` was greater than [`i32::MAX`].
    /// - The length of the `out_key` was greater than [`i32::MAX`].
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::kdf::{pbkdf1_into, Sha256, Iters};
    ///
    /// let password = b"my secret password";
    /// let salt = [42; 16];
    /// let iters = Iters::new(600_000).unwrap();
    /// let mut out_key = [0u8; 32];
    ///
    /// pbkdf1_into::<Sha256>(password, salt, iters, out_key.as_mut_slice()).unwrap();
    /// ```
    pub fn pbkdf1_into<H: Hash>(
        password: &[u8],
        salt: impl Salt<MinSize>,
        iters: Iters,
        out_key: &mut [u8]
    ) -> Result<(), Unspecified> {
        if can_cast_i32(password.len())
            && salt.i_is_valid_size()
            && iters.is_valid_size()
            && check_key_len(out_key.len()) {
            unsafe { pbkdf1_unchecked::<H>(password, salt, iters, out_key) };
            Ok(())
        } else {
            Err(Unspecified)
        }
    }

    /// Performs PBKDF1 and returns the result as a fixed-size array.
    ///
    /// # Arguments
    ///
    /// * `password` - The password to use for the key derivation.
    /// * `salt`     - The salt to use for key derivation.
    /// * `iters`    - The number of times to process the hash.
    ///
    /// # Errors
    ///
    /// - The length of the `password` was greater than [`i32::MAX`].
    /// - The length of the `salt` was greater than [`i32::MAX`].
    /// - The number of `iters` was greater than [`i32::MAX`].
    /// - The `KL` generic was greater than [`i32::MAX`].
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::kdf::{pbkdf1, Sha256, Iters};
    ///
    /// let password = b"my secret password";
    /// let salt = [42; 16];
    /// let iters = Iters::new(600_000).unwrap();
    ///
    /// let key = pbkdf1::<32, Sha256>(password, salt, iters).unwrap();
    /// assert_eq!(key.len(), 32);
    /// ```
    pub fn pbkdf1<const KL: usize, H: Hash>(
        password: &[u8],
        salt: impl Salt<MinSize>,
        iters: Iters
    ) -> Result<[u8; KL], Unspecified> {
        if const_check_key_len::<KL>()
            && can_cast_i32(password.len())
            && salt.i_is_valid_size()
            && iters.is_valid_size() {
            let mut out = [0u8; KL];
            unsafe { pbkdf1_unchecked::<H>(password, salt, iters, out.as_mut_slice()) };
            Ok(out)
        } else {
            Err(Unspecified)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::{FipsSaltSlice, Sha256};

    macro_rules! bogus_slice {
        ($sz:expr) => {{
            unsafe { core::slice::from_raw_parts(b"bogus".as_ptr(), $sz) }
        }};
        (mut $sz:expr) => {{
            unsafe { core::slice::from_raw_parts_mut(b"bogus".as_ptr().cast_mut(), $sz) }
        }};
    }

    #[test]
    fn catch_pwd_overflow() {
        let pass = bogus_slice!(i32::MAX as usize + 1);
        assert!(pbkdf2::<32, Sha256>(pass, [0u8; 16], Iters::new(100).unwrap()).is_err());
        #[cfg(feature = "allow-non-fips")] {
            assert!(pbkdf1::<32, Sha256>(pass, [0u8; 16], Iters::new(100).unwrap()).is_err());
        }

        let mut out = [0; 69];
        assert!(pbkdf2_into::<Sha256>(pass, [0u8; 16], Iters::new(100).unwrap(), &mut out).is_err());
        #[cfg(feature = "allow-non-fips")] {
            assert!(pbkdf1_into::<Sha256>(pass, [0u8; 16], Iters::new(100).unwrap(), &mut out).is_err());
        }
    }

    #[test]
    fn catch_salt_overflow() {
        let salt = FipsSaltSlice::new(bogus_slice!(i32::MAX as usize + 1)).unwrap();
        let pass = b"my password";
        assert!(pbkdf2::<32, Sha256>(pass, salt.clone(), Iters::new(100).unwrap()).is_err());
        #[cfg(feature = "allow-non-fips")] {
            assert!(pbkdf1::<32, Sha256>(pass, salt.clone(), Iters::new(100).unwrap()).is_err());
        }

        let mut out = [0; 69];
        assert!(pbkdf2_into::<Sha256>(pass, salt.clone(), Iters::new(100).unwrap(), &mut out).is_err());
        #[cfg(feature = "allow-non-fips")] {
            assert!(pbkdf1_into::<Sha256>(pass, salt.clone(), Iters::new(100).unwrap(), &mut out).is_err());
        }
    }

    #[test]
    fn catch_iters_overflow() {
        let salt = [0u8; 16];
        let pass = b"my password";
        let iters = Iters::new(i32::MAX as u32 + 1).unwrap();
        assert!(pbkdf2::<32, Sha256>(pass, salt.clone(), iters).is_err());
        #[cfg(feature = "allow-non-fips")] {
            assert!(pbkdf1::<32, Sha256>(pass, salt.clone(), iters).is_err());
        }

        let mut out = [0; 69];
        assert!(pbkdf2_into::<Sha256>(pass, salt.clone(), iters, &mut out).is_err());
        #[cfg(feature = "allow-non-fips")] {
            assert!(pbkdf1_into::<Sha256>(pass, salt.clone(), iters, &mut out).is_err());
        }
    }

    #[test]
    fn catch_desired_key_overflow() {
        // we don't want to put u32 max on the stack, so we will not test the array convenience func
        // in this case.
        let desired = bogus_slice!(mut i32::MAX as usize + 1);
        let salt = [0u8; 16];
        let pass = b"my password";
        assert!(pbkdf2_into::<Sha256>(pass, salt.clone(), Iters::new(100).unwrap(), desired).is_err());
        #[cfg(feature = "allow-non-fips")] {
            assert!(pbkdf1_into::<Sha256>(pass, salt.clone(), Iters::new(100).unwrap(), desired).is_err());
        }
    }

    #[test]
    #[cfg_attr(feature = "allow-non-fips", ignore)]
    fn catch_fips_min_key() {
        let mut out = [0u8; 13];
        assert!(pbkdf2::<13, Sha256>(b"hello world", [0u8; 16], Iters::new(100).unwrap()).is_err());
        assert!(pbkdf2_into::<Sha256>(b"hello world", [0u8; 16], Iters::new(100).unwrap(), &mut out).is_err());
    }
}

#[cfg(test)]
mod property_tests {
    // TODO: impl NIST CAVS tests.

    use proptest::prelude::*;
    use crate::aes::test_utils::BoundList;
    use super::*;

    use crate::kdf::{Sha256, Sha384, Sha512};
    use crate::kdf::DynSaltSlice as SaltSlice;

    use pbkdf2::{pbkdf2_hmac};

    macro_rules! against_rc_into {
        (
            name: $name:ident,
            cases: $cases:literal,
            max_iters: $max_iters:literal,
            algo: $algo:ident
        ) => {proptest! {
            #![proptest_config(ProptestConfig::with_cases($cases))]

            #[test]
            fn $name(
                pwd in any::<BoundList<512>>(),
                salt in any::<BoundList<512>>(),
                // I do not have the remainder of the year to wait for this to pass. I've run this
                // with 100k on release, I ate a meal and it was still running.
                iters in 1..$max_iters,
                key_len in 1..1024usize
            ) {
                #[cfg(feature = "allow-non-fips")] {
                    prop_assume!(!salt.as_slice().is_empty());
                }

                #[cfg(not(feature = "allow-non-fips"))] {
                    prop_assume!(salt.len() >= 16);
                    prop_assume!(key_len >= 14);
                }

                let mut key_buf = BoundList::<1024>::new_zeroes(key_len);
                let mut rc_key_buf = key_buf.create_self();

                pbkdf2_into::<$algo>(
                    pwd.as_slice(),
                    SaltSlice::new(salt.as_slice()).unwrap(),
                    Iters::new(iters).unwrap(),
                    key_buf.as_mut_slice()
                ).unwrap();

                pbkdf2_hmac::<sha2::$algo>(
                    pwd.as_slice(),
                    salt.as_slice(),
                    iters,
                    rc_key_buf.as_mut_slice()
                );

                prop_assert_eq!(key_buf.as_slice(), rc_key_buf.as_slice());
            }
        }};
    }

    against_rc_into! {
        name: rust_crypto_equivalence_sha256,
        cases: 5000,
        max_iters: 100u32,
        algo: Sha256
    }

    against_rc_into! {
        name: rust_crypto_equivalence_sha384,
        cases: 5000,
        max_iters: 100u32,
        algo: Sha384
    }

    against_rc_into! {
        name: rust_crypto_equivalence_sha512,
        cases: 5000,
        max_iters: 50u32,
        algo: Sha512
    }
}