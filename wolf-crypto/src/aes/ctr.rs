use core::ptr::{addr_of_mut};
use wolf_crypto_sys::{Aes as AesLL, wc_AesCtrEncrypt, wc_AesSetKey, wc_AesFree};
use crate::aes::{Key, init_aes, AesM};
use crate::ptr::{ConstPtr};
use core::ffi::c_int;
use crate::buf::Iv;
use crate::opaque_res::Res;
use core::mem::MaybeUninit;

#[must_use]
#[cfg_attr(not(debug_assertions), inline(always))]
pub(crate) unsafe fn init_aes_ctr(
    aes: *mut AesLL, key: ConstPtr<Key>, iv: ConstPtr<Iv>, mode: AesM
) -> c_int {
    wc_AesSetKey(
        aes,
        key.as_slice().as_ptr(),
        key.capacity() as u32,
        iv.slice().as_ptr(),
        mode.mode() as c_int
    )
}

#[must_use]
#[inline]
pub(crate) unsafe fn create_aes_ctr(
    key: ConstPtr<Key>, iv: ConstPtr<Iv>, mode: AesM
) -> (MaybeUninit<AesLL>, Res) {
    let (mut aes, mut res) = init_aes(MaybeUninit::<AesLL>::uninit());

    // NOTE: It looks as though the `wc_AesSetKey` can handle `wc_AesInit` failing from this
    // example:
    // https://www.wolfssl.com/documentation/manuals/wolfssl/group__AES.html#function-wc_aessetkey
    // This requires testing to back up this assumption.

    res.ensure_0(init_aes_ctr(aes.as_mut_ptr(), key, iv, mode));

    (aes, res)
}

#[inline]
#[must_use]
const fn size_predicate(len: usize) -> bool {
    len <= (u32::MAX as usize)
}

#[inline]
#[must_use]
const fn larger(left: usize, right: usize) -> usize {
    if left < right {
        right
    } else {
        left
    }
}

#[inline]
#[must_use]
const fn predicate(input_len: usize, output_len: usize) -> bool {
    let larger = larger(input_len, output_len);
    input_len <= output_len && size_predicate(larger)
}

macro_rules! impl_aes_api {
    (
        $(#[$ll_meta:meta])*
        unsafe => $ll_ident:ident,
        $(#[$sized_meta:meta])*
        sized => $sized_ident:ident,
        $(#[$try_meta:meta])*
        try => $try_ident:ident,
        $(#[$panics_meta:meta])*
        panics => $panics_ident:ident $(,)?
    ) => {
        $(#[$sized_meta])*
        #[inline]
        pub fn $sized_ident<const S: usize>(
            &mut self, input: &[u8; S], output: &mut [u8; S]
        ) -> Res {
            if !size_predicate(S) {
                return Res::ERR
            }
            unsafe {
                // SAFETY: Output size is guaranteed from type system to be at least the size
                // (or in this case equivalent) of the input.
                self.$ll_ident(input.as_slice(), output.as_mut_slice())
            }
        }

        $(#[$try_meta])*
        #[inline]
        pub fn $try_ident(&mut self, input: &[u8], output: &mut [u8]) -> Res {
            if !predicate(input.len(), output.len()) {
                return Res::ERR
            }

            unsafe {
                // SAFETY: `Self::predicate` ensures output is at least the size of input and
                // that the size does not overflow on u32 cast.
                self.$ll_ident(input, output)
            }
        }

        #[cfg(feature = "panic-api")]
        $(#[$panics_meta])*
        pub fn $panics_ident(&mut self, input: &[u8], output: &mut [u8]) {
            if self.$try_ident(input, output).is_err() {
                panic!("Failed to apply keystream");
            }
        }

        $(#[$ll_meta])*
        pub unsafe fn $ll_ident(&mut self, input: &[u8], output: &mut [u8]) -> Res {
            let mut res = Res::new();

            res.ensure_0(wc_AesCtrEncrypt(
                addr_of_mut!(self.inner),
                output.as_mut_ptr(),
                input.as_ptr(),
                input.len() as u32
            ));

            res
        }
    };
}

macro_rules! impl_aes_type {
    (
        $(#[$struct_meta:meta])*
        struct $s_ident:ident,
        direction $dir:ident,
        api {
            $(#[$new_meta:meta])*
            $new_vis:vis new,
            $(#[$ll_meta:meta])*
            unsafe => $ll_ident:ident,
            $(#[$sized_meta:meta])*
            sized => $sized_ident:ident,
            $(#[$try_meta:meta])*
            try => $try_ident:ident,
            $(#[$panics_meta:meta])*
            panics => $panics_ident:ident $(,)?
        }
    ) => {
        $(#[$struct_meta])*
        #[repr(transparent)]
        pub struct $s_ident {
            inner: AesLL,
        }

        impl $s_ident {
            $(#[$new_meta])*
            $new_vis fn new(key: &Key, iv: &Iv) -> Result<Self, ()> {
                let key_ptr = ConstPtr::new(key as *const Key);
                let nonce_ptr = ConstPtr::new(iv as *const Iv);

                unsafe {
                    let (aes_ll, res) = create_aes_ctr(key_ptr, nonce_ptr, AesM::$dir);
                    res.unit_err_with(|| Self::with_aes(aes_ll.assume_init()))
                }
            }

            #[inline]
            const fn with_aes(inner: AesLL) -> Self {
                Self { inner }
            }

            impl_aes_api! {
                $(#[$ll_meta])*
                unsafe => $ll_ident,
                $(#[$sized_meta])*
                sized => $sized_ident,
                $(#[$try_meta])*
                try => $try_ident,
                $(#[$panics_meta])*
                panics => $panics_ident
            }
        }

        impl Drop for $s_ident {
            #[inline]
            fn drop(&mut self) {
                unsafe {
                    // SAFETY:
                    //
                    // We are in the drop implementation, so we are never going to be using the
                    // `Aes` type again. Since we are configured to not malloc, this simply zeroes
                    // the secrets that were copied on `wc_AesSetKey` invocation. I wish there
                    // was a way to avoid the copying as I do not like secrets living in memory
                    // more than once, but I understand the decision to do this for ensuring safety.
                    wc_AesFree(addr_of_mut!(self.inner));
                }
            }
        }
    };
}

impl_aes_type! {
    struct AesCtr,
    direction ENCRYPT,
    api {
        /// Create a new AES CTR instance.
        ///
        /// # Arguments
        ///
        /// * `key`   - The key material to use (which determines the number of rounds).
        /// * `iv` - The initialization vector (nonce).
        ///
        /// # Returns
        ///
        /// A new AES instance in CTR mode.
        ///
        /// # Note
        ///
        /// This copies the key and nonce in the underlying C code and is out of scope of this Rust
        /// API. At the end of the `AesCtr`'s lifetime these will be zeroed. It may be desirable
        /// to immediately zero the key and nonce passed to this function by reference post
        /// invocation.
        pub new,

        /// Apply the underlying keystream to the output buffer.
        ///
        /// This method performs no runtime safety checks.
        ///
        /// # Safety
        ///
        /// - The `output` buffer must be at least the size of the `input`.
        /// - The size of both buffers must be representable by an `unsigned int` (u32).
        ///
        /// # Arguments
        ///
        /// * `input` - The input to apply the keystream to.
        /// * `output` - The output buffer to store the result of applying the keystream.
        ///
        /// # Errors
        ///
        /// If the application of the keystream failed.
        ///
        /// # Example
        ///
        /// ```
        /// use wolf_crypto::{buf::Iv, aes::{Key, ctr::AesCtr}};
        ///
        /// // securely generate a random key and initialization vector ...
        /// # let mut key = Key::Aes256([1u8; 32]);
        /// # let iv = Iv::new([2u8; 16]);
        ///
        /// let mut input = [1u8; 32];
        /// let mut output = [0u8; 32];
        ///
        /// # unsafe {
        /// assert!(AesCtr::new(&key, &iv)
        ///     .unwrap()
        ///     .apply_keystream_unchecked(input.as_slice(), output.as_mut_slice())
        ///     .is_ok());
        /// # }
        ///
        /// assert_ne!(&output, &input);
        ///
        /// // and decrypt
        ///
        /// let mut original = [0u8; 32];
        /// # unsafe {
        /// assert!(AesCtr::new(&key, &iv)
        ///     .apply_keystream_unchecked(output.as_slice(), original.as_mut_slice())
        ///     .is_ok());
        /// # }
        ///
        /// assert_eq!(&original, &input);
        ///
        /// key.zero();
        /// ```
        unsafe => apply_keystream_unchecked,

        /// Apply the underlying keystream to the output buffer, with the size of both the input and
        /// output buffers described at compile time to avoid most runtime checks.
        ///
        /// # Arguments
        ///
        /// * `input` - The input to apply the keystream to.
        /// * `output` - The output buffer to store the result of applying the keystream.
        ///
        /// # Errors
        ///
        /// - If the application of the keystream failed.
        /// - (Unlikely) If the size of the input and output buffer is greater than what can be
        ///   represented by an `unsigned int` (u32).
        ///
        /// # Example
        ///
        /// ```
        /// use wolf_crypto::{buf::Iv, aes::{Key, ctr::AesCtr}};
        /// // securely generate a random key and initialization vector ...
        /// # let mut key = Key::Aes256([1u8; 32]);
        /// # let iv = Iv::new([2u8; 16]);
        ///
        /// let mut input = [1u8; 32];
        /// let mut output = [0u8; 32];
        ///
        /// assert!(AesCtr::new(&key, &iv)
        ///     .unwrap()
        ///     .apply_keystream_sized(&input, &mut output)
        ///     .is_ok());
        ///
        /// assert_ne!(&input, &output);
        /// assert_ne!(output, [0u8; 32]);
        ///
        /// // and decrypt
        ///
        /// let mut plain = [0u8; 32];
        /// assert!(AesCtr::new(&key, &iv)
        ///     .unwrap()
        ///     .apply_keystream_sized(&output, &mut plain)
        ///     .is_ok());
        ///
        /// assert_eq!(&plain, &input);
        /// key.zero();
        /// ```
        sized => apply_keystream_sized,

        /// Try to apply the underlying keystream to the output buffer.
        ///
        /// # Arguments
        ///
        /// * `input` - The input to apply the keystream to.
        /// * `output` - The output buffer to store the result of applying the keystream.
        ///
        /// # Errors
        ///
        /// - If the application of the keystream failed.
        /// - If the `input` buffer is larger than the `output` buffer.
        /// - (Unlikely) If the size of the `input` or `output` buffer is greater than what can be
        ///   represented by an `unsigned int` (u32).
        ///
        /// # Example
        ///
        /// ```
        /// use wolf_crypto::{buf::Iv, aes::{Key, ctr::AesCtr}};
        /// // securely generate a random key and initialization vector ...
        /// # let mut key = Key::Aes256([1u8; 32]);
        /// # let iv = Iv::new([2u8; 16]);
        ///
        /// let mut input = [1u8; 32];
        /// let mut output = [0u8; 32];
        ///
        /// assert!(AesCtr::new(&key, &iv)
        ///     .unwrap()
        ///     .try_apply_keystream(input.as_slice(), output.as_mut_slice())
        ///     .is_ok());
        ///
        /// assert_ne!(&input, &output);
        /// assert_ne!(output, [0u8; 32]);
        ///
        /// // and decrypt
        ///
        /// let mut plain = [0u8; 32];
        /// assert!(AesCtr::new(&key, &iv)
        ///     .unwrap()
        ///     .try_apply_keystream(output.as_slice(), plain.as_mut_slice())
        ///     .is_ok());
        ///
        /// assert_eq!(&plain, &input);
        /// key.zero();
        /// ```
        try => try_apply_keystream,

        /// Apply the underlying keystream to the output buffer using the encryption key.
        ///
        /// # Arguments
        ///
        /// * `input` - The input to apply the keystream to.
        /// * `output` - The output buffer to store the result of applying the keystream.
        ///
        /// # Panics
        ///
        /// - If the application of the keystream failed.
        /// - If the `input` buffer is larger than the `output` buffer.
        /// - (Unlikely) If the size of the `input` or `output` buffer is greater than what can be
        ///   represented by an `unsigned int` (u32).
        ///
        /// # Example
        ///
        /// ```
        /// use wolf_crypto::{buf::Iv, aes::{Key, ctr::AesCtr}};
        /// // securely generate a random key and initialization vector ...
        /// # let mut key = Key::Aes256([1u8; 32]);
        /// # let iv = Iv::new([2u8; 16]);
        ///
        /// let mut input = [1u8; 32];
        /// let mut output = [0u8; 32];
        ///
        /// AesCtr::new(&key, &iv)
        ///     .unwrap()
        ///     .apply_keystream(input.as_slice(), output.as_mut_slice());
        ///
        /// assert_ne!(&input, &output);
        /// assert_ne!(output, [0u8; 32]);
        ///
        /// // and decrypt
        ///
        /// let mut plain = [0u8; 32];
        /// AesCtr::new(&key, &iv)
        ///     .unwrap()
        ///     .apply_keystream(output.as_slice(), plain.as_mut_slice());
        ///
        /// assert_eq!(&plain, &input);
        /// key.zero();
        /// ```
        panics => apply_keystream
    }
}

// SAFETY:
// All methods which mutate the underlying AES instance require a mutable reference,
// the only way to obtain a mutable reference across thread boundaries is via synchronization or
// unsafe in Rust (which then would be the user's responsibility).
unsafe impl Send for AesCtr {}

// SAFETY:
// There is no providing of interior mutability in the `AesCtr`, all methods which mutate the
// underlying AES instance require a mutable reference, thus making this safe to mark `Sync`.
unsafe impl Sync for AesCtr {}

#[cfg(test)]
mod tests {
    use ctr::Ctr128BE;
    use aes::Aes256;
    use ctr::cipher::{KeyIvInit, StreamCipher};
    use super::*;

    #[test]
    fn apply_smoke() {
        let key = Key::Aes256([7; 32]);
        let nonce = [0u8; 16].into();

        let mut ctr = AesCtr::new(&key, &nonce).unwrap();

        let input = [0u8; 12];
        let mut output = [0u8; 12];

        assert!(ctr.apply_keystream_sized(&input, &mut output).is_ok());

        let mut output2 = [0u8; 12];
        assert!(ctr.apply_keystream_sized(&input, &mut output2).is_ok());

        assert_ne!(output, output2);
    }

    #[test]
    fn against_ctr_rust_crypto_smoke() {
        let key = Key::Aes256([7; 32]);
        let nonce = [3; 16].into();
        let mut ctr = AesCtr::new(&key, &nonce).unwrap();

        let mut rc_ctr = Ctr128BE::<Aes256>::new_from_slices(
            key.as_slice(), nonce.slice()
        ).unwrap();

        let input = [0u8; 12];
        let mut out = [0u8; 12];
        let mut out_rc = [0u8; 12];

        rc_ctr.apply_keystream_b2b(input.as_slice(), out_rc.as_mut_slice()).unwrap();
        ctr.apply_keystream(input.as_slice(), out.as_mut_slice());

        assert_eq!(out, out_rc);
    }

    #[test]
    fn self_bijective_smoke() {
        let key = Key::Aes256([7; 32]);
        let nonce = [1u8; 16].into();

        let mut ctr = AesCtr::new(&key, &nonce).unwrap();

        let input = [1u8; 12];
        let mut output = [0u8; 12];

        assert!(ctr.apply_keystream_sized(&input, &mut output).is_ok());
        assert_ne!(output, input);

        let mut decrypt_ctr = AesCtr::new(&key, &nonce).unwrap();

        let mut plain = [0u8; 12];
        assert!(decrypt_ctr.apply_keystream_sized(&output, &mut plain).is_ok());

        assert_eq!(plain, input);
    }

    #[test]
    fn precondition_ensured() {
        let input = [0u8; 12];
        let mut output = [0u8; 11];

        let key = Key::Aes256([7; 32]);
        let nonce = [1u8; 16].into();

        let res = AesCtr::new(&key, &nonce).unwrap()
            .try_apply_keystream(input.as_slice(), output.as_mut_slice());

        assert!(res.is_err());
    }
}

#[cfg(all(test, not(miri)))]
mod property_tests {
    use aes::{Aes256, Aes192, Aes128};
    use ctr::cipher::{KeyIvInit, StreamCipher};
    use ctr::Ctr128BE;
    use proptest::prelude::*;
    use crate::aes::test_utils::*;
    use super::*;

    macro_rules! with_rust_crypto_ctr {
        ($key:expr, $nonce:expr, |$ctr:ident| $do:expr) => {
            match $key {
                Key::Aes256(buf) => {
                    let mut $ctr = Ctr128BE::<Aes256>::new_from_slices(
                        buf.as_slice(), $nonce.slice()
                    ).unwrap();

                    $do
                },
                Key::Aes128(buf) => {
                    let mut $ctr = Ctr128BE::<Aes128>::new_from_slices(
                        buf.as_slice(), $nonce.slice()
                    ).unwrap();

                    $do
                },
                Key::Aes192(buf) => {
                    let mut $ctr = Ctr128BE::<Aes192>::new_from_slices(
                        buf.as_slice(), $nonce.slice()
                    ).unwrap();

                    $do
                }
            }
        };
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10000))]

        #[test]
        fn self_bijective(
            input in any::<BoundList<1028>>(),
            key in any::<Key>(),
            nonce in any::<Iv>()
        ) {
            let mut output = input.create_self();

            let res = AesCtr::new(&key, &nonce)
                .unwrap()
                .try_apply_keystream(input.as_slice(), output.as_mut_slice());

            prop_assert!(res.is_ok());

            if input.len() >= 2 {
                prop_assert_ne!(&output, &input);
            }

            let mut plain = input.create_self();
            let res = AesCtr::new(&key, &nonce)
                .unwrap()
                .try_apply_keystream(output.as_slice(), plain.as_mut_slice());

            prop_assert!(res.is_ok());

            prop_assert_eq!(plain.as_slice(), input.as_slice());
        }

        #[test]
        fn from_ctr_crate_to_wolf(
            input in any::<BoundList<1028>>(),
            key in any::<Key>(),
            nonce in any::<Iv>()
        ) {
            let mut ctr = AesCtr::new(&key, &nonce).unwrap();
            let mut c_in = input;

            with_rust_crypto_ctr!(key, nonce, |o_ctr| {
                o_ctr.apply_keystream(c_in.as_mut_slice());
            });

            let mut plain = input.create_self();
            ctr.apply_keystream(c_in.as_slice(), plain.as_mut_slice());

            prop_assert_eq!(plain.as_slice(), input.as_slice());
        }

        #[test]
        fn from_wolf_to_ctr_crate(
            input in any::<BoundList<1028>>(),
            key in any::<Key>(),
            nonce in any::<Iv>()
        ) {
            let mut ctr = AesCtr::new(&key, &nonce).unwrap();
            let mut cipher = input.create_self();

            ctr.apply_keystream(input.as_slice(), cipher.as_mut_slice());

            if input.len() >= 2 {
                prop_assert_ne!(&input, &cipher);
            }

            with_rust_crypto_ctr!(key, nonce, |o_ctr| {
                o_ctr.apply_keystream(cipher.as_mut_slice());
            });

            prop_assert_eq!(cipher.as_slice(), input.as_slice());
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1000))]

        #[test]
        fn wolf_and_ctr_crate_eq_many_invocations(
            mut input in any::<BoundList<512>>(),
            key in any::<Key>(),
            nonce in any::<Iv>(),
        ) {
            let mut ctr = AesCtr::new(&key, &nonce).unwrap();

            with_rust_crypto_ctr!(key, nonce, |o_ctr| {
                for _ in 0..256 {
                    let mut wolf_out = input.create_self();
                    ctr.apply_keystream(input.as_slice(), wolf_out.as_mut_slice());

                    o_ctr.apply_keystream(input.as_mut_slice());

                    prop_assert_eq!(wolf_out.as_slice(), input.as_slice());
                }
            });
        }
    }
}