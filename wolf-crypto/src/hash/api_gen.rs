
/// Create an API for a hashing function
macro_rules! make_api {
    (
        $(sec_warning: $warning:literal,)?
        $(anecdote: $anecdote:literal,)?
        name: $name:ident,
        wc: $wc:ty,
        bs: $bs:literal,
        init: $(= $i_void:ident)? $init:ident $(, heap: $heap:expr, devid: $devId:expr)?,
        update: $(= $u_void:ident)? $update:ident,
        finalize: $(= $f_void:ident)? $finalize:ident
        $(, free: $free:ident)?
        $(, needs-reset: $nr:ident)? $(,)?
    ) => {
        #[doc = concat!("The `", stringify!($name), $($anecdote, )? "` hasher.")]
        #[doc = ""]
        $(
            #[doc = "# Security Warning"]
            #[doc = ""]
            #[doc = $warning]
            #[doc = ""]
        )?
        #[doc = "# Example"]
        #[doc = ""]
        #[doc = "```"]
        #[doc = concat!("use wolf_crypto::hash::", stringify!($name), ";")]
        #[doc = ""]
        #[doc = concat!("let mut hasher = ", stringify!($name), "::new().unwrap();")]
        #[doc = ""]
        #[doc = "let input = b\"hello world\";"]
        #[doc = "assert!(hasher.try_update(input.as_slice()).is_ok());"]
        #[doc = ""]
        #[doc = "let finalized = hasher.try_finalize().unwrap();"]
        #[doc = "assert_ne!(finalized.as_slice(), input.as_slice());"]
        #[doc = concat!("assert_eq!(finalized.len(), ", stringify!($bs), ");")]
        #[doc = "```"]
        #[repr(transparent)]
        pub struct $name {
            inner: $wc
        }

        #[allow(unused_mut)] // only for md4 and other very weak hashing algos.
        impl $name {
            $(
                #[doc = "# Security Warning"]
                #[doc = ""]
                #[doc = $warning]
                #[doc = ""]
            )?
            #[doc = concat!("Create a new `", stringify!($name), "` instance.")]
            #[doc = ""]
            #[doc = "# Errors"]
            #[doc = ""]
            #[doc = concat!(
                "If the underlying initialization function fails (`", stringify!($init), "`)"
            )]
            #[doc = ""]
            #[doc = "# Example"]
            #[doc = ""]
            #[doc = "```"]
            #[doc = concat!("use wolf_crypto::hash::", stringify!($name), ";")]
            #[doc = ""]
            #[doc = concat!("let mut hasher = ", stringify!($name), "::new().unwrap();")]
            #[doc = ""]
            #[doc = "let input = b\"hello world\";"]
            #[doc = "assert!(hasher.try_update(input.as_slice()).is_ok());"]
            #[doc = ""]
            #[doc = "let finalized = hasher.try_finalize().unwrap();"]
            #[doc = "assert_ne!(finalized.as_slice(), input.as_slice());"]
            #[doc = concat!("assert_eq!(finalized.len(), ", stringify!($bs), ");")]
            #[doc = "```"]
            pub fn new() -> Result<Self, ()> {
                unsafe {
                    let mut res = $crate::opaque_res::Res::new();
                    let mut inner = ::core::mem::MaybeUninit::<$wc>::uninit();

                    make_api!(
                        @check res,
                        $init(inner.as_mut_ptr() $(, $heap, $devId)?)
                        $(, $i_void)?
                    );

                    res.unit_err_with(|| Self { inner: inner.assume_init() })
                }
            }

            #[doc = concat!(
                "Update the underlying `", stringify!($wc), "` instance, without performing any ",
                "safety checks."
            )]
            #[doc = ""]
            #[doc = "# Safety"]
            #[doc = ""]
            #[doc = "The length of data is casted to a 32 bit unsigned integer without checking "]
            #[doc = "for overflows. While it is incredibly unlikely that this overflow will ever"]
            #[doc = "take place, it is not impossible. Thus this function is marked unsafe."]
            #[doc = ""]
            #[doc = "# Arguments"]
            #[doc = ""]
            #[doc = "* `data` - The slice to update the underlying hasher state with."]
            #[doc = ""]
            #[doc = "# Returns"]
            #[doc = ""]
            #[doc = "This function returns the result of the operation."]
            #[doc = ""]
            #[doc = "# Example"]
            #[doc = ""]
            #[doc = "```"]
            #[doc = concat!("use wolf_crypto::hash::", stringify!($name), ";")]
            #[doc = ""]
            #[doc = concat!("let mut hasher = ", stringify!($name), "::new().unwrap();")]
            #[doc = ""]
            #[doc = "let input = b\"hello world\";"]
            #[doc = "// SAFETY: The length of `hello world` is 11, which"]
            #[doc = "// cannot overflow even an 8 bit integer."]
            #[doc = "let res = unsafe {"]
            #[doc = "    hasher.update_unchecked(input.as_slice())"]
            #[doc = "};"]
            #[doc = "assert!(res.is_ok());"]
            #[doc = ""]
            #[doc = "let finalized = hasher.try_finalize().unwrap();"]
            #[doc = "assert_ne!(finalized.as_slice(), input.as_slice());"]
            #[doc = concat!("assert_eq!(finalized.len(), ", stringify!($bs), ");")]
            #[doc = "```"]
            #[inline]
            pub unsafe fn update_unchecked(&mut self, data: &[u8]) -> $crate::opaque_res::Res {
                let mut res = $crate::opaque_res::Res::new();

                make_api!(
                    @check res,
                    $update(
                        ::core::ptr::addr_of_mut!(self.inner),
                        data.as_ptr(),
                        data.len() as u32
                    )
                    $(, $u_void)?
                );

                res
            }

            #[doc = concat!("Update the underlying `", stringify!($wc), "` instance.")]
            #[doc = ""]
            #[doc = "# Arguments"]
            #[doc = ""]
            #[doc = "* `data` - The slice to update the underlying hasher state with."]
            #[doc = ""]
            #[doc = "# Returns"]
            #[doc = ""]
            #[doc = "This function returns the result of the operation."]
            #[doc = ""]
            #[doc = "# Errors"]
            #[doc = ""]
            #[doc = "- If the length of `data` cannot be safely casted to a `u32`."]
            #[doc = concat!("- If the underlying `", stringify!($update), "` function fails.")]
            #[doc = ""]
            #[doc = "# Example"]
            #[doc = ""]
            #[doc = "```"]
            #[doc = concat!("use wolf_crypto::hash::", stringify!($name), ";")]
            #[doc = ""]
            #[doc = concat!("let mut hasher = ", stringify!($name), "::new().unwrap();")]
            #[doc = ""]
            #[doc = "let input = b\"hello world\";"]
            #[doc = "assert!(hasher.try_update(input.as_slice()).is_ok());"]
            #[doc = ""]
            #[doc = "let finalized = hasher.try_finalize().unwrap();"]
            #[doc = "assert_ne!(finalized.as_slice(), input.as_slice());"]
            #[doc = concat!("assert_eq!(finalized.len(), ", stringify!($bs), ");")]
            #[doc = "```"]
            #[doc = ""]
            #[doc = "**Note**: if the size of the `data` is known at compile time, see "]
            #[doc = "[`update_sized`] for a slight optimization as the safety checks are done at "]
            #[doc = "compilation time."]
            #[doc = ""]
            #[doc = "[`update_sized`]: Self::update_sized"]
            #[inline]
            pub fn try_update(&mut self, data: &[u8]) -> $crate::opaque_res::Res {
                if !$crate::can_cast_u32(data.len()) {
                    return $crate::opaque_res::Res::ERR;
                }

                unsafe { self.update_unchecked(data) }
            }

            #[doc = concat!(
                "Update the underlying `", stringify!($wc), "` instance, with the safety checks ",
                "performed at compilation time."
            )]
            #[doc = ""]
            #[doc = "# Arguments"]
            #[doc = ""]
            #[doc = "* `data` - The slice to update the underlying hasher state with."]
            #[doc = ""]
            #[doc = "# Returns"]
            #[doc = ""]
            #[doc = "This function returns the result of the operation."]
            #[doc = ""]
            #[doc = "# Errors"]
            #[doc = ""]
            #[doc = "- If the length of `data` cannot be safely casted to a `u32`."]
            #[doc = concat!("- If the underlying `", stringify!($update), "` function fails.")]
            #[doc = ""]
            #[doc = "# Example"]
            #[doc = ""]
            #[doc = "```"]
            #[doc = concat!("use wolf_crypto::hash::", stringify!($name), ";")]
            #[doc = ""]
            #[doc = concat!("let mut hasher = ", stringify!($name), "::new().unwrap();")]
            #[doc = ""]
            #[doc = "let input = b\"hello world\";"]
            #[doc = "assert!(hasher.update_sized(input).is_ok());"]
            #[doc = ""]
            #[doc = "let finalized = hasher.try_finalize().unwrap();"]
            #[doc = "assert_ne!(finalized.as_slice(), input.as_slice());"]
            #[doc = concat!("assert_eq!(finalized.len(), ", stringify!($bs), ");")]
            #[doc = "```"]
            #[doc = ""]
            #[doc = "**Note**: if the size of the `data` is not known at compile time, see "]
            #[doc = "[`try_update`] for more flexibility."]
            #[doc = ""]
            #[doc = "[`try_update`]: Self::try_update"]
            #[inline]
            pub fn update_sized<const C: usize>(&mut self, data: &[u8; C]) -> $crate::opaque_res::Res {
                if !$crate::const_can_cast_u32::<{ C }>() {
                    return $crate::opaque_res::Res::ERR;
                }

                unsafe { self.update_unchecked(data) }
            }

            #[doc = concat!(
                "Update the underlying `", stringify!($wc), "`, panicking under any failure."
            )]
            #[doc = ""]
            #[doc = "# Arguments"]
            #[doc = ""]
            #[doc = "* `data` - The slice to update the underlying hasher state with."]
            #[doc = ""]
            #[doc = "# Panics"]
            #[doc = ""]
            #[doc = "- If the length of `data` cannot be safely casted to a `u32`."]
            #[doc = concat!("- If the underlying `", stringify!($update), "` function fails.")]
            #[doc = ""]
            #[doc = "If a `panic` under any failure is not acceptable for your use case, which "]
            #[doc = "generally is true, please consider using [`try_update`]."]
            #[doc = ""]
            #[doc = "# Example"]
            #[doc = ""]
            #[doc = "```"]
            #[doc = concat!("use wolf_crypto::hash::", stringify!($name), ";")]
            #[doc = ""]
            #[doc = concat!("let mut hasher = ", stringify!($name), "::new().unwrap();")]
            #[doc = ""]
            #[doc = "let input = b\"hello world\";"]
            #[doc = "hasher.update(input.as_slice());"]
            #[doc = ""]
            #[doc = "let finalized = hasher.try_finalize().unwrap();"]
            #[doc = "assert_ne!(finalized.as_slice(), input.as_slice());"]
            #[doc = concat!("assert_eq!(finalized.len(), ", stringify!($bs), ");")]
            #[doc = "```"]
            #[doc = ""]
            #[doc = "[`try_update`]: Self::try_update"]
            #[cfg(feature = "panic-api")]
            #[track_caller]
            pub fn update(&mut self, data: &[u8]) {
                self.try_update(data).unit_err(())
                    .expect(concat!("Failed to update hash in `", stringify!($name), "`"))
            }

            #[doc = concat!(
                "Calls the `", stringify!($finalize), "` function, finalizing the hashing of data ",
                "and resetting the underlying `", stringify!($wc), "` instance's state, without ",
                "performing any safety checks."
            )]
            #[doc = ""]
            #[doc = "# Safety"]
            #[doc = ""]
            #[doc = concat!(
                "The size of the `output` argument must have a size of at least `", stringify!($bs),
                "` (the size of the digest)."
            )]
            #[doc = ""]
            #[doc = "# Arguments"]
            #[doc = ""]
            #[doc = "* `output` - The buffer to store the output digest in."]
            #[doc = ""]
            #[doc = "# Returns"]
            #[doc = ""]
            #[doc = "This function returns the result of the operation."]
            #[doc = ""]
            #[doc = "# Example"]
            #[doc = ""]
            #[doc = "```"]
            #[doc = concat!("use wolf_crypto::hash::", stringify!($name), ";")]
            #[doc = concat!("let mut hasher = ", stringify!($name), "::new().unwrap();")]
            #[doc = "# let input = b\"hello world\";"]
            #[doc = "# assert!(hasher.update_sized(input).is_ok());"]
            #[doc = ""]
            #[doc = "// Use the hasher ..."]
            #[doc = ""]
            #[doc = concat!("let mut output = [0u8; ", stringify!($bs), "];")]
            #[doc = "// SAFETY: The size of the output is exactly "]
            #[doc = "// the size of the digest."]
            #[doc = "let res = unsafe {"]
            #[doc = "    hasher.finalize_unchecked(output.as_mut_slice())"]
            #[doc = "};"]
            #[doc = "assert!(res.is_ok());"]
            #[doc = "```"]
            #[inline]
            pub unsafe fn finalize_unchecked(&mut self, output: &mut [u8]) -> $crate::opaque_res::Res {
                let mut res = $crate::opaque_res::Res::new();

                make_api!(
                    @check res,
                    $finalize(::core::ptr::addr_of_mut!(self.inner), output.as_mut_ptr())
                    $(, $f_void)?
                );

                // it just so happens that whenever we do not have a free api, we do not get reset
                // on finalize. So to make the api consistent we reset manually in this case.
                make_api! { @needs-reset self, $init, res $(, $nr)? $(, = $i_void)? }

                res
            }

            #[inline]
            #[must_use]
            const fn finalize_predicate(len: usize) -> bool {
                len >= $bs
            }

            #[inline]
            #[must_use]
            const fn const_finalize_predicate<const S: usize>() -> bool {
                S >= $bs
            }

            #[doc = concat!(
                "Calls the `", stringify!($finalize), "` function, finalizing the hashing of data ",
                "and resetting the underlying `", stringify!($wc), "` instance's state."
            )]
            #[doc = ""]
            #[doc = "# Arguments"]
            #[doc = ""]
            #[doc = "* `output` - The buffer to store the output digest in."]
            #[doc = ""]
            #[doc = "# Errors"]
            #[doc = ""]
            #[doc = concat!(
                "- If the size of `output` is less than the digest size (`",
                stringify!($bs), "`)."
            )]
            #[doc = "- If the underlying finalize function fails."]
            #[doc = ""]
            #[doc = "# Example"]
            #[doc = ""]
            #[doc = "```"]
            #[doc = concat!("use wolf_crypto::hash::", stringify!($name), ";")]
            #[doc = concat!("let mut hasher = ", stringify!($name), "::new().unwrap();")]
            #[doc = "# let input = b\"hello world\";"]
            #[doc = "# assert!(hasher.update_sized(input).is_ok());"]
            #[doc = ""]
            #[doc = "// Use the hasher ..."]
            #[doc = ""]
            #[doc = concat!("let mut output = [0u8; ", stringify!($bs), "];")]
            #[doc = "let res = hasher.finalize_into(output.as_mut_slice());"]
            #[doc = "assert!(res.is_ok());"]
            #[doc = "```"]
            #[doc = ""]
            #[doc = "**Note**: if the size of the `output` slice is known at compile time, see"]
            #[doc = "[`finalize_into_sized`] for a slight optimization as the safety checks are "]
            #[doc = "done at compilation time. There is also [`finalize_into_exact`] if this size "]
            #[doc = concat!("is exactly `", stringify!($bs), "` bytes, moving all checks to the ")]
            #[doc = "type system."]
            #[doc = ""]
            #[doc = "[`finalize_into_sized`]: Self::finalize_into_sized"]
            #[doc = "[`finalize_into_exact`]: Self::finalize_into_exact"]
            #[inline]
            pub fn finalize_into(&mut self, output: &mut [u8]) -> $crate::opaque_res::Res {
                if !Self::finalize_predicate(output.len()) { return $crate::opaque_res::Res::ERR }
                unsafe { self.finalize_unchecked(output) }
            }

            #[doc = concat!(
                "Calls the `", stringify!($finalize), "` function, finalizing the hashing of data ",
                "and resetting the underlying `", stringify!($wc), "` instance's state, with the ",
                "safety checks performed at compilation time."
            )]
            #[doc = ""]
            #[doc = "# Arguments"]
            #[doc = ""]
            #[doc = "* `output` - The buffer to store the output digest in."]
            #[doc = ""]
            #[doc = "# Errors"]
            #[doc = ""]
            #[doc = concat!(
                "- If the size of `output` is less than the digest size (`",
                stringify!($bs), "`)."
            )]
            #[doc = "- If the underlying finalize function fails."]
            #[doc = ""]
            #[doc = "# Example"]
            #[doc = ""]
            #[doc = "```"]
            #[doc = concat!("use wolf_crypto::hash::", stringify!($name), ";")]
            #[doc = concat!("let mut hasher = ", stringify!($name), "::new().unwrap();")]
            #[doc = "# let input = b\"hello world\";"]
            #[doc = "# assert!(hasher.update_sized(input).is_ok());"]
            #[doc = ""]
            #[doc = "// Use the hasher ..."]
            #[doc = ""]
            #[doc = concat!("let mut output = [0u8; ", stringify!($bs), "];")]
            #[doc = "let res = hasher.finalize_into_sized(&mut output);"]
            #[doc = "assert!(res.is_ok());"]
            #[doc = "```"]
            #[doc = ""]
            #[doc = "**Note**: If the size of the output buffer is not known at compilation time "]
            #[doc = "see [`finalize_into`] for greater flexibility. There is also "]
            #[doc = "[`finalize_into_exact`] if this size "]
            #[doc = concat!("is exactly `", stringify!($bs), "` bytes, moving all checks to the ")]
            #[doc = "type system."]
            #[doc = ""]
            #[doc = "[`finalize_into`]: Self::finalize_into"]
            #[doc = "[`finalize_into_exact`]: Self::finalize_into_exact"]
            #[inline]
            pub fn finalize_into_sized<const C: usize>(&mut self, output: &mut [u8; C]) -> $crate::opaque_res::Res {
                if !Self::const_finalize_predicate::<{ C }>() { return $crate::opaque_res::Res::ERR }
                unsafe { self.finalize_unchecked(output) }
            }

            #[doc = concat!(
                "Calls the `", stringify!($finalize), "` function, finalizing the hashing of data ",
                "and resetting the underlying `", stringify!($wc), "` instance's state, with the ",
                "safety checks moved to the type system."
            )]
            #[doc = ""]
            #[doc = "# Arguments"]
            #[doc = ""]
            #[doc = "* `output` - The buffer to store the output digest in."]
            #[doc = ""]
            #[doc = "# Errors"]
            #[doc = ""]
            #[doc = "If the underlying finalize function fails."]
            #[doc = ""]
            #[doc = "# Example"]
            #[doc = ""]
            #[doc = "```"]
            #[doc = concat!("use wolf_crypto::hash::", stringify!($name), ";")]
            #[doc = concat!("let mut hasher = ", stringify!($name), "::new().unwrap();")]
            #[doc = "# let input = b\"hello world\";"]
            #[doc = "# assert!(hasher.update_sized(input).is_ok());"]
            #[doc = ""]
            #[doc = "// Use the hasher ..."]
            #[doc = ""]
            #[doc = concat!("let mut output = [0u8; ", stringify!($bs), "];")]
            #[doc = "let res = hasher.finalize_into_exact(&mut output);"]
            #[doc = "assert!(res.is_ok());"]
            #[doc = "```"]
            #[doc = ""]
            #[doc = "**Note**: If the size of the output buffer is not known at compilation time "]
            #[doc = "see [`finalize_into`] for greater flexibility. If the size is known at "]
            #[doc = concat!("compilation time, but not exactly `", stringify!($bs), "` bytes, ")]
            #[doc = "see [`finalize_into_sized`]."]
            #[doc = ""]
            #[doc = "[`finalize_into`]: Self::finalize_into"]
            #[doc = "[`finalize_into_sized`]: Self::finalize_into_sized"]
            #[inline]
            pub fn finalize_into_exact(&mut self, output: &mut [u8; $bs]) -> $crate::opaque_res::Res {
                unsafe { self.finalize_unchecked(output) }
            }

            #[doc = concat!(
                "Calls the `", stringify!($finalize), "` function, finalizing the hashing of ",
                "data and resetting the underlying `", stringify!($wc), "` instance's state."
            )]
            #[doc = ""]
            #[doc = "# Returns"]
            #[doc = ""]
            #[doc = "On success, this returns the output digest."]
            #[doc = ""]
            #[doc = "# Errors"]
            #[doc = ""]
            #[doc = "If the underlying finalize function fails."]
            #[doc = ""]
            #[doc = "# Example"]
            #[doc = ""]
            #[doc = "```"]
            #[doc = concat!("use wolf_crypto::hash::", stringify!($name), ";")]
            #[doc = concat!("let mut hasher = ", stringify!($name), "::new().unwrap();")]
            #[doc = "# let input = b\"hello world\";"]
            #[doc = "# assert!(hasher.update_sized(input).is_ok());"]
            #[doc = ""]
            #[doc = "// Use the hasher ..."]
            #[doc = ""]
            #[doc = "let res = hasher.try_finalize().unwrap();"]
            #[doc = "assert_ne!(res.as_slice(), input.as_slice());"]
            #[doc = "```"]
            #[inline]
            pub fn try_finalize(&mut self) -> Result<[u8; $bs], ()> {
                let mut buf = [0u8; $bs];
                self.finalize_into_exact(&mut buf).unit_err(buf)
            }

            #[doc = concat!(
                "Calls the `", stringify!($finalize), "` function, finalizing the hashing of ",
                "data and resetting the underlying `", stringify!($wc), "` instance's state."
            )]
            #[doc = ""]
            #[doc = "# Returns"]
            #[doc = ""]
            #[doc = "On success, this returns the output digest."]
            #[doc = ""]
            #[doc = "# Panics"]
            #[doc = ""]
            #[doc = "If the underlying finalize function fails. If panicking is not acceptable "]
            #[doc = "for your use case, which generally is true, see [`try_finalize`]."]
            #[doc = ""]
            #[doc = "# Example"]
            #[doc = ""]
            #[doc = "```"]
            #[doc = concat!("use wolf_crypto::hash::", stringify!($name), ";")]
            #[doc = concat!("let mut hasher = ", stringify!($name), "::new().unwrap();")]
            #[doc = "# let input = b\"hello world\";"]
            #[doc = "# assert!(hasher.update_sized(input).is_ok());"]
            #[doc = ""]
            #[doc = "// Use the hasher ..."]
            #[doc = ""]
            #[doc = "let res = hasher.try_finalize().unwrap();"]
            #[doc = "assert_ne!(res.as_slice(), input.as_slice());"]
            #[doc = "```"]
            #[doc = ""]
            #[doc = "[`try_finalize`]: Self::try_finalize"]
            #[cfg(feature = "panic-api")]
            #[track_caller]
            pub fn finalize(&mut self) -> [u8; $bs] {
                self.try_finalize().expect(concat!(
                    "Failed to finalize in `", stringify!($name), "`"
                ))
            }
        }

        // SAFETY:
        // All methods which mutate the underlying state require a mutable reference,
        // the only way to obtain a mutable reference across thread boundaries is via
        // synchronization or unsafe in Rust (which then would be the user's responsibility).
        unsafe impl Send for $name {}

        // SAFETY:
        // There is no providing of interior mutability, all methods which mutate the underlying
        // state require a mutable reference, thus making this safe to mark `Sync`.
        unsafe impl Sync for $name {}

        // only implement if free was provided, as some hashing functions do not have this API.
        $(
        impl Drop for $name {
            #[doc = concat!(
                "Calls the `", stringify!($free), "` function, cleaning up after itself."
            )]
            #[inline]
            fn drop(&mut self) {
                unsafe { $free(::core::ptr::addr_of_mut!(self.inner)) }
            }
        }
        )?

        #[cfg(test)]
        mod unit_tests {
            use super::*;
            use digest::Digest;

            #[test]
            fn reset_behavior() {
                let mut hasher = $name::new().unwrap();

                let input = b"hello world";
                assert!(hasher.try_update(input.as_slice()).is_ok());

                let _ = hasher.try_finalize().unwrap();

                // hasher2 and hasher when hashing more data should have the same digest due to the
                // implicit reset behavior of all finalize functions in wolfcrypt.
                let mut hasher2 = $name::new().unwrap();

                let sec_inp = b"goodbye world";
                assert!(hasher.try_update(sec_inp.as_slice()).is_ok());
                assert!(hasher2.try_update(sec_inp.as_slice()).is_ok());

                let r_out = hasher.try_finalize().unwrap();
                let out = hasher2.try_finalize().unwrap();

                assert_eq!(r_out.as_slice(), out.as_slice());
            }

            #[test]
            fn rust_crypto_equivalence() {
                let mut wolf = $name::new().unwrap();
                let mut rc = <make_api!(@rc $name $(, $heap, $devId)?)>::new();

                let inp = b"hello world";

                assert!(wolf.try_update(inp.as_slice()).is_ok());
                rc.update(inp.as_slice());

                let rc_out = rc.finalize();
                let wolf_out = wolf.try_finalize().unwrap();

                assert_eq!(rc_out.as_slice(), wolf_out.as_slice());
            }

            #[test]
            fn rust_crypto_reset_equivalence() {
                let mut wolf = $name::new().unwrap();
                let mut rc = <make_api!(@rc $name $(, $heap, $devId)?)>::new();

                let inp = b"hello world";

                assert!(wolf.try_update(inp.as_slice()).is_ok());
                rc.update(inp.as_slice());

                let f_rc_out = rc.finalize_reset();
                let f_wolf_out = wolf.try_finalize().unwrap();

                assert_eq!(f_rc_out.as_slice(), f_wolf_out.as_slice());

                let s_inp = b"goodbye world";

                assert!(wolf.try_update(s_inp.as_slice()).is_ok());
                rc.update(s_inp.as_slice());

                let s_rc_out = rc.finalize();
                let s_wolf_out = wolf.try_finalize().unwrap();

                assert_eq!(s_rc_out.as_slice(), s_wolf_out.as_slice());
            }

            #[test]
            fn hash_finalize_hash_finalize() {
                let mut hasher = $name::new().unwrap();
                let inp = b"hello world";

                assert!(hasher.try_update(inp.as_slice()).is_ok());

                let f_out = hasher.try_finalize().unwrap();

                assert!(hasher.try_update(inp.as_slice()).is_ok());

                let s_out = hasher.try_finalize().unwrap();
                assert_eq!(s_out, f_out);
            }

            #[test]
            fn just_finalize() {
                let mut hasher = $name::new().unwrap();
                assert!(hasher.try_finalize().is_ok());
            }

            #[test]
            fn rust_crypto_just_finalize_equivalence() {
                let mut wolf = $name::new().unwrap();
                let rc = <make_api!(@rc $name $(, $heap, $devId)?)>::new();

                let w_out = wolf.try_finalize().unwrap();
                let rc_out = rc.finalize();

                assert_eq!(w_out.as_slice(), rc_out.as_slice());
            }

            #[test]
            fn hash_empty() {
                let input = [0u8; 0];
                let mut hasher = $name::new().unwrap();

                assert!(hasher.try_update(input.as_slice()).is_ok());
                assert!(hasher.try_finalize().is_ok());
            }

            #[test]
            fn rust_crypto_hash_empty_equivalence() {
                let mut wolf = $name::new().unwrap();
                let mut rc = <make_api!(@rc $name $(, $heap, $devId)?)>::new();

                let input = [0u8; 0];

                assert!(wolf.try_update(input.as_slice()).is_ok());
                rc.update(input.as_slice());

                let w_out = wolf.try_finalize().unwrap();
                let rc_out = rc.finalize();

                assert_eq!(w_out.as_slice(), rc_out.as_slice());
            }

            #[test]
            fn finalize_into_predicate() {
                let mut hasher = $name::new().unwrap();
                let mut small_out = [0u8; $bs - 4];

                assert!(hasher.finalize_into(small_out.as_mut_slice()).is_err());
            }

            #[test]
            fn finalize_into_sized_predicate() {
                let mut hasher = $name::new().unwrap();
                let mut small_out = [0u8; $bs - 4];

                assert!(hasher.finalize_into_sized(&mut small_out).is_err());
            }

            #[test]
            fn hash_large() {
                let input = [7u8; 32_768];
                let mut hasher = $name::new().unwrap();

                assert!(hasher.try_update(input.as_slice()).is_ok());
                assert!(hasher.try_finalize().is_ok());
            }

            #[test]
            fn rust_crypto_hash_large_equivalence() {
                let input = [7u8; 32_768];
                let mut wolf = $name::new().unwrap();
                let mut rc = <make_api!(@rc $name $(, $heap, $devId)?)>::new();

                assert!(wolf.try_update(input.as_slice()).is_ok());
                rc.update(input.as_slice());

                let w_out = wolf.try_finalize().unwrap();
                let rc_out = rc.finalize();

                assert_eq!(w_out.as_slice(), rc_out.as_slice());
            }

            #[test]
            fn hash_massive() {
                let input = [7u8; 131_072];
                let mut hasher = $name::new().unwrap();

                assert!(hasher.try_update(input.as_slice()).is_ok());
                assert!(hasher.try_finalize().is_ok());
            }

            #[test]
            fn rust_crypto_hash_massive_equivalence() {
                let input = [7u8; 131_072];
                let mut wolf = $name::new().unwrap();
                let mut rc = <make_api!(@rc $name $(, $heap, $devId)?)>::new();

                assert!(wolf.try_update(input.as_slice()).is_ok());
                rc.update(input.as_slice());

                let w_out = wolf.try_finalize().unwrap();
                let rc_out = rc.finalize();

                assert_eq!(w_out.as_slice(), rc_out.as_slice());
            }

            #[test]
            fn hash_one_mb() {
                // probably do not want to put this on the stack
                let input = vec![7u8; 1_048_576];

                let mut hasher = $name::new().unwrap();

                assert!(hasher.try_update(input.as_slice()).is_ok());
                assert!(hasher.try_finalize().is_ok());
            }

            #[test]
            fn rust_crypto_hash_mb_equivalence() {
                let input = vec![7u8; 1_048_576];
                let mut wolf = $name::new().unwrap();
                let mut rc = <make_api!(@rc $name $(, $heap, $devId)?)>::new();

                assert!(wolf.try_update(input.as_slice()).is_ok());
                rc.update(input.as_slice());

                let w_out = wolf.try_finalize().unwrap();
                let rc_out = rc.finalize();

                assert_eq!(w_out.as_slice(), rc_out.as_slice());
            }
        }

        #[cfg(test)]
        mod property_tests {
            use super::*;
            use digest::Digest;
            use crate::aes::test_utils::{BoundList, AnyList};
            use proptest::prelude::*;

            proptest! {
                #![proptest_config(ProptestConfig::with_cases(100_000 / $bs))]

                #[test]
                fn rust_crypto_eq_wolf_single_update(
                    input in any::<BoundList<1024>>()
                ) {
                    let mut wolf = $name::new().unwrap();
                    let mut rc = <make_api!(@rc $name $(, $heap, $devId)?)>::new();

                    prop_assert!(wolf.try_update(input.as_slice()).is_ok());
                    rc.update(input.as_slice());

                    let finalized = wolf.try_finalize().unwrap();
                    let rc_finalized = rc.finalize();

                    prop_assert_eq!(finalized.as_slice(), rc_finalized.as_slice());
                }
            }

            proptest! {
                #![proptest_config(ProptestConfig::with_cases(50_000 / $bs))]

                #[test]
                fn rust_crypto_eq_wolf_arb_updates(
                    inputs in any::<AnyList<32, BoundList<512>>>()
                ) {
                    let mut wolf = $name::new().unwrap();
                    let mut rc = <make_api!(@rc $name $(, $heap, $devId)?)>::new();

                    for input in inputs.as_slice().iter() {
                        prop_assert!(wolf.try_update(input.as_slice()).is_ok());
                        rc.update(input.as_slice());
                    }

                    let finalized = wolf.try_finalize().unwrap();
                    let rc_finalized = rc.finalize();

                    prop_assert_eq!(finalized.as_slice(), rc_finalized.as_slice());
                }

                #[test]
                fn rust_crypto_arb_reset_equivalence(
                    inputs in any::<AnyList<32, BoundList<512>>>()
                ) {
                    let mut wolf = $name::new().unwrap();
                    let mut rc = <make_api!(@rc $name $(, $heap, $devId)?)>::new();

                    for input in inputs.as_slice().iter() {
                        prop_assert!(wolf.try_update(input.as_slice()).is_ok());
                        rc.update(input.as_slice());

                        let w_out = wolf.try_finalize().unwrap();
                        let rc_out = rc.finalize_reset();

                        prop_assert_eq!(w_out.as_slice(), rc_out.as_slice());
                    }

                    let finalized = wolf.try_finalize().unwrap();
                    let rc_finalized = rc.finalize();

                    prop_assert_eq!(finalized.as_slice(), rc_finalized.as_slice());
                }
            }

            proptest! {
                #[test]
                fn arb_massive(
                    input in proptest::collection::vec(any::<u8>(), 65536..=524_288)
                ) {
                    let mut wolf = $name::new().unwrap();

                    prop_assert!(wolf.try_update(input.as_slice()).is_ok());
                    prop_assert!(wolf.try_finalize().is_ok());
                }

                #[test]
                fn rust_crypto_arb_massive_equivalence(
                    input in proptest::collection::vec(any::<u8>(), 65536..=524_288)
                ) {
                    let mut wolf = $name::new().unwrap();
                    let mut rc = <make_api!(@rc $name $(, $heap, $devId)?)>::new();

                    prop_assert!(wolf.try_update(input.as_slice()).is_ok());
                    rc.update(input.as_slice());

                    let finalized = wolf.try_finalize().unwrap();
                    let rc_finalized = rc.finalize();

                    prop_assert_eq!(finalized.as_slice(), rc_finalized.as_slice());
                }
            }
        }
    };

    (@check $res:ident, $expr:expr, void) => {
        $expr
    };
    (@check $res:ident, $expr:expr) => {
        $res.ensure_0($expr)
    };

    (@needs-reset $this:ident, $init:ident, $res:ident $(, = $void:ident)?) => {};
    (@needs-reset $this:ident, $init:ident, $res:ident, true $(, = $void:ident)?) => {
        make_api! (@check $res, $init(::core::ptr::addr_of_mut!($this.inner)) $(, $void)? )
    };

    // rust-crypto to test against, convenient that I used the same naming convention by accident.
    (@rc $name:ident, $heap:expr, $devId:expr) => {
        sha3::$name
    };
    (@rc Md5) => {
        md5::Md5
    };
    (@rc Md4) => {
        md4::Md4
    };
    (@rc RipeMd) => {
        ripemd::Ripemd160
    };
    (@rc $name:ident) => {
        sha2::$name
    };
}

