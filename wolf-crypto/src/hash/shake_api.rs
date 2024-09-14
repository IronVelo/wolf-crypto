macro_rules! shake_api {
    (
        name: $name:ident,
        wc: $wc:ty,
        ds: $ds:literal,
        init: $init:ident, heap: $heap:expr, devid: $devId:expr,
        update: $update:ident,
        finalize: $finalize:ident,
        free: $free:ident,
        copy: $copy:ident $(,)?
    ) => {
        #[doc = concat!("The `", stringify!($name), "` hasher.")]
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
        #[doc = "let finalized = hasher.try_finalize::<64>().unwrap();"]
        #[doc = "assert_ne!(finalized.as_slice(), input.as_slice());"]
        #[doc = "assert_eq!(finalized.len(), 64);"]
        #[doc = "```"]
        #[repr(transparent)]
        pub struct $name {
            inner: $wc
        }

        impl $name {
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
            #[doc = "let finalized = hasher.try_finalize::<32>()"]
            #[doc = "    .unwrap();"]
            #[doc = "assert_eq!(finalized.len(), 32);"]
            #[doc = "assert_ne!(finalized.as_slice(), input.as_slice());"]
            #[doc = "```"]
            pub fn new() -> Result<Self, ()> {
                unsafe {
                    let mut res = $crate::opaque_res::Res::new();
                    let mut inner = ::core::mem::MaybeUninit::<$wc>::uninit();

                    res.ensure_0($init(inner.as_mut_ptr(), $heap, $devId));

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
            #[doc = "let finalized = hasher.finalize_default().unwrap();"]
            #[doc = "assert_ne!(finalized.as_slice(), input.as_slice());"]
            #[doc = "```"]
            #[inline]
            pub unsafe fn update_unchecked(&mut self, data: &[u8]) -> $crate::opaque_res::Res {
                let mut res = $crate::opaque_res::Res::new();

                res.ensure_0($update(
                    ::core::ptr::addr_of_mut!(self.inner),
                    data.as_ptr(),
                    data.len() as u32
                ));

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
            #[doc = "let finalized = hasher.finalize_default().unwrap();"]
            #[doc = "assert_ne!(finalized.as_slice(), input.as_slice());"]
            #[doc = concat!("assert_eq!(finalized.len(), ", stringify!($ds), ");")]
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
            #[doc = "let finalized = hasher.finalize_default().unwrap();"]
            #[doc = "assert_ne!(finalized.as_slice(), input.as_slice());"]
            #[doc = concat!("assert_eq!(finalized.len(), ", stringify!($ds), ");")]
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
            #[doc = "let finalized = hasher.try_finalize::<64>().unwrap();"]
            #[doc = "assert_ne!(finalized.as_slice(), input.as_slice());"]
            #[doc = "assert_eq!(finalized.len(), 64);"]
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
                "Calls the `", stringify!($finalize), "` function, finalizing the extensible ",
                "hashing of data and resetting the underlying `", stringify!($wc), "` instance's ",
                "state without performing any safety checks on the `output` buffer size."
            )]
            #[doc = ""]
            #[doc = "# Safety"]
            #[doc = ""]
            #[doc = "The length of `output` is casted to a 32 bit unsigned integer without checking"]
            #[doc = "for overflows. While it is incredibly unlikely that this overflow will ever"]
            #[doc = "take place, it is not impossible. Thus this function is marked unsafe."]
            #[doc = ""]
            #[doc = "# Arguments"]
            #[doc = ""]
            #[doc = "* `output` - The buffer to store the variable-length output digest. Its length must be manually verified."]
            #[doc = ""]
            #[doc = "# Errors"]
            #[doc = ""]
            #[doc = "If the underlying finalize function fails, the returned result will contain an error."]
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
            #[doc = "let mut output = [0u8; 64];"]
            #[doc = "unsafe {"]
            #[doc = "    let res = hasher.finalize_unchecked(&mut output);"]
            #[doc = "    assert!(res.is_ok());"]
            #[doc = "}"]
            #[doc = "```"]
            #[doc = ""]
            #[doc = "**Note**: Prefer using [`finalize_into`] or [`finalize_into_sized`] where possible to "]
            #[doc = "benefit from safety checks."]
            #[doc = ""]
            #[doc = "[`finalize_into`]: Self::finalize_into"]
            #[doc = "[`finalize_into_sized`]: Self::finalize_into_sized"]
            pub unsafe fn finalize_unchecked(&mut self, output: &mut [u8]) -> $crate::opaque_res::Res {
                let mut res = $crate::opaque_res::Res::new();
                let len = output.len() as u32;

                res.ensure_0($finalize(
                    ::core::ptr::addr_of_mut!(self.inner),
                    output.as_mut_ptr(),
                    len
                ));

                res
            }

            #[doc = concat!(
                "Calls the `", stringify!($finalize), "` function, finalizing the extensible ",
                "hashing of data and resetting the underlying `", stringify!($wc), "` instance's ",
                "state."
            )]
            #[doc = ""]
            #[doc = "# Arguments"]
            #[doc = ""]
            #[doc = "* `output` - The buffer to store the variable-length output digest."]
            #[doc = ""]
            #[doc = "# Errors"]
            #[doc = ""]
            #[doc = "- If the size of `output` exceeds what can be represented as a `u32`."]
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
            #[doc = "let mut output = [0u8; 64];"]
            #[doc = "let res = hasher.finalize_into(output.as_mut_slice());"]
            #[doc = "assert!(res.is_ok());"]
            #[doc = "```"]
            #[doc = ""]
            #[doc = "**Note**: If the size of the `output` slice is known at compile time, see "]
            #[doc = "[`finalize_into_sized`] for a slight optimization."]
            #[doc = ""]
            #[doc = "[`finalize_into_sized`]: Self::finalize_into_sized"]
            #[inline]
            pub fn finalize_into(&mut self, output: &mut [u8]) -> $crate::opaque_res::Res {
                if !$crate::can_cast_u32(output.len()) { return $crate::opaque_res::Res::ERR }
                unsafe { self.finalize_unchecked(output) }
            }

            #[doc = concat!(
                "Calls the `", stringify!($finalize), "` function, finalizing the extensible ",
                "hashing of data and resetting the underlying `", stringify!($wc), "` instance's ",
                "state, with the safety checks performed at compilation time."
            )]
            #[doc = ""]
            #[doc = "# Arguments"]
            #[doc = ""]
            #[doc = "* `output` - The buffer to store the variable-length output digest."]
            #[doc = ""]
            #[doc = "# Errors"]
            #[doc = ""]
            #[doc = "- If the size of `output` exceeds what can be represented as a `u32`."]
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
            #[doc = "let mut output = [0u8; 64];"]
            #[doc = "let res = hasher.finalize_into_sized(&mut output);"]
            #[doc = "assert!(res.is_ok());"]
            #[doc = "```"]
            #[doc = ""]
            #[doc = "**Note**: If the size of the output buffer is not known at compilation time, "]
            #[doc = "see [`finalize_into`] for greater flexibility."]
            #[doc = ""]
            #[doc = "[`finalize_into`]: Self::finalize_into"]
            #[inline]
            pub fn finalize_into_sized<const C: usize>(&mut self, output: &mut [u8; C]) -> $crate::opaque_res::Res {
                if !$crate::const_can_cast_u32::<{ C }>() { return $crate::opaque_res::Res::ERR }
                unsafe { self.finalize_unchecked(output) }
            }

            #[doc = concat!(
                "Calls the `", stringify!($finalize), "` function, finalizing the extensible ",
                "hashing of data and resetting the underlying `", stringify!($wc), "` instance's ",
                "state, returning a buffer of the specified output size."
            )]
            #[doc = ""]
            #[doc = "# Returns"]
            #[doc = ""]
            #[doc = "On success, this returns the output digest of the given size."]
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
            #[doc = "let res = hasher.try_finalize::<64>().unwrap();"]
            #[doc = "assert_ne!(res.as_slice(), input.as_slice());"]
            #[doc = "```"]
            #[inline]
            pub fn try_finalize<const C: usize>(&mut self) -> Result<[u8; C], ()> {
                let mut buf = [0u8; C];
                self.finalize_into_sized(&mut buf).unit_err(buf)
            }

            #[doc = concat!(
                "Calls the `", stringify!($finalize), "` function, finalizing the extensible ",
                "hashing of data and resetting the underlying `", stringify!($wc), "` instance's ",
                "state with the default digest size of `", stringify!($ds), "` bytes."
            )]
            #[doc = ""]
            #[doc = "# Returns"]
            #[doc = ""]
            #[doc = "On success, this returns the default output digest."]
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
            #[doc = "let res = hasher.finalize_default().unwrap();"]
            #[doc = "assert_ne!(res.as_slice(), input.as_slice());"]
            #[doc = "```"]
            #[inline]
            pub fn finalize_default(&mut self) -> Result<[u8; $ds], ()> {
                self.try_finalize::<{ $ds }>()
            }

            #[doc = concat!(
                "Calls the `", stringify!($finalize), "` function, finalizing the extensible ",
                "hashing of data and resetting the underlying `", stringify!($wc),
                "` instance's state."
            )]
            #[doc = ""]
            #[doc = "# Panics"]
            #[doc = ""]
            #[doc = "If the underlying finalize function fails. If panicking is not acceptable for your "]
            #[doc = "use case, see [`try_finalize`] or [`finalize_into`] instead."]
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
            #[doc = "let res = hasher.try_finalize::<24>().unwrap();"]
            #[doc = "assert_ne!(res.as_slice(), input.as_slice());"]
            #[doc = "```"]
            #[doc = ""]
            #[doc = "[`try_finalize`]: Self::try_finalize"]
            #[doc = "[`finalize_into`]: Self::finalize_into"]
            #[cfg(feature = "panic-api")]
            #[track_caller]
            pub fn finalize<const C: usize>(&mut self) -> [u8; C] {
                self.try_finalize::<{ C }>().expect(concat!(
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

        impl Drop for $name {
            #[doc = concat!(
                "Calls the `", stringify!($free), "` function, cleaning up after itself."
            )]
            #[inline]
            fn drop(&mut self) {
                unsafe { $free(::core::ptr::addr_of_mut!(self.inner)) }
            }
        }

        copy_impl! {
            name: $name,
            wc: $wc,
            copy: $copy,
            finalize_func: finalize_default
        }

        #[cfg(test)]
        mod unit_tests {
            use super::*;

            #[test]
            fn test_new() {
                let hasher = $name::new();
                assert!(hasher.is_ok());
            }

            #[test]
            fn test_update_single_finalize() {
                let mut hasher = $name::new().unwrap();
                let input = b"hello world";
                assert!(hasher.try_update(input).is_ok());

                let mut output = [0u8; 64];
                assert!(hasher.finalize_into(&mut output).is_ok());
                assert_eq!(output.len(), 64);
            }

            #[test]
            fn test_multiple_updates_before_finalize() {
                let mut hasher = $name::new().unwrap();
                let inputs = [b"part1", b"part2", b"part3"];
                for input in inputs {
                    assert!(hasher.try_update(input).is_ok());
                }

                let mut output = [0u8; 64];
                assert!(hasher.finalize_into(&mut output).is_ok());
                assert_eq!(output.len(), 64);
            }

            #[test]
            fn test_empty_input() {
                let mut hasher = $name::new().unwrap();
                let input: &[u8] = &[];
                assert!(hasher.try_update(input).is_ok());

                let mut output = [0u8; 64];
                assert!(hasher.finalize_into(&mut output).is_ok());
                assert_eq!(output.len(), 64);
            }

            #[test]
            fn test_large_input() {
                let mut hasher = $name::new().unwrap();
                let input = vec![0u8; 10 * 1024 * 1024]; // 10 MB
                assert!(hasher.try_update(&input).is_ok());

                let mut output = [0u8; 64];
                assert!(hasher.finalize_into(&mut output).is_ok());
                assert_eq!(output.len(), 64);
            }

            #[test]
            fn test_finalize_into_sized_exact() {
                let mut hasher = $name::new().unwrap();
                let input = b"exact sized finalize";
                assert!(hasher.try_update(input).is_ok());

                let mut output = [0u8; $ds];
                assert!(hasher.finalize_into_sized(&mut output).is_ok());
                assert_eq!(output.len(), $ds);
            }

            #[test]
            fn test_finalize_default() {
                let mut hasher = $name::new().unwrap();
                let input = b"default finalize test";
                assert!(hasher.try_update(input).is_ok());

                let output = hasher.finalize_default();
                assert!(output.is_ok());
                assert_eq!(output.unwrap().len(), $ds);
            }

            #[test]
            fn test_try_finalize_variable_size() {
                let mut hasher = $name::new().unwrap();
                let input = b"variable size finalize test";
                assert!(hasher.try_update(input).is_ok());

                let res = hasher.try_finalize::<128>();
                assert!(res.is_ok());
                assert_eq!(res.unwrap().len(), 128);
            }

            #[test]
            fn test_update_sized() {
                let mut hasher = $name::new().unwrap();
                let input: &[u8; 5] = b"hello";
                assert!(hasher.update_sized(input).is_ok());

                let mut output = [0u8; 64];
                assert!(hasher.finalize_into(&mut output).is_ok());
                assert_eq!(output.len(), 64);
            }

            #[test]
            fn test_finalize_after_reset() {
                let mut hasher = $name::new().unwrap();
                let input1 = b"first input";
                let input2 = b"second input";

                assert!(hasher.try_update(input1).is_ok());
                let mut output1 = [0u8; 64];
                assert!(hasher.finalize_into(&mut output1).is_ok());

                assert!(hasher.try_update(input2).is_ok());
                let mut output2 = [0u8; 64];
                assert!(hasher.finalize_into(&mut output2).is_ok());

                assert_ne!(output1, output2);
            }

            #[test]
            fn test_finalize_default_no_input() {
                let mut hasher = $name::new().unwrap();
                let output = hasher.finalize_default();
                assert!(output.is_ok());
                assert_eq!(output.unwrap().len(), $ds);
            }

            #[test]
            fn test_update_10_mb() {
                let mut hasher = $name::new().unwrap();
                let input = vec![0u8; 10_000_000]; // 10 MB
                assert!(hasher.try_update(&input).is_ok());

                let mut output = [0u8; 64];
                assert!(hasher.finalize_into_sized(&mut output).is_ok());
                assert_eq!(output.len(), 64);
            }

            #[test]
            fn test_finalize_into_sized_ds_size() {
                let mut hasher = $name::new().unwrap();
                let input = b"exact ds size finalize test";
                assert!(hasher.try_update(input).is_ok());

                let mut output = [0u8; $ds];
                assert!(hasher.finalize_into_sized(&mut output).is_ok());
                assert_eq!(output.len(), $ds);
            }

            #[test]
            fn test_finalize_into_large_output_buffer() {
                let mut hasher = $name::new().unwrap();
                let input = b"large output buffer finalize test";
                assert!(hasher.try_update(input).is_ok());

                let mut output = vec![0u8; 10_000]; // 10 KB
                assert!(hasher.finalize_into(&mut output).is_ok());
                assert_eq!(output.len(), 10_000);
            }

            #[test]
            fn test_finalize_after_empty_input() {
                let mut hasher = $name::new().unwrap();
                let input: &[u8] = &[];
                assert!(hasher.try_update(input).is_ok());

                let mut output = [0u8; 64];
                assert!(hasher.finalize_into(&mut output).is_ok());

                let mut output2 = [0u8; 64];
                assert!(hasher.finalize_into(&mut output2).is_ok());

                assert_eq!(output, output2);
            }

            #[test]
            fn test_finalize_into_exact_zero_length() {
                let mut hasher = $name::new().unwrap();
                let input = b"zero length output buffer test";
                assert!(hasher.try_update(input).is_ok());

                let mut output: [u8; 0] = [];
                assert!(hasher.finalize_into_sized(&mut output).is_ok());
            }

            #[test]
            fn test_finalize_default_multiple_no_updates() {
                let mut hasher = $name::new().unwrap();

                let output1 = hasher.finalize_default();
                assert!(output1.is_ok());

                let output2 = hasher.finalize_default();
                assert!(output2.is_ok());

                assert_eq!(output1.unwrap().as_slice(), output2.unwrap().as_slice());
            }

            #[test]
            fn test_update_after_finalize() {
                let mut hasher = $name::new().unwrap();
                let input1 = b"input before finalize";
                let input2 = b"input after finalize";

                assert!(hasher.try_update(input1).is_ok());
                let mut output1 = [0u8; 64];
                assert!(hasher.finalize_into(&mut output1).is_ok());

                assert!(hasher.try_update(input2).is_ok());
                let mut output2 = [0u8; 64];
                assert!(hasher.finalize_into(&mut output2).is_ok());

                assert_ne!(output1, output2);
            }

            #[test]
            fn test_finalize_with_multiple_threads() {
                use std::sync::{Arc, Mutex};
                use std::thread;

                let hasher = Arc::new(Mutex::new($name::new().unwrap()));
                let input = b"multithreaded finalize test";

                let handles: Vec<_> = (0..10).map(|_| {
                    let hasher_clone = Arc::clone(&hasher);
                    let input_clone = input.clone();
                    thread::spawn(move || {
                        let mut hasher = hasher_clone.lock().unwrap();
                        assert!(hasher.try_update(&input_clone).is_ok());
                        let mut output = [0u8; 64];
                        assert!(hasher.finalize_into(&mut output).is_ok());
                        output
                    })
                }).collect();

                for handle in handles {
                    let output = handle.join().expect("Thread panicked");
                    assert_eq!(output.len(), 64);
                }
            }

            #[test]
            fn test_finalize_with_various_output_sizes() {
                let mut hasher = $name::new().unwrap();
                let input = b"various output sizes test";
                assert!(hasher.try_update(input).is_ok());

                let sizes = [16, 32, 64, 128, 256];
                for &size in &sizes {
                    let mut output = vec![0u8; size];
                    assert!(hasher.finalize_into(&mut output).is_ok());
                    assert_eq!(output.len(), size);
                }
            }

            #[test]
            fn test_finalize_into_exact_max_size() {
                let mut hasher = $name::new().unwrap();
                let input = b"max size finalize test";
                assert!(hasher.try_update(input).is_ok());

                const MAX_SIZE: usize = 10_000;
                let mut output = [0u8; MAX_SIZE];
                assert!(hasher.finalize_into_sized(&mut output).is_ok());
                assert_eq!(output.len(), MAX_SIZE);
            }

            #[test]
            fn test_finalize_into_exact_after_multiple_updates() {
                let mut hasher = $name::new().unwrap();
                let inputs = [b"update1", b"update2", b"update3"];
                for input in inputs {
                    assert!(hasher.try_update(input).is_ok());
                }

                let mut output = [0u8; $ds];
                assert!(hasher.finalize_into_sized(&mut output).is_ok());
                assert_eq!(output.len(), $ds);
            }

            #[test]
            fn test_finalize_default_reset_behavior() {
                let mut hasher = $name::new().unwrap();
                let input = b"multiple finalize calls test";
                assert!(hasher.try_update(input).is_ok());

                let output1 = hasher.finalize_default();
                assert!(output1.is_ok());

                let output2 = hasher.finalize_default();
                assert!(output2.is_ok());

                assert_ne!(output1.unwrap().as_slice(), output2.unwrap().as_slice());
            }

            #[test]
            fn test_finalize_into_overlapping_mut_slices() {
                let mut hasher = $name::new().unwrap();
                let input = b"overlapping mutable slices test";
                assert!(hasher.try_update(input).is_ok());

                let mut buffer = [0u8; 128];
                let (left, right) = buffer.split_at_mut(64);
                assert!(hasher.finalize_into(left).is_ok());
                assert!(hasher.finalize_into(right).is_ok());
            }

            #[test]
            fn test_finalize_with_different_output_sizes_sequentially() {
                let mut hasher = $name::new().unwrap();
                let input = b"sequential different output sizes test";
                assert!(hasher.try_update(input).is_ok());

                let mut output1 = [0u8; 32];
                assert!(hasher.finalize_into(&mut output1).is_ok());
                assert_eq!(output1.len(), 32);

                let mut output2 = [0u8; 64];
                assert!(hasher.finalize_into(&mut output2).is_ok());
                assert_eq!(output2.len(), 64);
            }

            #[test]
            fn test_finalize_after_multiple_large_inputs() {
                let mut hasher = $name::new().unwrap();
                let inputs = [
                    vec![0u8; 5_000_000],
                    vec![1u8; 10_000_000],
                    vec![2u8; 15_000_000],
                ];

                for input in &inputs {
                    assert!(hasher.try_update(input).is_ok());
                    let mut output = [0u8; 64];
                    assert!(hasher.finalize_into(&mut output).is_ok());
                }
            }

            #[test]
            fn test_finalize_into_exact_multiple_exact_sizes() {
                let mut hasher = $name::new().unwrap();
                let inputs = [b"exact size A", b"exact size B", b"exact size C"];
                for input in inputs {
                    assert!(hasher.try_update(input).is_ok());
                    let mut output = [0u8; $ds];
                    assert!(hasher.finalize_into_sized(&mut output).is_ok());
                }
            }

            #[test]
            fn test_finalize_with_random_output_sizes() {
                let mut hasher = $name::new().unwrap();
                let input = b"random output sizes test";
                assert!(hasher.try_update(input).is_ok());

                let sizes = [15, 64, 100, 255, 1024];
                for &size in &sizes {
                    let mut output = vec![0u8; size];
                    assert!(hasher.finalize_into(&mut output).is_ok());
                    assert_eq!(output.len(), size);
                }
            }

            #[test]
            fn test_finalize_into_exact_varying_exact_sizes() {
                let mut hasher = $name::new().unwrap();
                let input = b"varying exact sizes finalize test";
                assert!(hasher.try_update(input).is_ok());

                let sizes = [32, 64, 128, 256];
                for size in sizes {
                    let mut output = vec![0u8; size];
                    assert!(hasher.finalize_into(output.as_mut_slice()).is_ok());
                    assert_eq!(output.len(), size);
                }
            }

            #[test]
            fn test_finalize_after_finalize_with_empty_input() {
                let mut hasher = $name::new().unwrap();

                let mut output1 = [0u8; 64];
                assert!(hasher.finalize_into(&mut output1).is_ok());

                let mut output2 = [0u8; 64];
                assert!(hasher.finalize_into(&mut output2).is_ok());

                assert_eq!(output1, output2);
            }

            #[test]
            fn test_finalize_into_exact_with_different_sizes() {
                let mut hasher = $name::new().unwrap();
                let inputs = [b"exact size test1", b"exact size test2"];

                for input in inputs {
                    assert!(hasher.try_update(input).is_ok());
                    let mut output = [0u8; $ds];
                    assert!(hasher.finalize_into_sized(&mut output).is_ok());
                }
            }

            #[test]
            fn test_finalize_with_unicode_input() {
                let mut hasher = $name::new().unwrap();
                let input = "こんにちは世界".as_bytes(); // "Hello, World" in Japanese
                assert!(hasher.try_update(input).is_ok());

                let mut output = [0u8; 64];
                assert!(hasher.finalize_into(&mut output).is_ok());
                assert_eq!(output.len(), 64);
            }

            #[test]
            fn test_finalize_with_repeated_updates() {
                let mut hasher = $name::new().unwrap();
                let input = b"repeated updates test";
                for _ in 0..1000 {
                    assert!(hasher.try_update(input).is_ok());
                }

                let mut output = [0u8; 64];
                assert!(hasher.finalize_into(&mut output).is_ok());
                assert_eq!(output.len(), 64);
            }

            #[test]
            fn test_finalize_into_sized_after_multiple_updates() {
                let mut hasher = $name::new().unwrap();
                let inputs = [b"update1", b"update2", b"update3"];
                for input in inputs {
                    assert!(hasher.try_update(input).is_ok());
                }

                let mut output = [0u8; $ds];
                assert!(hasher.finalize_into_sized(&mut output).is_ok());
                assert_eq!(output.len(), $ds);
            }

            #[test]
            fn test_finalize_with_random_updates_and_finalizes() {
                use rand::Rng;

                let mut hasher = $name::new().unwrap();
                let mut rng = rand::thread_rng();

                for _ in 0..100 {
                    let size = rng.gen_range(0..1024);
                    let input: Vec<u8> = (0..size).map(|_| rng.gen()).collect();
                    assert!(hasher.try_update(&input).is_ok());

                    let output_size = rng.gen_range(1..2048);
                    let mut output = vec![0u8; output_size];
                    assert!(hasher.finalize_into(&mut output).is_ok());
                    assert_eq!(output.len(), output_size);
                }
            }

            #[test]
            fn test_finalize_after_large_input_multiple_times() {
                let mut hasher = $name::new().unwrap();
                let input = vec![3u8; 20_000_000]; // 20 MB
                assert!(hasher.try_update(&input).is_ok());

                for _ in 0..10 {
                    let mut output = [0u8; 64];
                    assert!(hasher.finalize_into(&mut output).is_ok());
                }
            }

            #[test]
            fn test_finalize_with_special_characters_input() {
                let mut hasher = $name::new().unwrap();
                let input = b"sp3c!@l ch@r@ct3rs #test";
                assert!(hasher.try_update(input).is_ok());

                let mut output = [0u8; 64];
                assert!(hasher.finalize_into(&mut output).is_ok());
                assert_eq!(output.len(), 64);
            }

            #[test]
            fn test_finalize_after_finalizing_with_large_input() {
                let mut hasher = $name::new().unwrap();
                let input = vec![4u8; 50_000_000]; // 50 MB
                assert!(hasher.try_update(&input).is_ok());

                let mut output = [0u8; 64];
                assert!(hasher.finalize_into(&mut output).is_ok());

                // Finalize again without updates
                let mut output2 = [0u8; 64];
                assert!(hasher.finalize_into(&mut output2).is_ok());

                // Outputs should be different
                assert_ne!(output, output2);
            }

            #[test]
            fn test_finalize_with_multiple_different_inputs() {
                let mut hasher = $name::new().unwrap();
                let inputs = [
                    b"input one".as_slice(),
                    b"input two".as_slice(),
                    b"input three".as_slice(),
                    b"input four".as_slice(),
                    b"input five".as_slice(),
                ];

                for input in &inputs {
                    assert!(hasher.try_update(input).is_ok());
                }

                let mut output = [0u8; 64];
                assert!(hasher.finalize_into(&mut output).is_ok());
                assert_eq!(output.len(), 64);
            }
        }

        #[cfg(test)]
        mod property_tests {
            use super::*;
            use digest::{ExtendableOutput, ExtendableOutputReset, XofReader, Update};
            use sha3::$name as RcShake;
            use proptest::prelude::*;

            fn get_rc_hasher() -> RcShake {
                RcShake::default()
            }

            proptest! {
                #![proptest_config(ProptestConfig::with_cases(1000))]

                #[test]
                fn prop_single_update(
                    input in any::<Vec<u8>>(),
                    output_size in 1..2048usize
                ) {
                    let mut wolf = $name::new().unwrap();
                    let mut rc = get_rc_hasher();

                    // Update both hashers
                    assert!(wolf.try_update(&input).is_ok());
                    rc.update(&input);

                    // Finalize both hashers
                    let mut wolf_output = vec![0u8; output_size];
                    assert!(wolf.finalize_into(&mut wolf_output).is_ok());

                    let mut rc_output = vec![0u8; output_size];
                    rc.finalize_xof().read(&mut rc_output);

                    // Compare outputs
                    prop_assert_eq!(wolf_output, rc_output);
                }

                #[test]
                fn prop_multiple_updates(
                    inputs in proptest::collection::vec(any::<Vec<u8>>(), 0..100),
                    output_size in 1..2048usize
                ) {
                    let mut wolf = $name::new().unwrap();
                    let mut rc = get_rc_hasher();

                    for input in &inputs {
                        assert!(wolf.try_update(input).is_ok());
                        rc.update(input);
                    }

                    let mut wolf_output = vec![0u8; output_size];
                    assert!(wolf.finalize_into(&mut wolf_output).is_ok());

                    let mut rc_output = vec![0u8; output_size];
                    rc.finalize_xof().read(&mut rc_output);

                    // Compare outputs
                    prop_assert_eq!(wolf_output, rc_output);
                }

                #[test]
                fn prop_finalize_idempotent(
                    input in any::<Vec<u8>>(),
                    output_size in 1..2048usize
                ) {
                    let mut wolf = $name::new().unwrap();
                    let mut rc = get_rc_hasher();

                    assert!(wolf.try_update(&input).is_ok());
                    rc.update(&input);

                    let mut wolf_output1 = vec![0u8; output_size];
                    assert!(wolf.finalize_into(&mut wolf_output1).is_ok());

                    let mut rc_output1 = vec![0u8; output_size];
                    rc.finalize_xof_reset().read(&mut rc_output1);

                    let mut wolf_output2 = vec![0u8; output_size];
                    assert!(wolf.finalize_into(&mut wolf_output2).is_ok());

                    let mut rc_output2 = vec![0u8; output_size];
                    rc.finalize_xof().read(&mut rc_output2);

                    // Compare first outputs
                    prop_assert_eq!(wolf_output1, rc_output1);

                    // Compare second outputs (hash of empty input)
                    prop_assert_eq!(wolf_output2, rc_output2);
                }

                #[test]
                fn prop_zero_length_input(
                    output_size in 1..2048usize
                ) {
                    let mut wolf = $name::new().unwrap();
                    let mut rc = get_rc_hasher();

                    let input: Vec<u8> = vec![];
                    assert!(wolf.try_update(&input).is_ok());
                    rc.update(&input);

                    let mut wolf_output = vec![0u8; output_size];
                    assert!(wolf.finalize_into(&mut wolf_output).is_ok());

                    let mut rc_output = vec![0u8; output_size];
                    rc.finalize_xof().read(&mut rc_output);

                    // Compare outputs
                    prop_assert_eq!(wolf_output, rc_output);
                }

                #[test]
                fn prop_variable_output_sizes(
                    input in any::<Vec<u8>>(),
                    sizes in proptest::collection::vec(1..2048usize, 1..10)
                ) {
                    let mut wolf = $name::new().unwrap();
                    let mut rc = get_rc_hasher();

                    // Update both hashers
                    assert!(wolf.try_update(&input).is_ok());
                    rc.update(&input);

                    for &size in &sizes {
                        let mut wolf_output = vec![0u8; size];
                        assert!(wolf.finalize_into(&mut wolf_output).is_ok());

                        let mut rc_output = vec![0u8; size];
                        rc.finalize_xof_reset().read(&mut rc_output);

                        // Compare outputs
                        prop_assert_eq!(wolf_output, rc_output);
                    }
                }
            }
        }
    };
}