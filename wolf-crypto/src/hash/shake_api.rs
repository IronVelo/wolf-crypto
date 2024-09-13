macro_rules! shake_api {
    (
        name: $name:ident,
        wc: $wc:ty,
        ds: $ds:literal,
        init: $init:ident, heap: $heap:expr, devid: $devId:expr,
        update: $update:ident,
        finalize: $finalize:ident,
        free: $free:ident
        $(,)?
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
    }
}