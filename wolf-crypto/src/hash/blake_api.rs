macro_rules! blake_api {
    (
        name: $name:ident,
        wc: $wc:ty,
        // applies to both key and the digest length
        max: $max:literal,
        init: $init:ident,
        init_with_key: $init_key:ident,
        update: $update:ident,
        final: $final:ident,
        ll_final: $ll_final:ident,
        w_loc: $warning:literal $(,)?
    ) => {
        #[doc = concat!("The `", stringify!($name), "` hasher.")]
        #[doc = ""]
        #[doc = "# Soundness Note"]
        #[doc = ""]
        #[doc = concat!(
            "In the underlying `wolfcrypt` source, the `", stringify!($ll_final),
            "` function includes a comment "
        )]
        #[doc = "[`/* Is this correct? */`][1], which may raise concern about its implementation."]
        #[doc = "However, we have subjected this Rust API to extensive testing, including property tests"]
        #[doc = concat!(
            "against other trusted ", stringify!($name),
            " implementations, and no failures have been observed."
        )]
        #[doc = ""]
        #[doc = "Furthermore, this comment is not present in the public WolfSSL API, suggesting "]
        #[doc = "that they may have confidence in their own implementation despite the internal comment."]
        #[doc = ""]
        #[doc = "# Const Generic"]
        #[doc = ""]
        #[doc = concat!(
            "* `C` - The length of the ", stringify!($name),
            " digest to implement, with a maximum length of `", stringify!($max), "`."
        )]
        #[doc = ""]
        #[doc = "# Example"]
        #[doc = ""]
        #[doc = "```"]
        #[doc = concat!("use wolf_crypto::hash::", stringify!($name), ";")]
        #[doc = ""]
        #[doc = concat!(
            "let mut hasher = ", stringify!($name), "::<", stringify!($max), ">::new().unwrap();"
        )]
        #[doc = ""]
        #[doc = "let input = b\"hello world\";"]
        #[doc = "assert!(hasher.try_update(input.as_slice()).is_ok());"]
        #[doc = ""]
        #[doc = "let finalized = hasher.try_finalize().unwrap();"]
        #[doc = concat!("assert_eq!(finalized.len(), ", stringify!($max), ");")]
        #[doc = "```"]
        #[doc = ""]
        #[doc = concat!("[1]: ", $warning)]
        pub struct $name<const C: usize> {
            inner: $wc
        }

        impl<const C: usize> $name<C> {
            #[doc = concat!("Create a new `", stringify!($name), "` instance.")]
            #[doc = ""]
            #[doc = "# Errors"]
            #[doc = ""]
            #[doc = concat!(
                "- If the digest length is greater than `", stringify!($max), "` (const generic `C`)"
            )]
            #[doc = concat!(
                "- If the underling initialization function fails (`", stringify!($init), "`)"
            )]
            #[doc = ""]
            #[doc = "# Example"]
            #[doc = ""]
            #[doc = "```"]
            #[doc = concat!("use wolf_crypto::hash::", stringify!($name), ";")]
            #[doc = ""]
            #[doc = concat!(
                "let mut hasher = ", stringify!($name), "::<", stringify!($max), ">::new().unwrap();"
            )]
            #[doc = ""]
            #[doc = "let input = b\"hello world\";"]
            #[doc = "assert!(hasher.try_update(input.as_slice()).is_ok());"]
            #[doc = ""]
            #[doc = "let finalized = hasher.try_finalize().unwrap();"]
            #[doc = "assert_ne!(finalized.as_slice(), input.as_slice());"]
            #[doc = concat!("assert_eq!(finalized.len(), ", stringify!($max), ");")]
            #[doc = ""]
            #[doc = concat!("// Maximum `C` is ", stringify!($max))]
            #[doc = concat!(
                "assert!(", stringify!($name), "::<{", stringify!($max * 2), "}>::new().is_err());"
            )]
            #[doc = "```"]
            pub fn new() -> Result<Self, $crate::error::Unspecified> {
                if !$crate::const_lte::<C, { $max }>() { return Err($crate::error::Unspecified); }
                let mut res = $crate::opaque_res::Res::new();

                unsafe {
                    let mut inner = ::core::mem::MaybeUninit::<$wc>::uninit();
                    res.ensure_0($init(inner.as_mut_ptr(), C as u32));
                    res.unit_err_with(|| Self { inner: inner.assume_init() })
                }
            }

            #[inline]
            unsafe fn new_with_key_unchecked(
                key: &[u8]
            ) -> (::core::mem::MaybeUninit<$wc>, $crate::opaque_res::Res) {
                let mut res = $crate::opaque_res::Res::new();
                let mut inner = ::core::mem::MaybeUninit::<$wc>::uninit();

                res.ensure_0($init_key(
                    inner.as_mut_ptr(),
                    C as u32,
                    key.as_ptr(),
                    key.len() as u32
                ));

                (inner, res)
            }

            #[doc = concat!("Create a new `", stringify!($name), "` instance using a key.")]
            #[doc = ""]
            #[doc = concat!(
                "The key is used to create a keyed ", stringify!($name), " instance, ",
                "which is suitable for"
            )]
            #[doc = "message authentication (MAC) purposes. The output digest length is determined"]
            #[doc = "by the constant generic parameter `C`."]
            #[doc = ""]
            #[doc = "# Errors"]
            #[doc = ""]
            #[doc = concat!("- If the digest length `C` is greater than `", stringify!($max), "`.")]
            #[doc = concat!("- If the key length exceeds `", stringify!($max), "` bytes.")]
            #[doc = "- If the key is of zero length."]
            #[doc = concat!(
                "- If the underlying initialization function (`", stringify!($init_key), "`) fails.\
            ")]
            #[doc = ""]
            #[doc = "# Arguments"]
            #[doc = ""]
            #[doc = concat!(
                "* `key` - A secret key used to initialize the ", stringify!($name),
                " instance. The length of the key must be less than or equal to ", stringify!($max),
                " bytes."
            )]
            #[doc = ""]
            #[doc = "# Example"]
            #[doc = ""]
            #[doc = "```"]
            #[doc = concat!("use wolf_crypto::hash::", stringify!($name), ";")]
            #[doc = ""]
            #[doc = "let key = b\"my-secret-key\";"]
            #[doc = concat!(
                "let mut hasher = ", stringify!($name), "::<", stringify!($max),
                ">::new_with_key(key).unwrap();"
            )]
            #[doc = ""]
            #[doc = "let input = b\"hello world\";"]
            #[doc = "assert!(hasher.try_update(input.as_slice()).is_ok());"]
            #[doc = ""]
            #[doc = "let finalized = hasher.try_finalize().unwrap();"]
            #[doc = "assert_ne!(finalized.as_slice(), input.as_slice());"]
            #[doc = concat!("assert_eq!(finalized.len(), ", stringify!($max), ");")]
            #[doc = ""]
            #[doc = concat!(
                "// Key length must be less than or equal to ", stringify!($max), " bytes."
            )]
            #[doc = concat!("let long_key = [0u8; ", stringify!($max * 2), "];")]
            #[doc = concat!(
                "assert!(", stringify!($name), "::<", stringify!($max),
                ">::new_with_key(&long_key).is_err());"
            )]
            #[doc = "```"]
            pub fn new_with_key(key: &[u8]) -> Result<Self, $crate::error::Unspecified> {
                if !($crate::const_lte::<C, { $max }>() && $crate::lte::<{ $max }>(key.len())) {
                    return Err($crate::error::Unspecified);
                }

                unsafe {
                    let (inner, res) = Self::new_with_key_unchecked(key);
                    res.unit_err_with(|| Self { inner: inner.assume_init() })
                }
            }

            #[doc = concat!("Create a new `", stringify!($name), "` instance using a fixed-size key.")]
            #[doc = ""]
            #[doc = "This function allows you to specify the key as a fixed-size array. It is"]
            #[doc = "similar to [`new_with_key`] but function preconditions are checked at compile time."]
            #[doc = ""]
            #[doc = "# Errors"]
            #[doc = ""]
            #[doc = concat!("- If the digest length `C` is greater than `", stringify!($max), "`.")]
            #[doc = concat!(
                "- If the key length exceeds `", stringify!($max), "` bytes (compile-time check)."
            )]
            #[doc = "- If the key is of zero length."]
            #[doc = concat!(
                "- If the underlying initialization function (`", stringify!($init_key), "`) fails."
            )]
            #[doc = ""]
            #[doc = "# Arguments"]
            #[doc = ""]
            #[doc = concat!(
                "- `key`: A fixed-size secret key (length `K`) used to initialize the `",
                stringify!($name), "` instance. The length of the key must be less than or equal to ",
                stringify!($max), " bytes."
            )]
            #[doc = ""]
            #[doc = "# Example"]
            #[doc = ""]
            #[doc = "```"]
            #[doc = concat!("use wolf_crypto::hash::", stringify!($name), ";")]
            #[doc = ""]
            #[doc = "let key: [u8; 32] = [0x00; 32];"]
            #[doc = concat!(
                "let mut hasher = ", stringify!($name), "::<", stringify!($max),
                ">::new_with_sized_key(&key).unwrap();"
            )]
            #[doc = ""]
            #[doc = "let input = b\"some data\";"]
            #[doc = "assert!(hasher.try_update(input.as_slice()).is_ok());"]
            #[doc = ""]
            #[doc = "let finalized = hasher.try_finalize().unwrap();"]
            #[doc = concat!("assert_eq!(finalized.len(), ", stringify!($max), ");")]
            #[doc = ""]
            #[doc = concat!(
                "// Key length must be less than or equal to ", stringify!($max), " bytes."
            )]
            #[doc = concat!("let oversized_key = [0u8; ", stringify!($max * 2), "];")]
            #[doc = concat!(
                "assert!(", stringify!($name), "::<", stringify!($max),
                ">::new_with_sized_key(&oversized_key).is_err());"
            )]
            #[doc = "```"]
            #[doc = "[`new_with_key`]: Self::new_with_key"]
            pub fn new_with_sized_key<const K: usize>(key: &[u8; K]) -> Result<Self, $crate::error::Unspecified> {
                if !($crate::const_lte::<C, { $max }>() && $crate::const_lte::<K, { $max }>()) {
                    return Err($crate::error::Unspecified);
                }

                unsafe {
                    let (inner, res) = Self::new_with_key_unchecked(key);
                    res.unit_err_with(|| Self { inner: inner.assume_init() })
                }
            }

            #[doc = concat!(
                "Update the `", stringify!($name),
                "` instance with the provided data, without performing any safety checks."
            )]
            #[doc = ""]
            #[doc = "# Safety"]
            #[doc = ""]
            #[doc = "The length of the data is cast to a 32-bit unsigned integer without checking for"]
            #[doc = "overflow. While this is unlikely to occur in most practical scenarios, it is not impossible,"]
            #[doc = "especially with very large slices. Therefore, this function is marked `unsafe`."]
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
            #[doc = concat!("let mut hasher = ", stringify!($name), "::<", stringify!($max), ">::new().unwrap();")]
            #[doc = ""]
            #[doc = "let input = b\"hello world\";"]
            #[doc = "// SAFETY: The length of `hello world` is 11, which cannot overflow even an 8-bit integer."]
            #[doc = "let res = unsafe { hasher.update_unchecked(input.as_slice()) };"]
            #[doc = "assert!(res.is_ok());"]
            #[doc = ""]
            #[doc = "let finalized = hasher.try_finalize().unwrap();"]
            #[doc = "assert_ne!(finalized.as_slice(), input.as_slice());"]
            #[doc = concat!("assert_eq!(finalized.len(), ", stringify!($max), ");")]
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

            #[doc = concat!("Update the `", stringify!($name), "` instance with the provided data.")]
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
            #[doc = "- If the length of `data` cannot be safely cast to a `u32`."]
            #[doc = concat!("- If the underlying `", stringify!($update), "` function fails.")]
            #[doc = ""]
            #[doc = "# Example"]
            #[doc = ""]
            #[doc = "```"]
            #[doc = concat!("use wolf_crypto::hash::", stringify!($name), ";")]
            #[doc = ""]
            #[doc = concat!("let mut hasher = ", stringify!($name), "::<", stringify!($max), ">::new().unwrap();")]
            #[doc = ""]
            #[doc = "let input = b\"hello world\";"]
            #[doc = "assert!(hasher.try_update(input.as_slice()).is_ok());"]
            #[doc = ""]
            #[doc = "let finalized = hasher.try_finalize().unwrap();"]
            #[doc = "assert_ne!(finalized.as_slice(), input.as_slice());"]
            #[doc = concat!("assert_eq!(finalized.len(), ", stringify!($max), ");")]
            #[doc = "```"]
            #[inline]
            pub fn try_update(&mut self, data: &[u8]) -> $crate::opaque_res::Res {
                if !$crate::can_cast_u32(data.len()) { return $crate::opaque_res::Res::ERR }
                unsafe { self.update_unchecked(data) }
            }

            #[doc = concat!(
                "Update the `", stringify!($name),
                "` instance with the provided data, using compile-time safety checks."
            )]
            #[doc = ""]
            #[doc = "# Arguments"]
            #[doc = ""]
            #[doc = "* `data` - The slice to update the underlying hasher state with, where the size of the slice"]
            #[doc = "   is known at compile time."]
            #[doc = ""]
            #[doc = "# Returns"]
            #[doc = ""]
            #[doc = "This function returns the result of the operation."]
            #[doc = ""]
            #[doc = "# Errors"]
            #[doc = ""]
            #[doc = "- If the length of `data` cannot be safely cast to a `u32`."]
            #[doc = concat!("- If the underlying `", stringify!($update), "` function fails.")]
            #[doc = ""]
            #[doc = "# Example"]
            #[doc = ""]
            #[doc = "```"]
            #[doc = concat!("use wolf_crypto::hash::", stringify!($name), ";")]
            #[doc = ""]
            #[doc = concat!("let mut hasher = ", stringify!($name), "::<", stringify!($max), ">::new().unwrap();")]
            #[doc = ""]
            #[doc = "let input = b\"hello world\";"]
            #[doc = "assert!(hasher.update_sized(&input).is_ok());"]
            #[doc = ""]
            #[doc = "let finalized = hasher.try_finalize().unwrap();"]
            #[doc = "assert_ne!(finalized.as_slice(), input.as_slice());"]
            #[doc = concat!("assert_eq!(finalized.len(), ", stringify!($max), ");")]
            #[doc = "```"]
            #[inline]
            pub fn update_sized<const OC: usize>(&mut self, data: &[u8; OC]) -> $crate::opaque_res::Res {
                if !$crate::const_can_cast_u32::<{ OC }>() { return $crate::opaque_res::Res::ERR }
                unsafe { self.update_unchecked(data) }
            }

            panic_api! {
            #[doc = concat!("Update the `", stringify!($name), "` instance with the provided data, panicking on failure.")]
            #[doc = ""]
            #[doc = "# Arguments"]
            #[doc = ""]
            #[doc = "* `data` - The slice to update the underlying hasher state with."]
            #[doc = ""]
            #[doc = "# Panics"]
            #[doc = ""]
            #[doc = "- If the length of `data` cannot be safely cast to a `u32`."]
            #[doc = concat!("- If the underlying `", stringify!($update), "` function fails.")]
            #[doc = ""]
            #[doc = "If a panic is not acceptable for your use case, consider using [`try_update`] instead."]
            #[doc = ""]
            #[doc = "# Example"]
            #[doc = ""]
            #[doc = "```"]
            #[doc = concat!("use wolf_crypto::hash::", stringify!($name), ";")]
            #[doc = ""]
            #[doc = concat!("let mut hasher = ", stringify!($name), "::<", stringify!($max), ">::new().unwrap();")]
            #[doc = ""]
            #[doc = "let input = b\"hello world\";"]
            #[doc = "hasher.update(input.as_slice());"]
            #[doc = ""]
            #[doc = "let finalized = hasher.try_finalize().unwrap();"]
            #[doc = "assert_ne!(finalized.as_slice(), input.as_slice());"]
            #[doc = concat!("assert_eq!(finalized.len(), ", stringify!($max), ");")]
            #[doc = "```"]
            #[doc = ""]
            #[doc = "[`try_update`]: Self::try_update"]
            #[track_caller]
            pub fn update(&mut self, data: &[u8]) {
                self.try_update(data).unit_err(())
                    .expect(concat!("Failed to update hash in `", stringify!($name), "`"))
            }
            }

            #[doc = concat!(
                "Finalize the `", stringify!($name),
                "` hashing process, writing the output to the provided buffer, without"
            )]
            #[doc = "performing safety checks."]
            #[doc = ""]
            #[doc = "# Safety"]
            #[doc = ""]
            #[doc = "The size of the `output` argument must be at least `C` (the size of the digest)."]
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
            #[doc = concat!("let mut hasher = ", stringify!($name), "::<", stringify!($max), ">::new().unwrap();")]
            #[doc = ""]
            #[doc = concat!("let mut output = [0u8; ", stringify!($max), "];")]
            #[doc = concat!(
                "// SAFETY: The size of the output buffer is exactly ", stringify!($max),
                " bytes (the size of the digest)."
            )]
            #[doc = "let res = unsafe { hasher.finalize_unchecked(&mut output) };"]
            #[doc = "assert!(res.is_ok());"]
            #[doc = "```"]
            #[inline]
            pub unsafe fn finalize_unchecked(mut self, output: &mut [u8]) -> $crate::opaque_res::Res {
                let mut res = $crate::opaque_res::Res::new();

                res.ensure_0($final(
                    ::core::ptr::addr_of_mut!(self.inner),
                    output.as_mut_ptr(),
                    C as u32
                ));

                res
            }

            #[doc = concat!(
                "Finalize the `", stringify!($name),
                "` hashing process, writing the output to the provided buffer."
            )]
            #[doc = ""]
            #[doc = "# Arguments"]
            #[doc = ""]
            #[doc = "* `output` - The buffer to store the output digest in."]
            #[doc = ""]
            #[doc = "# Errors"]
            #[doc = ""]
            #[doc = "- If the size of `output` is less than `C` (the size of the digest)."]
            #[doc = "- If the underlying finalize function fails."]
            #[doc = ""]
            #[doc = "# Example"]
            #[doc = ""]
            #[doc = "```"]
            #[doc = concat!("use wolf_crypto::hash::", stringify!($name), ";")]
            #[doc = concat!("let mut hasher = ", stringify!($name), "::<", stringify!($max), ">::new().unwrap();")]
            #[doc = ""]
            #[doc = "// use the hasher ..."]
            #[doc = ""]
            #[doc = concat!("let mut output = [0u8; ", stringify!($max), "];")]
            #[doc = "assert!(hasher.finalize_into(&mut output).is_ok());"]
            #[doc = "```"]
            #[inline]
            pub fn finalize_into(self, output: &mut [u8]) -> $crate::opaque_res::Res {
                if !$crate::gte::<{ C }>(output.len()) { return $crate::opaque_res::Res::ERR }
                unsafe { self.finalize_unchecked(output) }
            }

            #[doc = concat!(
                "Finalize the `", stringify!($name),
                "` hashing process, writing the output to a fixed-size buffer, and"
            )]
            #[doc = "performing safety checks at compilation time."]
            #[doc = ""]
            #[doc = "# Arguments"]
            #[doc = ""]
            #[doc = "* `output` - The fixed-size buffer to store the output digest in."]
            #[doc = ""]
            #[doc = "# Errors"]
            #[doc = ""]
            #[doc = "- If the length of `output` is less than `C` (the size of the digest)."]
            #[doc = "- If the underlying finalize function fails."]
            #[doc = ""]
            #[doc = "# Example"]
            #[doc = ""]
            #[doc = "```"]
            #[doc = concat!("use wolf_crypto::hash::", stringify!($name), ";")]
            #[doc = concat!("let mut hasher = ", stringify!($name), "::<", stringify!($max), ">::new().unwrap();")]
            #[doc = ""]
            #[doc = "// use the hasher ..."]
            #[doc = ""]
            #[doc = concat!("let mut output = [0u8; ", stringify!($max), "];")]
            #[doc = "assert!(hasher.finalize_into_sized(&mut output).is_ok());"]
            #[doc = "```"]
            #[inline]
            pub fn finalize_into_sized<const OC: usize>(self, output: &mut [u8; OC]) -> $crate::opaque_res::Res {
                if !$crate::const_gte::<{ OC }, { C }>() { return $crate::opaque_res::Res::ERR }
                unsafe { self.finalize_unchecked(output) }
            }

            #[doc = concat!(
                "Finalize the `", stringify!($name),
                "` hashing process, writing the output to a buffer with an exact size."
            )]
            #[doc = ""]
            #[doc = "This method is for cases where the size of the output buffer is exactly the same as the"]
            #[doc = "digest size (`C`). The buffer size is checked at compile time, so no runtime size checks"]
            #[doc = "are necessary, making this a highly optimized version of finalization."]
            #[doc = ""]
            #[doc = "# Arguments"]
            #[doc = ""]
            #[doc = "* `output` - The buffer to store the output digest in, with a size exactly equal to the"]
            #[doc = "             digest size (`C`)."]
            #[doc = ""]
            #[doc = "# Returns"]
            #[doc = ""]
            #[doc = "This function returns the result of the operation."]
            #[doc = ""]
            #[doc = "# Example"]
            #[doc = ""]
            #[doc = "```"]
            #[doc = concat!("use wolf_crypto::hash::", stringify!($name), ";")]
            #[doc = concat!("let mut hasher = ", stringify!($name), "::<", stringify!($max), ">::new().unwrap();")]
            #[doc = ""]
            #[doc = "// use the hasher ..."]
            #[doc = ""]
            #[doc = concat!("let mut output = [0u8; ", stringify!($max), "];")]
            #[doc = "assert!(hasher.finalize_into_exact(&mut output).is_ok());"]
            #[doc = "```"]
            #[doc = ""]
            #[doc = "**Note**: If the size of the output buffer is not exactly `C`, see [`finalize_into`] for"]
            #[doc = "greater flexibility, or [`finalize_into_sized`] if the size is known at compile time but is"]
            #[doc = "not exactly `C`."]
            #[doc = ""]
            #[doc = "[`finalize_into`]: Self::finalize_into"]
            #[doc = "[`finalize_into_sized`]: Self::finalize_into_sized"]
            #[inline]
            pub fn finalize_into_exact(self, output: &mut [u8; C]) -> $crate::opaque_res::Res {
                unsafe { self.finalize_unchecked(output) }
            }

            #[doc = concat!(
                "Finalize the `", stringify!($name), "` hashing process, returning the result as an array."
            )]
            #[doc = ""]
            #[doc = "# Returns"]
            #[doc = ""]
            #[doc = "On success, this returns the output digest as an array."]
            #[doc = ""]
            #[doc = "# Errors"]
            #[doc = ""]
            #[doc = "If the underlying finalize function fails."]
            #[doc = ""]
            #[doc = "# Example"]
            #[doc = ""]
            #[doc = "```"]
            #[doc = concat!("use wolf_crypto::hash::", stringify!($name), ";")]
            #[doc = concat!(
                "let mut hasher = ", stringify!($name), "::<", stringify!($max), ">::new().unwrap();"
            )]
            #[doc = ""]
            #[doc = "// use the hasher ..."]
            #[doc = ""]
            #[doc = "let res = hasher.try_finalize().unwrap();"]
            #[doc = concat!("assert_eq!(res.len(), ", stringify!($max), ");")]
            #[doc = "```"]
            #[inline]
            pub fn try_finalize(self) -> Result<[u8; C], $crate::error::Unspecified> {
                let mut buf = [0u8; C];
                self.finalize_into_exact(&mut buf).unit_err(buf)
            }

            panic_api! {
            #[doc = concat!(
                "Finalize the `", stringify!($name),
                "` hashing process, returning the result as an array, panicking on"
            )]
            #[doc = "failure."]
            #[doc = ""]
            #[doc = "# Returns"]
            #[doc = ""]
            #[doc = "On success, this returns the output digest as an array."]
            #[doc = ""]
            #[doc = "# Panics"]
            #[doc = ""]
            #[doc = "If the underlying finalize function fails."]
            #[doc = ""]
            #[doc = "If panicking is not acceptable for your use case, consider using [`try_finalize`] instead."]
            #[doc = ""]
            #[doc = "# Example"]
            #[doc = ""]
            #[doc = "```"]
            #[doc = concat!("use wolf_crypto::hash::", stringify!($name), ";")]
            #[doc = concat!("let mut hasher = ", stringify!($name), "::<", stringify!($max), ">::new().unwrap();")]
            #[doc = ""]
            #[doc = "// use the hasher ..."]
            #[doc = ""]
            #[doc = "let res = hasher.finalize();"]
            #[doc = concat!("assert_eq!(res.len(), ", stringify!($max), ");")]
            #[doc = "```"]
            #[doc = ""]
            #[doc = "[`try_finalize`]: Self::try_finalize"]
            #[track_caller]
            pub fn finalize(self) -> [u8; C] {
                self.try_finalize()
                    .expect(concat!("Failed to finalize in `", stringify!($name), "`"))
            }
            }
        }

        // SAFETY:
        // All methods which mutate the underlying state require a mutable reference,
        // the only way to obtain a mutable reference across thread boundaries is via
        // synchronization or unsafe in Rust (which then would be the user's responsibility).
        unsafe impl<const C: usize> Send for $name<C> {}

        // SAFETY:
        // There is no providing of interior mutability, all methods which mutate the underlying
        // state require a mutable reference, thus making this safe to mark `Sync`.
        unsafe impl<const C: usize> Sync for $name<C> {}

        #[cfg(test)]
        mod unit_tests {
            use super::*;
            use digest::Digest;

            #[test]
            fn rust_crypto_equivalence() {
                many_blake!($name => |mut wolf, mut rc| {
                    let input = b"hello world";

                    assert!(wolf.try_update(input.as_slice()).is_ok());
                    rc.update(input.as_slice());

                    let w_out  = wolf.try_finalize().unwrap();
                    let rc_out = rc.finalize();

                    assert_eq!(w_out.as_slice(), rc_out.as_slice());
                });
            }


            #[test]
            fn rust_crypto_partial_update_equivalence() {
                many_blake!($name => |mut wolf, mut rc| {
                    let input = b"hello w";

                    assert!(wolf.try_update(input.as_slice()).is_ok());
                    rc.update(input.as_slice());

                    let f = b"orld";

                    wolf.update(f.as_slice());
                    rc.update(f.as_slice());

                    let w_out  = wolf.try_finalize().unwrap();
                    let rc_out = rc.finalize();

                    assert_eq!(w_out.as_slice(), rc_out.as_slice());
                });
            }

            #[test]
            fn rust_crypto_empty_equivalence() {
                many_blake!($name => |mut wolf, mut rc| {
                    let input = b"";

                    assert!(wolf.try_update(input.as_slice()).is_ok());
                    rc.update(input.as_slice());

                    let w_out  = wolf.try_finalize().unwrap();
                    let rc_out = rc.finalize();

                    assert_eq!(w_out.as_slice(), rc_out.as_slice());
                })
            }

            #[test]
            fn rust_crypto_1mb_equivalence() {
                let input = vec![7u8; 1_000_000];

                many_blake!($name => |mut wolf, mut rc| {
                    assert!(wolf.try_update(input.as_slice()).is_ok());
                    rc.update(input.as_slice());

                    let w_out  = wolf.try_finalize().unwrap();
                    let rc_out = rc.finalize();

                    assert_eq!(w_out.as_slice(), rc_out.as_slice());
                })
            }
        }

        #[cfg(test)]
        mod property_tests {
            use super::*;
            use digest::Digest;

            use $crate::aes::test_utils::{BoundList, AnyList};
            use proptest::prelude::*;

            proptest! {
                #![proptest_config(ProptestConfig::with_cases(15_000))]

                #[test]
                fn rust_crypto_eq_wolf_single_update(
                    input in any::<BoundList<1024>>()
                ) {
                    many_blake!($name => |mut wolf, mut rc| {
                        prop_assert!(wolf.try_update(input.as_slice()).is_ok());
                        rc.update(input.as_slice());

                        let finalized = wolf.try_finalize().unwrap();
                        let rc_finalized = rc.finalize();

                        prop_assert_eq!(finalized.as_slice(), rc_finalized.as_slice());
                    });
                }
            }

            proptest! {
                #![proptest_config(ProptestConfig::with_cases(5_000))]

                // this takes a while, as testing multiple different digest sizes, iterating over
                // all inputs updating each.
                #[test]
                fn rust_crypto_eq_wolf_arb_updates(
                    inputs in any::<AnyList<32, BoundList<512>>>()
                ) {
                    many_blake!($name => |mut wolf, mut rc| {
                        for input in inputs.as_slice().iter() {
                            prop_assert!(wolf.try_update(input.as_slice()).is_ok());
                            rc.update(input.as_slice());
                        }

                        let finalized = wolf.try_finalize().unwrap();
                        let rc_finalized = rc.finalize();

                        prop_assert_eq!(finalized.as_slice(), rc_finalized.as_slice());
                    });
                }
            }
        }
    };
}

#[cfg(test)]
macro_rules! many_blake {
    (
        $blake:ident => |mut $wolf:ident, mut $rc:ident $(, $sz:ident)?| $do:expr
    ) => {{
        many_blake! { $blake => |mut $wolf is 32, mut $rc is U32 $(, $sz)?| $do }
        many_blake! { $blake => |mut $wolf is 28, mut $rc is U28 $(, $sz)?| $do }
        many_blake! { $blake => |mut $wolf is 24, mut $rc is U24 $(, $sz)?| $do }
        many_blake! { $blake => |mut $wolf is 22, mut $rc is U22 $(, $sz)?| $do }
        many_blake! { $blake => |mut $wolf is 20, mut $rc is U20 $(, $sz)?| $do }
        many_blake! { $blake => |mut $wolf is 14, mut $rc is U14 $(, $sz)?| $do }
        many_blake! { $blake => |mut $wolf is 12, mut $rc is U12 $(, $sz)?| $do }
        many_blake! { $blake => |mut $wolf is 9, mut $rc is U9 $(, $sz)?| $do }
        many_blake! { $blake => |mut $wolf is 8, mut $rc is U8 $(, $sz)?| $do }
        many_blake! { $blake => |mut $wolf is 6, mut $rc is U6 $(, $sz)?| $do }
        many_blake! { $blake => |mut $wolf is 4, mut $rc is U4 $(, $sz)?| $do }
        many_blake! { $blake => |mut $wolf is 2, mut $rc is U2 $(, $sz)?| $do }
        many_blake! { $blake => |mut $wolf is 1, mut $rc is U1 $(, $sz)?| $do }
    }};
    (
        $blake:ident => |mut $wolf:ident is $sz:literal, mut $rc:ident is $rSz:ident $(, $gS:ident)?|
        $do:expr
    ) => {{
        $(let $gS = $sz;)?
        let mut $wolf = $blake::<{ $sz }>::new().unwrap();
        let mut $rc   = blake2::$blake::<::digest::consts::$rSz>::new();
        $do
    }}
}

#[cfg(test)]
pub struct KeyedVector {
    pub input: &'static [u8],
    pub key: &'static [u8],
    pub hash: &'static [u8]
}

#[cfg(test)]
macro_rules! ingest_blake_vectors {
    (
        $(
            in: $input:literal
            key: $key:literal
            hash: $output:literal
        )*
    ) => {
        &[
            $(
                $crate::hash::blake_api::KeyedVector {
                    input: &hex_literal::hex!($input),
                    key: &hex_literal::hex!($key),
                    hash: &hex_literal::hex!($output)
                }
            ),*
        ]
    };
    ($ident:ident => $($tt:tt)*) => {
        const $ident: &'static [$crate::hash::blake_api::KeyedVector] = ingest_blake_vectors!(
            $($tt)*
        );
    }
}