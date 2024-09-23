use core::fmt;

/// Represents the authentication tag for AEADs
#[must_use = "You must use the tag, or GCM is doing nothing for you"]
#[derive(Copy, Clone)]
#[repr(transparent)]
pub struct Tag {
    inner: [u8; 16],
}

impl fmt::Debug for Tag {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_fmt(format_args!("Tag({:?})", &self.inner))
    }
}

impl Tag {
    /// The size of the authentication tag in bytes.
    pub const CAPACITY: usize = 16;
    pub(crate) const SIZE: u32 = 16;

    /// Creates a new `Tag` instance from a 16-byte array.
    ///
    /// # Arguments
    ///
    /// * `inner` - A 16-byte array containing the authentication tag.
    ///
    /// # Returns
    ///
    /// A new `Tag` instance.
    pub const fn new(inner: [u8; Self::CAPACITY]) -> Self {
        Self { inner }
    }

    /// Creates a new `Tag` instance filled with zeros.
    ///
    /// This is typically used to create a tag buffer that will be filled
    /// by an encryption operation.
    ///
    /// # Returns
    ///
    /// A new `Tag` instance with all bytes set to zero.
    ///
    /// # Example
    ///
    /// ```
    /// use wolf_crypto::aes::gcm::Tag;
    ///
    /// let tag = Tag::new_zeroed();
    /// assert_eq!(tag.as_slice(), &[0u8; 16]);
    /// ```
    pub const fn new_zeroed() -> Self {
        Self::new([0u8; Self::CAPACITY])
    }

    /// Consumes the `Tag` and returns the underlying 16-byte array.
    #[inline]
    pub const fn take(self) -> [u8; Self::CAPACITY] {
        self.inner
    }

    /// Returns a reference to the tag as a byte slice.
    pub const fn as_slice(&self) -> &[u8] {
        self.inner.as_slice()
    }

    #[inline]
    pub(crate) fn as_mut_ptr(&mut self) -> *mut u8 {
        self.inner.as_mut_ptr()
    }

    #[inline]
    pub(crate) const fn as_ptr(&self) -> *const u8 {
        self.inner.as_ptr()
    }
}

impl PartialEq for Tag {
    /// Constant Time Equivalence
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        // wolfcrypt (or just with my current config) does not expose the `misc` module
        // utilities. This function is only ensuring both pointers are valid, and then uses the
        // `misc` module's ConstantCompare on the two tags. So this will work for all tags, and
        // allows us not to depend on a crate like subtle.
        use wolf_crypto_sys::wc_ChaCha20Poly1305_CheckTag;
        unsafe { wc_ChaCha20Poly1305_CheckTag(self.as_ptr(), other.as_ptr()) == 0 }
    }
}