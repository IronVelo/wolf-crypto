//! Key management for the `Poly1305` MAC.
//!
//! This defines the key structures, traits, and associated functionalities required
//! for securely managing and utilizing cryptographic keys.
//!
//! # Key Structures
//!
//! - `Key`: Represents a 32-byte secret key used for MAC computations.
//! - `KeyRef`: A reference to a `Key`, allowing for efficient key handling without ownership.
//!
//! # Traits
//!
//! - `GenericKey`: A sealed trait for generic key types, providing a method to access the key's
//!   byte pointer.

use core::array::TryFromSliceError;
use zeroize::Zeroize;
use crate::sealed::Sealed;

/// The size of the Poly1305 key in bytes.
pub const KEY_SIZE: usize = KEY_SIZE_U32 as usize;

/// The size of the Poly1305 key as a `u32`.
pub(crate) const KEY_SIZE_U32: u32 = 32;


/// A sealed trait for generic key types used in Poly1305.
///
/// This trait is sealed and cannot be implemented outside of this crate.
pub trait GenericKey : Sealed {
    #[doc(hidden)]
    fn ptr(&self) -> *const u8;
}

/// Represents a 32-byte secret key for `Poly1305` and `ChaCha20Poly1305`.
///
/// This struct ensures that the key material is securely managed and zeroed from memory when
/// dropped.
#[repr(transparent)]
#[derive(Clone)]
pub struct Key {
    inner: [u8; KEY_SIZE]
}

arb_key! { struct Key::new([u8; 32]) }

impl Key {
    /// Creates a new `Key` from a 32-byte array.
    ///
    /// # Arguments
    ///
    /// * `inner` - A 32-byte array containing the key material.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolf_crypto::mac::poly1305::Key;
    ///
    /// let key = Key::new([0u8; 32]);
    /// # drop(key);
    /// ```
    pub const fn new(inner: [u8; KEY_SIZE]) -> Self {
        Self { inner }
    }

    /// Returns a reference to the key as a `KeyRef`.
    ///
    /// # Returns
    ///
    /// * `KeyRef` - A reference to the key material.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolf_crypto::mac::poly1305::{Key, KeyRef};
    ///
    /// let key = Key::new([0u8; 32]);
    /// let key_ref: KeyRef = key.as_ref();
    /// # drop(key_ref); drop(key);
    /// ```
    pub const fn as_ref(&self) -> KeyRef {
        KeyRef::new(&self.inner)
    }
}

impl Zeroize for Key {
    /// Zeroes the key material in memory.
    ///
    /// This method securely erases the key from memory to prevent leakage.
    #[inline]
    fn zeroize(&mut self) {
        self.inner.zeroize()
    }
}

opaque_dbg! { Key }
impl Sealed for Key {}
impl GenericKey for Key {
    #[doc(hidden)]
    #[inline]
    fn ptr(&self) -> *const u8 {
        self.inner.as_ptr()
    }
}

impl From<[u8; KEY_SIZE]> for Key {
    /// Converts a 32-byte array into a `Key`.
    ///
    /// # Arguments
    ///
    /// * `value` - A 32-byte array containing the key material.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolf_crypto::mac::poly1305::Key;
    ///
    /// let key_bytes = [1u8; 32];
    /// let key: Key = key_bytes.into();
    /// # drop(key);
    /// ```
    #[inline]
    fn from(value: [u8; KEY_SIZE]) -> Self {
        Self::new(value, )
    }
}

impl Drop for Key {
    /// Drops the `Key`, ensuring that the key material is zeroed from memory.
    #[inline]
    fn drop(&mut self) {
        self.zeroize()
    }
}

/// A reference to a [`Key`], allowing for efficient key handling without ownership.
#[repr(transparent)]
pub struct KeyRef<'r> {
    inner: &'r [u8; KEY_SIZE]
}

impl<'r> KeyRef<'r> {
    /// Creates a new `KeyRef` from a reference to a 32-byte array.
    ///
    /// # Arguments
    ///
    /// * `inner` - A reference to a 32-byte array containing the key material.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolf_crypto::mac::poly1305::{Key, KeyRef};
    ///
    /// let key_bytes = [2u8; 32];
    /// let key = Key::new(key_bytes,);
    /// let key_ref: KeyRef = key.as_ref();
    /// # drop(key_ref); drop(key);
    /// ```
    pub const fn new(inner: &'r [u8; KEY_SIZE]) -> Self {
        Self { inner }
    }

    /// Creates a copy of the key as a [`Key`].
    ///
    /// # Returns
    ///
    /// A new [`Key`] instance containing the same key material.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolf_crypto::mac::poly1305::{Key, KeyRef};
    ///
    /// let key_ref: KeyRef = (&[7u8; 32]).into();
    /// let owned_key = key_ref.copy();
    /// # drop(key_ref); drop(owned_key);
    /// ```
    pub const fn copy(&self) -> Key {
        Key::new(*self.inner, )
    }
}

opaque_dbg! { KeyRef<'r> }

impl<'r> Sealed for KeyRef<'r> {}
impl<'r> GenericKey for KeyRef<'r> {
    #[doc(hidden)]
    #[inline]
    fn ptr(&self) -> *const u8 {
        self.inner.as_ptr()
    }
}

impl<'r> From<&'r [u8; KEY_SIZE]> for KeyRef<'r> {
    /// Converts a reference to a 32-byte array into a `KeyRef`.
    ///
    /// # Arguments
    ///
    /// * `value` - A reference to a 32-byte array containing the key material.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolf_crypto::mac::poly1305::{Key, KeyRef};
    ///
    /// let key_ref = KeyRef::from(&[2u8; 32]);
    /// # drop(key_ref);
    /// ```
    #[inline]
    fn from(value: &'r [u8; KEY_SIZE]) -> Self {
        Self::new(value)
    }
}

impl<'r> TryFrom<&'r [u8]> for KeyRef<'r> {
    type Error = TryFromSliceError;

    /// Attempts to convert a slice of bytes into a `KeyRef`.
    ///
    /// # Arguments
    ///
    /// * `value` - A slice of bytes to convert.
    ///
    /// # Errors
    ///
    /// Returns `TryFromSliceError` if the slice length is not exactly 32 bytes.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolf_crypto::mac::poly1305::KeyRef;
    ///
    /// let key_slice = &[5u8; 32];
    /// let key_ref = KeyRef::try_from(key_slice).unwrap();
    /// ```
    #[inline]
    fn try_from(value: &'r [u8]) -> Result<Self, Self::Error> {
        value.try_into().map(Self::new)
    }
}