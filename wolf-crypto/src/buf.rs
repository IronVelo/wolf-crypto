//! Types for Keys, IVs, and Generally Sensitive Bytes
use zeroize::Zeroize;
use core::convert::TryFrom;
use crate::can_cast_u32;

macro_rules! make_buffer {
    (
        $(#[$meta:meta])*
        $ident:ident,
        sensitive: $sensitive:ident
    ) => {
        $(#[$meta])*
        pub enum $ident {
            B128([u8; 128]),
            B256([u8; 256]),
            B384([u8; 384]),
            B512([u8; 512])
        }

        #[allow(clippy::len_without_is_empty)]
        impl $ident {
            #[doc = concat!("Returns `", stringify!($sensitive),"`")]
            pub const fn is_sensitive(&self) -> bool {
                $sensitive
            }
            /// Checks if the buffer is the 128-byte variant.
            pub const fn is_128(&self) -> bool {
                matches!(self, Self::B128(_))
            }
            /// Checks if the buffer is the 256-byte variant.
            pub const fn is_256(&self) -> bool {
                matches!(self, Self::B256(_))
            }
            /// Checks if the buffer is the 384-byte variant.
            pub const fn is_384(&self) -> bool {
                matches!(self, Self::B384(_))
            }
            /// Checks if the buffer is the 512-byte variant.
            pub const fn is_512(&self) -> bool {
                matches!(self, Self::B512(_))
            }
            /// Returns the length of the buffer in bytes.
            #[inline]
            pub const fn len(&self) -> usize {
                match self {
                    Self::B128(_) => 128,
                    Self::B256(_) => 256,
                    Self::B512(_) => 512,
                    Self::B384(_) => 384
                }
            }
            /// Returns a reference to the buffer as a slice.
            #[inline]
            pub const fn as_slice(&self) -> &[u8] {
                match self {
                    Self::B128(buf) => buf.as_slice(),
                    Self::B256(buf) => buf.as_slice(),
                    Self::B512(buf) => buf.as_slice(),
                    Self::B384(buf) => buf.as_slice()
                }
            }
            /// Returns a mutable reference to the buffer as a slice.
            #[inline]
            pub fn as_mut_slice(&mut self) -> &mut [u8] {
                match self {
                    Self::B128(buf) => buf.as_mut_slice(),
                    Self::B256(buf) => buf.as_mut_slice(),
                    Self::B512(buf) => buf.as_mut_slice(),
                    Self::B384(buf) => buf.as_mut_slice()
                }
            }
        }

        impl ByteArray for $ident {
            type Target = Self;
            
            #[inline]
            fn capacity(&self) -> usize {
                self.len()
            }
            
            #[inline]
            fn slice(&self) -> &[u8] {
                self.as_slice()
            }
            #[inline]
            fn mut_slice(&mut self) -> &mut [u8] {
                self.as_mut_slice()
            }
        }

        make_buffer! { @drop $ident $sensitive }
    };

    (@drop $ident:ident true) => {
        impl Drop for $ident {
            /// Zeroes the buffer from memory
            fn drop(&mut self) {
                self.as_mut_slice().zeroize();
            }
        }
    };
    (@drop $ident:ident false) => {};
    (@drop $ident:ident $bad:ident) => {
        compile_error!(
            concat!(
                "Expected a boolean in the `sensitive` field, found: ",
                stringify!($bad)
            )
        )
    }
}

make_buffer! {
    #[derive(Copy, Clone, PartialEq, Eq)]
    Buf,
    sensitive: false
}

make_buffer! {
    #[derive(Clone)]
    SecretBuf,
    sensitive: true
}

/// A trait for types that represent initialization vector (IV) sizes.
///
/// This trait is sealed and can only be implemented within this crate.
pub trait IvSize : crate::sealed::Sealed {
    /// Returns the size of the IV in bytes.
    fn size() -> usize;

    /// Returns the size of the IV as a u32.
    ///
    /// # Panics
    ///
    /// In debug builds, this method will panic if the size is greater than `u32::MAX`.
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn size_32() -> u32 {
        debug_assert!(can_cast_u32(Self::size()), "IvSize `size` is too large.");
        Self::size() as u32
    }
}

macro_rules! make_iv_size {
    ($ident:ident = $size:literal) => {
        #[doc = concat!("Represents a `", stringify!($size), "` byte IV size.")]
        pub struct $ident;

        impl $ident {
            #[doc = concat!(
                "The size of the IV as a u32 constant (`", stringify!($size), "`)"
            )]
            pub const SIZE_U32: u32 = $size;
            #[doc = concat!(
                "The size of the IV as a usize constant (`", stringify!($size), "`)"
            )]
            pub const SIZE: usize = $size;
        }

        impl $crate::sealed::Sealed for $ident {}

        impl $crate::buf::IvSize for $ident {
            #[doc = concat!("Returns the size of the IV in bytes. (`", stringify!($size), "`)")]
            #[inline]
            fn size() -> usize {
                Self::SIZE
            }

            #[doc = concat!("Returns the size of the IV in bytes. (`", stringify!($size), "`)")]
            #[inline]
            fn size_32() -> u32 {
                Self::SIZE_U32
            }
        }
    };
}

make_iv_size! { U16 = 16 }
make_iv_size! { U12 = 12 }

/// A trait for types that can be used as generic initialization vectors.
pub trait GenericIv {
    /// The associated size type for this IV.
    type Size : IvSize;

    /// Returns a reference to the IV as a byte slice.
    fn as_slice(&self) -> &[u8];
}

/// An error type indicating an invalid size when converting to an IV type.
#[derive(Debug)]
pub struct InvalidSize;

macro_rules! def_nonce {
    ($ident:ident, $size:ident) => {
        #[doc = concat!("Represents an IV / Nonce with the size: [`", stringify!($size), "`].")]
        #[doc = ""]
        #[doc = concat!("[`", stringify!($size), "`]: crate::buf::", stringify!($size))]
        #[repr(transparent)]
        #[cfg_attr(test, derive(Debug))]
        pub struct $ident {
            inner: [u8; $size::SIZE]
        }

        impl $ident {
            /// The size type for this IV / Nonce.
            pub const SIZE: $size = $size;

            #[doc = "Creates a new nonce / IV"]
            pub const fn new(inner: [u8; $size::SIZE]) -> Self {
                Self { inner }
            }

            /// Returns a reference to the IV / Nonce as a slice.
            #[inline]
            pub const fn slice(&self) -> &[u8] {
                self.inner.as_slice()
            }

            /// Zeros out the contents of the IV / Nonce.
            #[inline]
            pub fn zero(&mut self) {
                self.inner.as_mut_slice().zeroize();
            }
            /// Creates a copy of the IV / Nonce.
            ///
            /// This type purposefully does not derive the `Copy` trait, to ensure that nonce / IV
            /// reuse is explicit.
            #[inline]
            #[must_use]
            pub const fn copy(&self) -> Self {
                Self::new(self.inner)
            }
        }

        impl GenericIv for $ident {
            type Size = $size;

            #[inline]
            fn as_slice(&self) -> &[u8] {
                self.inner.as_slice()
            }
        }

        impl From<[u8; $size::SIZE]> for $ident {
            fn from(value: [u8; $size::SIZE]) -> Self {
                Self::new(value)
            }
        }

        impl<'s> From<&'s [u8; $size::SIZE]> for $ident {
            fn from(value: &'s [u8; $size::SIZE]) -> Self {
                Self::new(*value)
            }
        }

        // NOTE: with #[repr(transparent)] TryFrom for [u8; C] is implicitly implemented.

        impl<'s> TryFrom<&'s [u8]> for $ident {
            type Error = InvalidSize;

            fn try_from(value: &'s [u8]) -> Result<Self, Self::Error> {
                match value.try_into() {
                    Ok(res) => Ok(Self::new(res)),
                    Err(_) => Err(InvalidSize)
                }
            }
        }

        #[cfg(test)]
        impl proptest::arbitrary::Arbitrary for $ident {
            type Parameters = ();

            fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
                use proptest::strategy::Strategy as _;
                proptest::arbitrary::any::<[u8; $size::SIZE]>().prop_map($ident::new).boxed()
            }

            type Strategy = proptest::prelude::BoxedStrategy<Self>;
        }
    };
}

def_nonce!(Nonce, U12);
def_nonce!(Nonce16, U16);
def_nonce!(Iv, U16);

impl<'r> GenericIv for &'r [u8; 12] {
    type Size = U12;

    #[inline]
    fn as_slice(&self) -> &[u8] {
        *self
    }
}

impl GenericIv for [u8; 12] {
    type Size = U12;

    #[inline]
    fn as_slice(&self) -> &[u8] {
        *&self
    }
}

impl<'r> GenericIv for &'r [u8; 16] {
    type Size = U16;

    #[inline]
    fn as_slice(&self) -> &[u8] {
        *self
    }
}

impl GenericIv for [u8; 16] {
    type Size = U16;

    #[inline]
    fn as_slice(&self) -> &[u8] {
        *&self
    }
}

/// A trait for types that represent byte arrays.
pub trait ByteArray {
    /// The target type of the byte array.
    type Target;

    /// Returns the readable capacity of the byte array.
    fn capacity(&self) -> usize;

    /// Returns a reference to the byte array as a slice.
    fn slice(&self) -> &[u8];
    /// Returns a mutable reference to the byte array as a slice.
    fn mut_slice(&mut self) -> &mut [u8];

    /// Zeros out the contents of the byte array.
    #[inline]
    fn zero(&mut self) {
        self.mut_slice().zeroize();
    }
}

impl<const N: usize> ByteArray for [u8; N] {
    type Target = Self;

    #[inline]
    fn capacity(&self) -> usize {
        N
    }

    #[inline]
    fn slice(&self) -> &[u8] {
        self.as_slice()
    }
    #[inline]
    fn mut_slice(&mut self) -> &mut [u8] {
        self.as_mut_slice()
    }
}

#[cfg(feature = "alloc")]
impl ByteArray for Vec<u8> {
    type Target = Self;

    #[inline]
    fn capacity(&self) -> usize {
        self.len()
    }

    #[inline]
    fn slice(&self) -> &[u8] {
        self.as_slice()
    }
    #[inline]
    fn mut_slice(&mut self) -> &mut [u8] {
        self.as_mut_slice()
    }
}
