//! Types for Keys, IVs, and Generally Sensitive Bytes
use zeroize::Zeroize;
use core::convert::TryFrom;

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

        impl $ident {
            pub const fn is_sensitive(&self) -> bool {
                $sensitive
            }
            pub const fn is_128(&self) -> bool {
                matches!(self, Self::B128(_))
            }
            pub const fn is_256(&self) -> bool {
                matches!(self, Self::B256(_))
            }
            pub const fn is_384(&self) -> bool {
                matches!(self, Self::B384(_))
            }
            pub const fn is_512(&self) -> bool {
                matches!(self, Self::B512(_))
            }
            
            #[inline]
            pub const fn len(&self) -> usize {
                match self {
                    Self::B128(_) => 128,
                    Self::B256(_) => 256,
                    Self::B512(_) => 512,
                    Self::B384(_) => 384
                }
            }
            
            #[inline]
            pub const fn as_slice(&self) -> &[u8] {
                match self {
                    Self::B128(buf) => buf.as_slice(),
                    Self::B256(buf) => buf.as_slice(),
                    Self::B512(buf) => buf.as_slice(),
                    Self::B384(buf) => buf.as_slice()
                }
            }
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
    #[derive(Copy, Clone, PartialEq)]
    Buf,
    sensitive: false
}

make_buffer! {
    #[derive(Clone)]
    SecretBuf,
    sensitive: true
}

pub trait IvSize : crate::sealed::Sealed {
    fn size() -> usize;

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn size_32() -> u32 {
        debug_assert!(Self::size() <= (u32::MAX as usize), "IvSize `size` is too large.");
        Self::size() as u32
    }
}

macro_rules! make_iv_size {
    ($ident:ident = $size:literal) => {
        pub struct $ident;

        impl $ident {
            pub const SIZE_U32: u32 = $size;
            pub const SIZE: usize = $size;
        }

        impl $crate::sealed::Sealed for $ident {}

        impl $crate::buf::IvSize for $ident {
            #[inline]
            fn size() -> usize {
                Self::SIZE
            }

            #[inline]
            fn size_32() -> u32 {
                Self::SIZE_U32
            }
        }
    };
}

make_iv_size! { U16 = 16 }
make_iv_size! { U12 = 12 }

pub trait GenericIv {
    type Size : IvSize;

    fn as_slice(&self) -> &[u8];
}

#[derive(Debug)]
pub struct InvalidSize;

macro_rules! def_nonce {
    ($ident:ident, $size:ident) => {
        #[repr(transparent)]
        #[cfg_attr(test, derive(Debug))]
        pub struct $ident {
            inner: [u8; $size::SIZE]
        }

        impl $ident {
            pub const SIZE: $size = $size;

            pub const fn new(inner: [u8; $size::SIZE]) -> Self {
                Self { inner }
            }

            #[inline]
            pub const fn slice(&self) -> &[u8] {
                self.inner.as_slice()
            }

            #[inline]
            pub fn zero(&mut self) {
                self.inner.as_mut_slice().zeroize();
            }

            #[inline]
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

pub trait ByteArray {
    type Target;

    fn capacity(&self) -> usize;

    fn slice(&self) -> &[u8];
    fn mut_slice(&mut self) -> &mut [u8];

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
