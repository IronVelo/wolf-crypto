use crate::sealed::Sealed;
use zeroize::Zeroize;
use core::fmt;

pub trait GenericKey : Sealed {
    fn slice(&self) -> &[u8];
    fn size(&self) -> u32;
}

macro_rules! basic_key_api {
    ($ident:ident $($lt:lifetime)?) => {
        impl $(<$lt>)? $ident $(<$lt>)? {
            #[inline]
            pub const fn new_128(key: $(&$lt)? [u8; 16]) -> Self {
                Self::B128(key)
            }

            #[inline]
            pub const fn new_256(key: $(&$lt)? [u8; 32]) -> Self {
                Self::B256(key)
            }

            #[inline]
            pub const fn len(&self) -> u32 {
                match self {
                    Self::B256(_) => 32,
                    Self::B128(_) => 16
                }
            }

            #[doc = " Returns a friendly identifier for the key."]
            #[doc = ""]
            #[doc = " # Returns"]
            #[doc = ""]
            #[doc = concat!(" - `256` bit key: `\"", stringify!($ident), "::256\"`")]
            #[doc = concat!(" - `128` bit key: `\"", stringify!($ident), "::128\"`")]
            pub const fn ident(&self) -> &'static str {
                match self {
                    Self::B256(_) => concat!(stringify!($ident), "::256"),
                    Self::B128(_) => concat!(stringify!($ident), "::128"),
                }
            }

            #[inline]
            pub const fn as_slice(&self) -> &[u8] {
                match self {
                    Self::B256(array) => array.as_slice(),
                    Self::B128(array) => array.as_slice()
                }
            }
        }

        impl $(<$lt>)? fmt::Debug for $ident $(<$lt>)? {
            #[doc = "This writes the following to the `Formatter` (depending on the variant): "]
            #[doc = ""]
            #[doc = concat!(" - `256` bit key: `\"", stringify!($ident), "::256\"`")]
            #[doc = concat!(" - `128` bit key: `\"", stringify!($ident), "::128\"`")]
            #[inline]
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str(self.ident())
            }
        }

        impl $(<$lt>)? fmt::Display for $ident $(<$lt>)? {
            #[doc = "This writes the following to the `Formatter` (depending on the variant): "]
            #[doc = ""]
            #[doc = concat!(" - `256` bit key: `\"", stringify!($ident), "::256\"`")]
            #[doc = concat!(" - `128` bit key: `\"", stringify!($ident), "::128\"`")]
            #[inline]
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str(self.ident())
            }
        }

        impl $(<$lt>)? Sealed for $ident $(<$lt>)? {}

        impl $(<$lt>)? GenericKey for $ident $(<$lt>)? {
            #[inline]
            fn slice(&self) -> &[u8] {
                self.as_slice()
            }
            #[inline]
            fn size(&self) -> u32 {
                self.len()
            }
        }
    };
}

#[must_use]
pub enum Key {
    B128([u8; 16]),
    B256([u8; 32])
}

basic_key_api! { Key }

impl Key {
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        match self {
            Self::B256(array) => array.as_mut_slice(),
            Self::B128(array) => array.as_mut_slice()
        }
    }

    #[inline]
    pub const fn as_ref(&self) -> KeyRef {
        match self {
            Self::B128(raw) => KeyRef::B128(raw),
            Self::B256(raw) => KeyRef::B256(raw)
        }
    }
}

impl Zeroize for Key {
    #[inline]
    fn zeroize(&mut self) {
        self.as_mut_slice().zeroize()
    }
}

impl Drop for Key {
    #[inline]
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl From<[u8; 16]> for Key {
    #[inline]
    fn from(value: [u8; 16]) -> Self {
        Self::B128(value)
    }
}

impl From<[u8; 32]> for Key {
    #[inline]
    fn from(value: [u8; 32]) -> Self {
        Self::B256(value)
    }
}

#[must_use]
pub enum KeyRef<'r> {
    B128(&'r [u8; 16]),
    B256(&'r [u8; 32])
}

impl<'r> KeyRef<'r> {
    #[inline]
    pub const fn copy(&self) -> Key {
        match *self {
            Self::B128(raw) => Key::B128(*raw),
            Self::B256(raw) => Key::B256(*raw)
        }
    }
}

basic_key_api! { KeyRef 'r }

impl<'r> From<&'r [u8; 16]> for KeyRef<'r> {
    #[inline]
    fn from(value: &'r [u8; 16]) -> Self {
        Self::B128(value)
    }
}

impl<'r> From<&'r [u8; 32]> for KeyRef<'r> {
    #[inline]
    fn from(value: &'r [u8; 32]) -> Self {
        Self::B256(value)
    }
}

impl<'kr> Sealed for &'kr [u8; 16] {}

impl<'kr> GenericKey for &'kr [u8; 16] {
    #[inline]
    fn slice(&self) -> &[u8] {
        self.as_slice()
    }
    #[inline]
    fn size(&self) -> u32 {
        16
    }
}

impl<'kr> Sealed for &'kr [u8; 32] {}
impl<'kr> GenericKey for &'kr [u8; 32] {
    #[inline]
    fn slice(&self) -> &[u8] {
        self.as_slice()
    }
    #[inline]
    fn size(&self) -> u32 {
        32
    }
}