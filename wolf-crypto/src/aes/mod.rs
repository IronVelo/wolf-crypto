//! Advanced Encryption Standard (AES)
// macro_rules! impl_aes_new {
//     ($self:ident, $lt:lifetime, $nl:lifetime, $nonce_ty:ty) => {
//         pub fn new(key: &$lt $crate::aes::Key, nonce: &$nl $nonce_ty) -> Result<$self, ()> {
//             let key_ptr = $crate::ptr::MutPtr::new(key as *const _ as *mut $crate::aes::Key);
//             let iv_ptr = $crate::ptr::MutPtr::new(nonce as *const _ as *mut u8);
//
//             unsafe {
//                 let mut aes: AesLL = core::mem::zeroed();
//                 let aes_ptr = $crate::ptr::MutPtr::new(core::ptr::addr_of_mut!(aes));
//                 $crate::aes::init_aes(aes_ptr, $self::MODE, key_ptr, iv_ptr)
//                     .unit_err($self::with_aes(aes))
//             }
//         }
//     };
// }

hidden! {
    pub mod ctr;
}

pub use { crate::aes::ctr::AesCtr };

#[cfg(test)]
pub mod test_utils;

use wolf_crypto_sys::{
    Aes as AesLL,
    wc_AesInit,
    INVALID_DEVID, AES_ENCRYPTION,
};

use zeroize::Zeroize;
use core::mem::MaybeUninit;
use crate::opaque_res::Res;

/// Represents different AES key sizes.
///
/// AES (Advanced Encryption Standard) supports three key sizes:
/// - 128-bit (16 bytes)
/// - 192-bit (24 bytes)
/// - 256-bit (32 bytes)
///
/// This enum allows for type-safe handling of these different key sizes.
#[cfg_attr(test, derive(Debug, Clone, PartialEq))]
pub enum Key {
    /// 256-bit AES key (32 bytes)
    Aes256([u8; 32]),
    /// 192-bit AES key (24 bytes)
    Aes192([u8; 24]),
    /// 128-bit AES key (16 bytes)
    Aes128([u8; 16])
}

impl Key {
    /// Returns the capacity (size in bytes) of the key.
    ///
    /// # Returns
    ///
    /// - `32` for Aes256
    /// - `24` for Aes192
    /// - `16` for Aes128
    #[inline]
    pub const fn capacity(&self) -> usize {
        match self {
            Self::Aes256(_) => 32,
            Self::Aes192(_) => 24,
            Self::Aes128(_) => 16
        }
    }

    /// Returns a reference to the key as a byte slice.
    #[inline]
    pub const fn as_slice(&self) -> &[u8] {
        match self {
            Self::Aes256(buf) => buf.as_slice(),
            Self::Aes192(buf) => buf.as_slice(),
            Self::Aes128(buf) => buf.as_slice()
        }
    }

    /// Returns a mutable reference to the key as a byte slice.
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        match self {
            Self::Aes256(buf) => buf.as_mut_slice(),
            Self::Aes192(buf) => buf.as_mut_slice(),
            Self::Aes128(buf) => buf.as_mut_slice()
        }
    }

    /// Zeros out the key for security purposes.
    ///
    /// This method uses the `zeroize` crate to ensure that the key material
    /// is securely erased from memory.
    ///
    /// This is called in the `Key` drop implementation.
    #[inline]
    pub fn zero(&mut self) {
        self.as_mut_slice().zeroize();
    }
}

impl Zeroize for Key {
    fn zeroize(&mut self) {
        self.zero();
    }
}

impl Drop for Key {
    /// Zeroes the underlying key material.
    fn drop(&mut self) {
        self.zero();
    }
}

impl From<[u8; 32]> for Key {
    #[inline]
    fn from(value: [u8; 32]) -> Self {
        Self::Aes256(value)
    }
}

impl From<[u8; 24]> for Key {
    #[inline]
    fn from(value: [u8; 24]) -> Self {
        Self::Aes192(value)
    }
}

impl From<[u8; 16]> for Key {
    #[inline]
    fn from(value: [u8; 16]) -> Self {
        Self::Aes128(value)
    }
}

#[repr(transparent)]
pub(crate) struct AesM {
    mode: core::ffi::c_uint
}

impl AesM {
    pub const ENCRYPT: Self = Self { mode: AES_ENCRYPTION };
    // pub const DECRYPT: Self = Self { mode: AES_DECRYPTION };

    #[inline]
    pub const fn mode(&self) -> core::ffi::c_uint {
        self.mode
    }
}

#[cfg_attr(not(debug_assertions), inline(always))]
pub(crate) unsafe fn init_aes(mut aes: MaybeUninit<AesLL>) -> (MaybeUninit<AesLL>, Res) {
    let mut res = Res::new();
    res.ensure_0(wc_AesInit(aes.as_mut_ptr(), core::ptr::null_mut(), INVALID_DEVID));
    (aes, res)
}