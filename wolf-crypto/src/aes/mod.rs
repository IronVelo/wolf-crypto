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
#![allow(dead_code)]
pub mod gcm;
pub mod ctr;

#[cfg(test)]
pub mod test_utils;

use wolf_crypto_sys::{
    Aes as AesLL,
    wc_AesInit,
    INVALID_DEVID, AES_ENCRYPTION, AES_DECRYPTION,
};

use crate::ptr::MutPtr;
use zeroize::Zeroize;
use core::ffi::c_int;

#[cfg_attr(test, derive(Debug, Clone, PartialEq))]
pub enum Key {
    Aes256([u8; 32]),
    Aes192([u8; 24]),
    Aes128([u8; 16])
}

impl Key {
    #[inline]
    pub const fn capacity(&self) -> usize {
        match self {
            Self::Aes256(_) => 32,
            Self::Aes192(_) => 24,
            Self::Aes128(_) => 16
        }
    }

    #[inline]
    pub const fn as_slice(&self) -> &[u8] {
        match self {
            Self::Aes256(buf) => buf.as_slice(),
            Self::Aes192(buf) => buf.as_slice(),
            Self::Aes128(buf) => buf.as_slice()
        }
    }

    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        match self {
            Self::Aes256(buf) => buf.as_mut_slice(),
            Self::Aes192(buf) => buf.as_mut_slice(),
            Self::Aes128(buf) => buf.as_mut_slice()
        }
    }

    #[inline]
    pub fn zero(&mut self) {
        self.as_mut_slice().zeroize();
    }
}

impl Drop for Key {
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
    pub const DECRYPT: Self = Self { mode: AES_DECRYPTION };

    #[inline]
    pub const fn mode(&self) -> core::ffi::c_uint {
        unsafe { core::mem::transmute_copy(self) }
    }
}

#[inline(always)]
#[cfg_attr(debug_assertions, must_use)]
pub(crate) unsafe fn init_aes_unchecked(aes: MutPtr<AesLL>) -> c_int {
    wc_AesInit(aes.get(), core::ptr::null_mut(), INVALID_DEVID)
}

#[inline]
pub(crate) unsafe fn init_aes(aes: MutPtr<AesLL>) {
    #[cfg(debug_assertions)] {
        assert_eq!(init_aes_unchecked(aes), 0);
    }
    #[cfg(not(debug_assertions))] {
        init_aes_unchecked(aes);
    }
}
