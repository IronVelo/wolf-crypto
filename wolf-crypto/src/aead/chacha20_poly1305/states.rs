use core::ffi::c_int;
use wolf_crypto_sys::{CHACHA20_POLY1305_AEAD_DECRYPT, CHACHA20_POLY1305_AEAD_ENCRYPT};
use crate::sealed::Sealed;

pub trait State: Sealed {}

define_state! {
    Init,
    EncryptMaybeAad,
    EncryptAad,
    Encrypt,
    DecryptMaybeAad,
    DecryptAad,
    Decrypt,
}

pub trait CanUpdate: State {
    type Mode: CanUpdate;
}
pub trait Updating: CanUpdate {
    type InitState: CanSetAad;

    #[doc(hidden)]
    #[must_use]
    fn direction() -> c_int;
}

pub trait CanUpdateAad: State {
    type Updating: UpdatingAad;
}
pub trait CanSetAad: CanUpdateAad + CanUpdate {
    type Mode: CanUpdate;
    type Updating: UpdatingAad;
}
pub trait UpdatingAad: CanUpdateAad {
    type Mode: CanUpdate;
}

// AAD permitted states
impl CanSetAad for EncryptMaybeAad {
    type Mode = Encrypt;
    type Updating = EncryptAad;
}
impl CanUpdateAad for EncryptMaybeAad {
    type Updating = EncryptAad;
}
impl CanUpdate for EncryptMaybeAad {
    type Mode = Encrypt;
}

impl CanUpdateAad for EncryptAad {
    type Updating = Self;
}
impl UpdatingAad for EncryptAad {
    type Mode = Encrypt;
}

// ---

impl CanUpdate for Encrypt {
    type Mode = Self;
}
impl Updating for Encrypt {
    type InitState = EncryptMaybeAad;

    #[inline(always)]
    #[doc(hidden)]
    fn direction() -> c_int {
        CHACHA20_POLY1305_AEAD_ENCRYPT as c_int
    }
}


// AAD permitted states
impl CanUpdate for DecryptMaybeAad {
    type Mode = Decrypt;
}
impl CanSetAad for DecryptMaybeAad {
    type Mode = Decrypt;
    type Updating = DecryptAad;
}
impl CanUpdateAad for DecryptMaybeAad {
    type Updating = DecryptAad;
}
impl CanUpdateAad for DecryptAad {
    type Updating = Self;
}
impl UpdatingAad for DecryptAad {
    type Mode = Decrypt;
}

// ---

impl CanUpdate for Decrypt {
    type Mode = Decrypt;
}
impl Updating for Decrypt {
    type InitState = DecryptMaybeAad;

    #[inline(always)]
    #[doc(hidden)]
    fn direction() -> c_int {
        CHACHA20_POLY1305_AEAD_DECRYPT as c_int
    }
}