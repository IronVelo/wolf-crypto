//! State marker types and traits for the `ChaCha20Poly1305` AEAD.
//!
//! This module defines the internal state machine for the `ChaCha20Poly1305` AEAD, using marker
//! types and traits to enforce correct usage at compile time. It ensures that methods are called in
//! the correct order and that the AEAD transitions through the appropriate states during encryption
//! or decryption operations.
use core::ffi::c_int;
use wolf_crypto_sys::{CHACHA20_POLY1305_AEAD_DECRYPT, CHACHA20_POLY1305_AEAD_ENCRYPT};
use crate::sealed::Sealed;

/// Represents the possible states that the [`ChaCha20Poly1305`] AEAD may be in.
///
/// [`ChaCha20Poly1305`]: crate::aead::ChaCha20Poly1305
pub trait State: Sealed {}

define_state! {
    /// Initial state of the `ChaCha20Poly1305` AEAD.
    Init,

    /// State where encryption can begin, with optional AAD.
    ///
    /// In this state, the cipher is ready to accept optional Additional Authenticated Data (AAD)
    /// before proceeding to encrypt data.
    EncryptMaybeAad,

    /// State for updating the AAD during encryption.
    ///
    /// In this state, the cipher is in the process of accepting AAD for authentication during
    /// encryption. Multiple AAD updates can be performed.
    EncryptAad,

    /// State where encryption of data can occur.
    ///
    /// In this state, the cipher can encrypt data and update the authentication tag accordingly.
    Encrypt,

    /// State where decryption can begin, with optional AAD.
    ///
    /// In this state, the cipher is ready to accept optional Additional Authenticated Data (AAD)
    /// before proceeding to decrypt data.
    DecryptMaybeAad,

    /// State for updating the AAD during decryption.
    ///
    /// In this state, the cipher is in the process of accepting AAD for authentication during
    /// decryption. Multiple AAD updates can be performed.
    DecryptAad,

    /// State where decryption of data can occur.
    ///
    /// In this state, the cipher can decrypt data and update the authentication tag accordingly.
    Decrypt,
}

/// Indicates that the cipher can process data in its current state.
pub trait CanUpdate: State {
    /// The mode (encryption or decryption) associated with this state.
    type Mode: Updating;
}

/// Defines the behavior for states that can perform the main AEAD operations.
pub trait Updating: CanUpdate {
    /// The initial state type when starting the AEAD operation.
    type InitState: CanSetAad;

    #[doc(hidden)]
    #[must_use]
    /// Returns the direction (encrypt or decrypt) for the AEAD operation.
    fn direction() -> c_int;
}

/// Indicates that the cipher can update Additional Authenticated Data (AAD) in its current state.
pub trait CanUpdateAad: State {
    /// The mode (encryption or decryption) associated with this state.
    type Updating: UpdatingAad;
}

/// Indicates that the cipher can either set AAD or proceed to data processing.
pub trait CanSetAad: CanUpdateAad + CanUpdate {
    /// The mode (encryption or decryption) associated with this state.
    type Mode: Updating;
    /// The associated state for streaming AAD updates.
    type Updating: UpdatingAad;
}

/// Defines the behavior for states that are actively updating AAD.
pub trait UpdatingAad: CanUpdateAad {
    /// The mode (encryption or decryption) associated with this state. 
    type Mode: Updating;
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
impl<S: UpdatingAad> CanUpdate for S {
    type Mode = S::Mode;
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
    type Mode = Self;
}
impl Updating for Decrypt {
    type InitState = DecryptMaybeAad;

    #[inline(always)]
    #[doc(hidden)]
    fn direction() -> c_int {
        CHACHA20_POLY1305_AEAD_DECRYPT as c_int
    }
}