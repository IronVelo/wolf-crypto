//! State marker types and traits for the [`ChaCha20`] cipher.
//! 
//! [`ChaCha20`]: crate::chacha::ChaCha20

use crate::sealed::Sealed;

/// Represents the possible states that the [`ChaCha20`] cipher may be in.
/// 
/// [`ChaCha20`]: crate::chacha::ChaCha20
pub trait State: Sealed {}

/// Represents the states which **can** process (encrypt / decrypt) data.
pub trait CanProcess: State {}

define_state! {
    /// The ingress state for `ChaCha`, where the key is set and the instance is constructed.
    Init,
    /// The `ChaCha` instance requires a new initialization vector (IV).
    NeedsIv,
    /// The `ChaCha` instance is ready to perform encryption / decryption.
    Ready,
    /// The `ChaCha` instance is encrypting some stream of unknown length.
    Streaming
}

impl CanProcess for Ready {}
impl CanProcess for Streaming {}