use crate::sealed::Sealed;

pub trait State: Sealed {}
pub trait CanProcess: State {}

define_state! {
    /// The ingress state for `ChaCha`, where the key is set and the instance is constructed.
    Init,
    /// The `ChaCha` instance requires a new initialization vector (IV)
    NeedsIv,
    /// The `ChaCha` instance is ready to perform encryption / decryption
    Ready,
    /// The `ChaCha` instance is encrypting some stream of unknown length
    Streaming
}

impl CanProcess for Ready {}
impl CanProcess for Streaming {}