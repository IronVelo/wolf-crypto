use crate::sealed::Sealed;

pub trait State: Sealed {}
pub trait CanProcess: State {}

macro_rules! define_state {
    (
        $(#[$meta:meta])*
        $name:ident
    ) => {
        $(#[$meta])*
        pub struct $name;

        impl Sealed for $name {}
        impl State for $name {}
    };

    ($(
        $(#[$meta:meta])*
        $name:ident
    ),* $(,)?) => {
        $(
            define_state! {
                $(#[$meta])*
                $name
            }
        )*
    };
}

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