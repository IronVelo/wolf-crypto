//! Defines the various states that a `Poly1305` instance can be in.
//!
//! These states ensure that the MAC computation follows the correct sequence of operations,
//! enhancing type safety and preventing misuse at compile time.
//!
//! # States
//!
//! - `Init`: The initial state before any operations have been performed.
//! - `Ready`: The state after initialization, ready to perform MAC computations.
//! - `Streaming`: The state during streaming updates of the MAC computation.

use crate::sealed::Sealed;

/// Represents the state of a `Poly1305` instance.
///
/// This trait is sealed and cannot be implemented outside of this crate.
pub trait Poly1305State : Sealed {}

/// Macro to generate state structs and implement necessary traits.
///
/// This macro simplifies the creation of new states by generating the struct and implementing the
/// `Sealed` and `Poly1305State` traits for it.
///
/// # Arguments
///
/// * `$(#[$meta:meta])*` - Optional attributes for the struct.
/// * `$vis:vis` - The visibility of the struct.
/// * `$ident:ident` - The identifier/name of the struct.
macro_rules! make_state {
    ($(#[$meta:meta])* $vis:vis $ident:ident) => {
        $(#[$meta])*
        $vis struct $ident;

        impl Sealed for $ident {}
        impl Poly1305State for $ident {}
    };
    ($(
        $(#[$meta:meta])*
        $vis:vis $ident:ident
    ),* $(,)?) => {
        $(
            make_state! {
                $(#[$meta])*
                $vis $ident
            }
        )*
    };
}

make_state! {
    /// The initial state of a `Poly1305` instance before any operations.
    pub Init,
    /// The ready state of a `Poly1305` instance after initialization.
    pub Ready,
    /// The streaming state of a `Poly1305` instance during updates.
    pub Streaming,
}