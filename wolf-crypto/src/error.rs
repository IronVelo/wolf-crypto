use core::fmt;

/// A generic error type representing an unspecified failure in cryptographic operations.
///
/// In cryptographic contexts, it is often necessary to hide the specific reason for
/// an operation's failure to prevent leaking sensitive information to potential attackers.
/// `Unspecified` serves this purpose by providing a simple, non-descriptive error type
/// that can be used in situations where the cause of the failure should not be exposed.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Unspecified;

impl fmt::Display for Unspecified {
    /// Writes "Unspecified" to the formatter.
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("Unspecified")
    }
}

std! { impl std::error::Error for Unspecified {} }