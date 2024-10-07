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
no_std_io! {
    impl embedded_io::Error for Unspecified {
        fn kind(&self) -> embedded_io::ErrorKind {
            embedded_io::ErrorKind::Other
        }
    }
}

/// Trait for transforming a `Result<T, E>` into a `Result<T, Unspecified>`.
///
/// This trait is useful in contexts where you want to prevent specific error details from being
/// exposed, such as in cryptographic operations or security-critical code paths, where leaking
/// error information could aid in side-channel attacks.
///
/// # Examples
///
/// ```
/// use wolf_crypto::{Unspecified, MakeOpaque};
///
/// let success: Result<u32, &str> = Ok(42);
/// let result = success.opaque();
/// assert_eq!(result, Ok(42));
///
/// let failure: Result<u32, &str> = Err("error");
/// let result = failure.opaque();
/// assert_eq!(result, Err(Unspecified));
/// ```
///
/// **Bind Combinator**
/// ```
/// use wolf_crypto::{Unspecified, MakeOpaque};
///
/// let failure = Ok::<usize, ()>(7)
///     .opaque_bind(|not_seven| if not_seven == 7 {
///         Err("Did not expect 7")
///     } else {
///         Ok(not_seven)
///     });
/// assert_eq!(failure, Err(Unspecified));
///
/// let ok = Ok::<usize, ()>(42)
///     .opaque_bind(|res| if res == 42 {
///         Ok("meaning of life")
///     } else {
///         Err("Expected the meaning of life")
///     });
/// assert_eq!(ok, Ok("meaning of life"));
/// ```
///
/// **Map Combinator**
/// ```
/// use wolf_crypto::{Unspecified, MakeOpaque};
///
/// assert_eq!(
///     Err::<usize, usize>(7).opaque_map(|num| num * 6),
///     Err(Unspecified)
/// );
/// assert_eq!(
///     Ok::<usize, usize>(7).opaque_map(|num| num * 6),
///     Ok(42)
/// );
/// ```
#[allow(clippy::missing_errors_doc)]
pub trait MakeOpaque<T> {
    /// Transforms the `Result<T, E>` into a `Result<T, Unspecified>`.
    ///
    /// If the original `Result` was `Ok(T)`, it remains unchanged. However, if it was `Err(E)`,
    /// the error is transformed into a generic `Unspecified` error, hiding the underlying cause.
    ///
    /// # Example
    ///
    /// ```
    /// # use wolf_crypto::{MakeOpaque, Unspecified};
    /// let success: Result<u32, &str> = Ok(42);
    /// let result = success.opaque();
    /// assert_eq!(result, Ok(42));
    ///
    /// let failure: Result<u32, &str> = Err("error");
    /// let result = failure.opaque();
    /// assert_eq!(result, Err(Unspecified));
    /// ```
    fn opaque(self) -> Result<T, Unspecified>;

    /// Calls `op` if the result is [`Ok`], converting all errors to the [`Unspecified`] type.
    ///
    /// This method is similar to Rust's [`and_then`] and Haskell's `bind`, though it does not
    /// require the closure to have the same error type due to it transforming all errors to the
    /// [`Unspecified`] type.
    ///
    /// This function can be used for control flow based on `Result` values.
    ///
    /// # Example
    ///
    /// ```
    /// # use wolf_crypto::{MakeOpaque, Unspecified};
    /// let success: Result<u32, &str> = Ok(7);
    /// let result = success.opaque_bind(|v| v.checked_mul(6).ok_or(()));
    /// assert_eq!(result, Ok(42));
    ///
    /// let failure: Result<u32, &str> = Err("error");
    /// let result = failure.opaque_bind(|v| v.checked_mul(6).ok_or(()));
    /// assert_eq!(result, Err(Unspecified));
    /// ```
    ///
    /// [`and_then`]: Result::and_then
    fn opaque_bind<F: FnOnce(T) -> Result<N, NE>, N, NE>(self, op: F) -> Result<N, Unspecified>;

    /// Maps a `Result<T, E>` to `Result<U, Unspecified>` by applying a function to a
    /// contained [`Ok`] value, and replacing the error with [`Unspecified`].
    ///
    /// This function can be used to compose the results of two functions.
    ///
    /// # Examples
    ///
    /// ```
    /// # use wolf_crypto::{MakeOpaque, Unspecified};
    /// let success: Result<u32, &str> = Ok(42);
    /// let result = success.opaque_map(|v| v + 1);
    /// assert_eq!(result, Ok(43));
    ///
    /// let failure: Result<u32, &str> = Err("error");
    /// let result = failure.opaque_map(|v| v + 1);
    /// assert_eq!(result, Err(Unspecified));
    /// ```
    fn opaque_map<F: FnOnce(T) -> N, N>(self, op: F) -> Result<N, Unspecified>;
}

#[allow(clippy::option_if_let_else)]
impl<T, E> MakeOpaque<T> for Result<T, E> {
    #[inline]
    fn opaque(self) -> Result<T, Unspecified> {
        match self {
            Ok(ok) => Ok(ok),
            Err(_) => Err(Unspecified)
        }
    }

    #[inline]
    fn opaque_bind<F: FnOnce(T) -> Result<N, NE>, N, NE>(self, op: F) -> Result<N, Unspecified> {
        match self {
            Ok(ok) => op(ok).opaque(),
            Err(_) => Err(Unspecified)
        }
    }

    #[inline]
    fn opaque_map<F: FnOnce(T) -> N, N>(self, op: F) -> Result<N, Unspecified> {
        match self {
            Ok(ok) => Ok(op(ok)),
            Err(_) => Err(Unspecified)
        }
    }
}