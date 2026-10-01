//! The `BuilderTimeout` error: the port of the reference's `TimeoutError`
//! raised by every deadline and budget guard in the probe builders.
//!
//! The message text is the reference exception text; the arbiter surfaces
//! it verbatim in the verdict reason.

/// The reference `TimeoutError` analog for probe construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuilderTimeout(pub String);

impl std::fmt::Display for BuilderTimeout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for BuilderTimeout {}
