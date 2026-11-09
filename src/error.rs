//! The error type: a code and a message.

use std::fmt;

use crate::diag::{self, Code, Severity};

/// A failure with its diagnostic code. Displays as `EF###_NAME: message`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    pub code: Code,
    pub msg: String,
}

impl Error {
    /// Builds an error without recording it.
    pub fn new(code: Code, msg: impl Into<String>) -> Self {
        Error { code, msg: msg.into() }
    }

    /// Builds an error and records it in the thread's sink at error level.
    pub fn recorded(code: Code, msg: impl Into<String>) -> Self {
        let msg = msg.into();
        diag::record(code, Severity::Error, msg.clone());
        Error { code, msg }
    }

    /// Builds an error and records it as a warning (the caller carries on).
    pub fn warned(code: Code, msg: impl Into<String>) -> Self {
        let msg = msg.into();
        diag::record(code, Severity::Warning, msg.clone());
        Error { code, msg }
    }

    /// Prefixes the message with where it happened.
    pub fn context(mut self, what: impl fmt::Display) -> Self {
        self.msg = format!("{what}: {}", self.msg);
        self
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.msg)
    }
}

impl std::error::Error for Error {}

/// The crate's result.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn displays_code_then_message() {
        let e = Error::new(crate::source::code::IMAGE_NOT_FOUND, "x.E01");
        assert_eq!(e.to_string(), "EF001_IMAGE_NOT_FOUND: x.E01");
        let e = e.context("opening");
        assert_eq!(e.to_string(), "EF001_IMAGE_NOT_FOUND: opening: x.E01");
    }

    #[test]
    fn recorded_goes_to_the_sink() {
        diag::set_quiet(true);
        diag::drain();
        let e = Error::recorded(crate::source::code::IMAGE_NOT_FOUND, "gone");
        let list = diag::drain();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].code, e.code);
        assert_eq!(list[0].severity, Severity::Error);
        let _ = Error::warned(crate::source::code::IMAGE_NOT_FOUND, "soft");
        assert_eq!(diag::drain()[0].severity, Severity::Warning);
    }
}
