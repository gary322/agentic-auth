use std::fmt;

/// A wrapper that prevents secrets from being accidentally logged via `Debug` / `Display`.
///
/// Always keep the underlying value private to the component that must use it.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Sensitive<T>(pub T);

impl<T> Sensitive<T> {
    pub fn expose(&self) -> &T {
        &self.0
    }

    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> fmt::Debug for Sensitive<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl<T> fmt::Display for Sensitive<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts() {
        let s = Sensitive("secret-token-123".to_string());
        let out = format!("{s:?}");
        assert!(!out.contains("secret-token-123"));
        assert!(out.contains("REDACTED"));
    }
}
