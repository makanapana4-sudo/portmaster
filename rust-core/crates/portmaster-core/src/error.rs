use std::fmt;

/// Errors produced by the experimental Rust core.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoreError {
    InvalidConfiguration(String),
    InvalidConnection(String),
    ResourceLimitExceeded(&'static str),
}

impl fmt::Display for CoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration(message) => {
                write!(formatter, "invalid configuration: {message}")
            }
            Self::InvalidConnection(message) => {
                write!(formatter, "invalid connection: {message}")
            }
            Self::ResourceLimitExceeded(resource) => {
                write!(formatter, "resource limit exceeded: {resource}")
            }
        }
    }
}

impl std::error::Error for CoreError {}
