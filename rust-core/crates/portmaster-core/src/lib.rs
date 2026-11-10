//! Platform-independent building blocks for the experimental Rust core.
//!
//! This crate does not intercept traffic, alter firewall rules, or communicate
//! with the Windows kernel driver. Those integrations require separate,
//! compatibility-tested milestones.

pub mod config;
pub mod connection;
pub mod error;

pub use config::{CoreConfig, ConfigError, ResourceLimits};
pub use connection::{ConnectionKey, NetworkProtocol};
pub use error::CoreError;
