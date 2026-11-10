//! Platform-independent building blocks for the experimental Rust core.
//!
//! This crate does not intercept traffic, alter firewall rules, or communicate
//! with the Windows kernel driver. Those integrations require separate,
//! compatibility-tested milestones.

pub mod cache;
pub mod config;
pub mod connection;
pub mod driver_protocol;
pub mod error;
pub mod event_queue;

pub use cache::{BoundedTtlCache, CacheConfigError};
pub use config::{ConfigError, CoreConfig, ResourceLimits};
pub use connection::{ConnectionKey, NetworkProtocol};
pub use driver_protocol::{
    parse_info_frame, DriverCommand, InfoFrame, InfoKind, ProtocolError, DEFAULT_MAX_INFO_PAYLOAD,
};
pub use error::CoreError;
pub use event_queue::{bounded_event_queue, QueueConfigError};
