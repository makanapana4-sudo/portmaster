//! Platform-independent building blocks for the experimental Rust core.
//!
//! This crate does not intercept traffic, alter firewall rules, or communicate
//! with the Windows kernel driver. Those integrations require separate,
//! compatibility-tested milestones.

pub mod cache;
pub mod config;
pub mod connection;
pub mod driver_info;
pub mod driver_protocol;
pub mod driver_stream;
pub mod driver_transport;
pub mod error;
pub mod event_queue;

pub use cache::{BoundedTtlCache, CacheConfigError};
pub use config::{ConfigError, CoreConfig, ResourceLimits};
pub use connection::{ConnectionKey, NetworkProtocol};
pub use driver_info::{
    parse_driver_info, parse_driver_info_frame, BandwidthStatsV4, BandwidthStatsV6,
    BandwidthValueV4, BandwidthValueV6, ConnectionEndV4, ConnectionEndV6, ConnectionInfoV4,
    ConnectionInfoV6, DriverInfo,
};
pub use driver_protocol::{
    parse_info_frame, CommandEncodeError, DriverCommand, InfoFrame, InfoKind, ProtocolError,
    DEFAULT_MAX_INFO_PAYLOAD,
};
pub use driver_stream::DriverInfoStream;
pub use driver_transport::{DriverReadOutcome, DriverTransport, DriverTransportError, DRIVER_READ_BUFFER_SIZE};
pub use error::CoreError;
pub use event_queue::{bounded_event_queue, QueueConfigError};
