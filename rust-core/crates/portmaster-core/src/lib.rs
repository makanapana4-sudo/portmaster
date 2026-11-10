//! Platform-independent building blocks for the experimental Rust core.
//!
//! This crate does not intercept traffic, alter firewall rules, or communicate
//! with the Windows kernel driver. Those integrations require separate,
//! compatibility-tested milestones.

pub mod cache;
pub mod config;
pub mod connection;
pub mod dns_cache;
pub mod dns_coalescer;
pub mod dns_wire;
pub mod dns_query;
pub mod dns_resolver;
pub mod dns_service;
pub mod dns_upstream;
pub mod driver_info;
pub mod driver_protocol;
pub mod driver_stream;
pub mod driver_transport;
pub mod error;
pub mod event_queue;

pub use cache::{BoundedTtlCache, CacheConfigError};
pub use config::{ConfigError, CoreConfig, ResourceLimits};
pub use connection::{ConnectionKey, NetworkProtocol};
pub use dns_coalescer::{
    DnsCoalescerConfigError, DnsRequestCoalescer, DnsRequestGuard, DnsRequestStart,
};
pub use dns_cache::{
    DnsCache, DnsCacheConfigError, DnsCacheEntry, DnsCacheLookup, DnsCacheLookupKind,
    DnsCachePolicy, DnsQueryKey, DnsResponseMetadata, DnsWireCacheError, DNS_RCODE_NAME_ERROR,
    DNS_RCODE_REFUSED, DNS_RCODE_SUCCESS,
};
pub use dns_query::{build_dns_query, DnsQueryOptions};
pub use dns_resolver::{DnsResolveOptions, DnsResolveResult, DnsResolveSource, DnsResolver, DnsResolverError};
pub use dns_service::{DnsResolverService, DnsServiceError};
pub use dns_upstream::{DnsUpstreamClient, DnsUpstreamConfig, DnsUpstreamError};
pub use dns_wire::{
    parse_dns_message, rewrite_resource_record_ttls, validate_dns_response, DnsMessageMetadata,
    DnsQuestion, DnsWireError, DNS_HEADER_SIZE,
};
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
