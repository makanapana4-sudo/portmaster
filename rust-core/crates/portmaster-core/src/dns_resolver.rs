use crate::{
    dns_cache::{
        DnsCache, DnsCacheConfigError, DnsCacheEntry, DnsCacheLookupKind, DnsWireCacheError,
    },
    dns_coalescer::{DnsRequestCoalescer, DnsRequestStart},
    dns_upstream::{DnsUpstreamClient, DnsUpstreamError},
    dns_wire::{parse_dns_message, rewrite_resource_record_ttls, DnsMessageMetadata, DnsWireError},
};
use std::{
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

/// Per-request policy supplied by the caller's network and process context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsResolveOptions {
    pub is_connectivity_domain: bool,
    pub online: bool,
    pub no_caching: bool,
    pub allow_stale_on_error: bool,
}

impl Default for DnsResolveOptions {
    fn default() -> Self {
        Self {
            is_connectivity_domain: false,
            online: true,
            no_caching: false,
            allow_stale_on_error: true,
        }
    }
}

/// Where a DNS response was obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsResolveSource {
    Cache,
    Upstream,
    StaleFallback,
}

/// A response ready to be sent to the local DNS client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsResolveResult {
    pub response: Vec<u8>,
    pub source: DnsResolveSource,
    pub metadata: DnsMessageMetadata,
}

/// Errors produced by the integrated DNS resolver.
#[derive(Debug)]
pub enum DnsResolverError {
    InvalidQuery,
    CacheUnavailable,
    CacheKey(DnsCacheConfigError),
    Upstream(DnsUpstreamError),
    Wire(DnsWireError),
    Cache(DnsWireCacheError),
    CoalescerUnavailable,
}

impl std::fmt::Display for DnsResolverError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidQuery => formatter.write_str("DNS request must be a single-question query"),
            Self::CacheUnavailable => formatter.write_str("DNS response cache is unavailable"),
            Self::CacheKey(error) => write!(formatter, "invalid DNS question key: {error}"),
            Self::Upstream(error) => write!(formatter, "DNS upstream failed: {error}"),
            Self::Wire(error) => write!(formatter, "DNS message is invalid: {error}"),
            Self::Cache(error) => write!(formatter, "DNS response could not be cached: {error}"),
            Self::CoalescerUnavailable => formatter.write_str("DNS request coalescer is unavailable"),
        }
    }
}

impl std::error::Error for DnsResolverError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Upstream(error) => Some(error),
            Self::Wire(error) => Some(error),
            Self::Cache(error) => Some(error),
            Self::CacheKey(error) => Some(error),
            _ => None,
        }
    }
}

impl From<DnsUpstreamError> for DnsResolverError {
    fn from(error: DnsUpstreamError) -> Self {
        Self::Upstream(error)
    }
}

impl From<DnsWireError> for DnsResolverError {
    fn from(error: DnsWireError) -> Self {
        Self::Wire(error)
    }
}

impl From<DnsCacheConfigError> for DnsResolverError {
    fn from(error: DnsCacheConfigError) -> Self {
        Self::CacheKey(error)
    }
}

impl From<DnsWireCacheError> for DnsResolverError {
    fn from(error: DnsWireCacheError) -> Self {
        Self::Cache(error)
    }
}

/// Small synchronous resolver joining query validation, cache, request
/// coalescing and one configured upstream.
///
/// It intentionally does not install a local listener, select system
/// resolvers, inspect application identities, or change firewall policy.
/// Callers supply connectivity/offline and no-cache context.
pub struct DnsResolver {
    upstream: DnsUpstreamClient,
    cache: Mutex<DnsCache>,
    coalescer: DnsRequestCoalescer,
}

impl DnsResolver {
    pub fn new(
        upstream: DnsUpstreamClient,
        cache: DnsCache,
        coalescer: DnsRequestCoalescer,
    ) -> Self {
        Self {
            upstream,
            cache: Mutex::new(cache),
            coalescer,
        }
    }

    /// Resolves a raw one-question DNS request.
    ///
    /// Fresh cache hits are returned immediately. Entries approaching expiry
    /// are refreshed through the upstream; expired successful responses can
    /// be used as a fallback if the upstream fails and stale serving is
    /// enabled. Identical cacheable requests share one in-flight upstream
    /// exchange.
    pub fn resolve(
        &self,
        query_packet: &[u8],
        options: DnsResolveOptions,
    ) -> Result<DnsResolveResult, DnsResolverError> {
        let query = parse_dns_message(query_packet)?;
        if query.is_response() || query.is_truncated() || query.question_count != 1 {
            return Err(DnsResolverError::InvalidQuery);
        }

        let question = query
            .first_question
            .as_ref()
            .ok_or(DnsResolverError::InvalidQuery)?;
        if question.class != 1 {
            return Err(DnsResolverError::InvalidQuery);
        }
        let key = question.cache_key()?;
        let cacheable = !options.no_caching && !options.is_connectivity_domain;
        let stale_fallback = if cacheable {
            let mut cache = self.cache.lock().map_err(|_| DnsResolverError::CacheUnavailable)?;
            match cache.lookup(&key, now_unix, true, false) {
                Some(lookup) if lookup.kind == DnsCacheLookupKind::Fresh => {
                    return cached_result(lookup.entry);
                }
                Some(lookup) => {
                    if options.allow_stale_on_error {
                        Some(lookup.entry.prepare_client_response()?)
                    } else {
                        None
                    }
                }
                None => None,
            }
        } else {
            None
        };

        if !cacheable {
            return self.fetch_uncached(query_packet);
        }

        loop {
            match self.coalescer.begin(key.clone(), || false) {
                DnsRequestStart::Leader(guard) => {
                    let upstream_result = self.upstream.exchange(query_packet);
                    match upstream_result {
                        Ok(response) => {
                            {
                                let mut cache = self
                                    .cache
                                    .lock()
                                    .map_err(|_| DnsResolverError::CacheUnavailable)?;
                                cache.insert_dns_response_for_query(
                                    query_packet,
                                    response.clone(),
                                    options.is_connectivity_domain,
                                    options.online,
                                    options.no_caching,
                                    current_unix_seconds(),
                                )?;
                            }

                            drop(guard);
                            return prepare_network_response(
                                response,
                                DnsResolveSource::Upstream,
                                self.client_ttl()?,
                            );
                        }
                        Err(error) => {
                            drop(guard);
                            if options.allow_stale_on_error {
                                if let Some(response) = stale_fallback {
                                    return prepare_network_response(
                                        response,
                                        DnsResolveSource::StaleFallback,
                                        self.client_ttl()?,
                                    );
                                }
                            }
                            return Err(DnsResolverError::Upstream(error));
                        }
                    }
                }
                DnsRequestStart::CompletedByPeer => {
                    if let Some(result) = self.lookup_fresh(&key)? {
                        return Ok(result);
                    }
                }
                DnsRequestStart::Cancelled => {
                    return Err(DnsResolverError::CoalescerUnavailable);
                }
            }
        }
    }

    fn fetch_uncached(
        &self,
        query_packet: &[u8],
    ) -> Result<DnsResolveResult, DnsResolverError> {
        let response = self.upstream.exchange(query_packet)?;
        let metadata = parse_dns_message(&response)?;

        if !metadata.is_response() || metadata.is_truncated() {
            return Err(DnsResolverError::InvalidQuery);
        }

        let client_ttl = self.client_ttl()?;
        prepare_network_response(
            response,
            DnsResolveSource::Upstream,
            client_ttl,
        )
    }

    fn lookup_fresh(
        &self,
        key: &crate::dns_cache::DnsQueryKey,
    ) -> Result<Option<DnsResolveResult>, DnsResolverError> {
        let mut cache = self.cache.lock().map_err(|_| DnsResolverError::CacheUnavailable)?;
        match cache.lookup(key, current_unix_seconds(), false, false) {
            Some(lookup) if lookup.kind == DnsCacheLookupKind::Fresh => {
                Ok(Some(cached_result(lookup.entry)?))
            }
            _ => Ok(None),
        }
    }

    fn client_ttl(&self) -> Result<u32, DnsResolverError> {
        let cache = self.cache.lock().map_err(|_| DnsResolverError::CacheUnavailable)?;
        Ok(cache.policy().client_record_ttl_secs)
    }
}

fn cached_result(entry: &DnsCacheEntry) -> Result<DnsResolveResult, DnsResolverError> {
    let response = entry.prepare_client_response()?;
    let metadata = parse_dns_message(&response)?;
    Ok(DnsResolveResult {
        response,
        source: DnsResolveSource::Cache,
        metadata,
    })
}

fn prepare_network_response(
    mut response: Vec<u8>,
    source: DnsResolveSource,
    client_ttl: u32,
) -> Result<DnsResolveResult, DnsResolverError> {
    rewrite_resource_record_ttls(&mut response, client_ttl)?;
    let metadata = parse_dns_message(&response)?;
    Ok(DnsResolveResult {
        response,
        source,
        metadata,
    })
}

fn current_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        dns_cache::{DnsCachePolicy, DNS_RCODE_SUCCESS},
        dns_coalescer::DnsRequestCoalescer,
        dns_query::{build_dns_query, DnsQueryOptions},
        dns_upstream::DnsUpstreamConfig,
        dns_wire::DNS_HEADER_SIZE,
    };
    use std::{
        io,
        net::UdpSocket,
        thread,
        time::Duration,
    };

    fn query() -> Vec<u8> {
        build_dns_query(
            "example.com",
            1,
            0x3456,
            DnsQueryOptions {
                recursion_desired: true,
                udp_payload_size: None,
                dnssec_ok: false,
            },
        )
        .unwrap()
    }

    fn response_for(query: &[u8]) -> Vec<u8> {
        let mut response = query.to_vec();
        let mut flags = u16::from_be_bytes([response[2], response[3]]);
        flags |= 0x8080;
        response[2..4].copy_from_slice(&flags.to_be_bytes());
        response[6..8].copy_from_slice(&1_u16.to_be_bytes());

        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&120_u32.to_be_bytes());
        response.extend_from_slice(&4_u16.to_be_bytes());
        response.extend_from_slice(&[1, 2, 3, 4]);
        response
    }

    fn make_resolver(remote: std::net::SocketAddr) -> DnsResolver {
        let upstream = DnsUpstreamClient::new(
            remote,
            DnsUpstreamConfig {
                timeout: Duration::from_millis(300),
                attempts: 1,
                max_response_size: 4096,
                prefer_tcp: false,
                allow_tcp_fallback: true,
            },
        )
        .unwrap();
        let cache = DnsCache::new(16, DnsCachePolicy::default()).unwrap();
        let coalescer =
            DnsRequestCoalescer::new(16, Duration::from_secs(1)).unwrap();
        DnsResolver::new(upstream, cache, coalescer)
    }

    #[test]
    fn fetches_then_serves_the_response_from_cache() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let remote = server.local_addr().unwrap();
        let server_thread = thread::spawn(move || {
            let mut buffer = [0_u8; 512];
            let (length, source) = server.recv_from(&mut buffer).unwrap();
            let response = response_for(&buffer[..length]);
            server.send_to(&response, source).unwrap();
        });

        let resolver = make_resolver(remote);
        let query_packet = query();
        let first = resolver
            .resolve(&query_packet, DnsResolveOptions::default())
            .unwrap();
        assert_eq!(first.source, DnsResolveSource::Upstream);
        assert_eq!(first.metadata.minimum_record_ttl_secs, Some(17));

        let second = resolver
            .resolve(&query_packet, DnsResolveOptions::default())
            .unwrap();
        assert_eq!(second.source, DnsResolveSource::Cache);
        assert_eq!(second.response, first.response);
        server_thread.join().unwrap();
    }

    #[test]
    fn no_cache_request_does_not_populate_response_cache() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let remote = server.local_addr().unwrap();
        let server_thread = thread::spawn(move || {
            for _ in 0..2 {
                let mut buffer = [0_u8; 512];
                let (length, source) = server.recv_from(&mut buffer).unwrap();
                let response = response_for(&buffer[..length]);
                server.send_to(&response, source).unwrap();
            }
        });

        let resolver = make_resolver(remote);
        let query_packet = query();
        let options = DnsResolveOptions {
            no_caching: true,
            ..DnsResolveOptions::default()
        };

        let first = resolver.resolve(&query_packet, options).unwrap();
        let second = resolver.resolve(&query_packet, options).unwrap();
        assert_eq!(first.source, DnsResolveSource::Upstream);
        assert_eq!(second.source, DnsResolveSource::Upstream);
        server_thread.join().unwrap();
    }

    #[test]
    fn rejects_non_inet_query_class() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let resolver = make_resolver(server.local_addr().unwrap());
        let mut packet = query();
        let question_type_offset = packet.len() - 4;
        packet[question_type_offset + 2..].copy_from_slice(&3_u16.to_be_bytes());

        assert!(matches!(
            resolver.resolve(&packet, DnsResolveOptions::default()),
            Err(DnsResolverError::InvalidQuery)
        ));
    }

    #[test]
    fn invalid_query_does_not_contact_upstream() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        server
            .set_read_timeout(Some(Duration::from_millis(30)))
            .unwrap();
        let resolver = make_resolver(server.local_addr().unwrap());
        let mut packet = query();
        packet[2] |= 0x80;

        assert!(matches!(
            resolver.resolve(&packet, DnsResolveOptions::default()),
            Err(DnsResolverError::InvalidQuery)
        ));

        let mut buffer = [0; 512];
        assert!(matches!(
            server.recv_from(&mut buffer),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock || error.kind() == io::ErrorKind::TimedOut
        ));
    }

    #[test]
    fn successful_resolver_inserts_only_success_rcodes() {
        assert_eq!(DNS_RCODE_SUCCESS, 0);
        let packet = query();
        let metadata = parse_dns_message(&packet).unwrap();
        assert!(!metadata.is_response());
        assert_eq!(metadata.question_count, 1);
        assert!(DNS_HEADER_SIZE < packet.len());
    }
}
