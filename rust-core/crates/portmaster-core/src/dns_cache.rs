use std::{
    collections::{HashMap, VecDeque},
};

const MAX_CACHE_CAPACITY: usize = 1_000_000;

pub const DNS_RCODE_SUCCESS: u16 = 0;
pub const DNS_RCODE_NAME_ERROR: u16 = 3;
pub const DNS_RCODE_REFUSED: u16 = 5;

/// Errors returned by the bounded DNS cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsCacheConfigError {
    ZeroCapacity,
    CapacityTooLarge,
    ZeroTtl,
    MinimumTtlExceedsMaximum,
    EmptyName,
    ZeroByteBudget,
    EntryBudgetExceedsTotal,
}

impl std::fmt::Display for DnsCacheConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZeroCapacity => formatter.write_str("DNS cache capacity must be greater than zero"),
            Self::CapacityTooLarge => {
                write!(formatter, "DNS cache capacity exceeds {MAX_CACHE_CAPACITY}")
            }
            Self::ZeroTtl => formatter.write_str("DNS cache TTL values must be greater than zero"),
            Self::MinimumTtlExceedsMaximum => {
                formatter.write_str("DNS cache minimum TTL cannot exceed maximum TTL")
            }
            Self::EmptyName => formatter.write_str("DNS query name cannot be empty"),
            Self::ZeroByteBudget => formatter.write_str("DNS cache byte budgets must be greater than zero"),
            Self::EntryBudgetExceedsTotal => {
                formatter.write_str("DNS cache entry limit cannot exceed total byte budget")
            }
        }
    }
}

impl std::error::Error for DnsCacheConfigError {}

/// TTL and refresh rules matching the current Portmaster resolver defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsCachePolicy {
    pub min_ttl_secs: u32,
    pub refresh_window_secs: u32,
    pub max_ttl_secs: u32,
    pub error_ttl_secs: u32,
    pub connectivity_ttl_secs: u32,
    pub empty_answer_ttl_secs: u32,
    pub offline_ttl_secs: u32,
    pub client_record_ttl_secs: u32,
}

impl Default for DnsCachePolicy {
    fn default() -> Self {
        Self {
            min_ttl_secs: 60,
            refresh_window_secs: 30,
            max_ttl_secs: 24 * 60 * 60,
            error_ttl_secs: 10,
            connectivity_ttl_secs: 3,
            empty_answer_ttl_secs: 60,
            offline_ttl_secs: 60,
            client_record_ttl_secs: 17,
        }
    }
}

impl DnsCachePolicy {
    pub fn validate(&self) -> Result<(), DnsCacheConfigError> {
        if self.min_ttl_secs == 0
            || self.max_ttl_secs == 0
            || self.error_ttl_secs == 0
            || self.connectivity_ttl_secs == 0
            || self.empty_answer_ttl_secs == 0
            || self.offline_ttl_secs == 0
            || self.client_record_ttl_secs == 0
        {
            return Err(DnsCacheConfigError::ZeroTtl);
        }

        if self.min_ttl_secs > self.max_ttl_secs {
            return Err(DnsCacheConfigError::MinimumTtlExceedsMaximum);
        }

        Ok(())
    }

    /// Calculates the resolver's cache lifetime for one response.
    ///
    /// The precedence follows the existing resolver: non-success RCodes first,
    /// then connectivity domains, empty answers, offline state, and finally
    /// the minimum record TTL with configured lower and upper bounds.
    #[must_use]
    pub fn lifetime_secs(&self, metadata: &DnsResponseMetadata) -> u32 {
        if metadata.rcode != DNS_RCODE_SUCCESS {
            return self.error_ttl_secs;
        }

        if metadata.is_connectivity_domain {
            return self.connectivity_ttl_secs;
        }

        if metadata.answer_count == 0 {
            return self.empty_answer_ttl_secs;
        }

        if !metadata.online {
            return self.offline_ttl_secs;
        }

        metadata
            .minimum_record_ttl_secs
            .unwrap_or(self.max_ttl_secs)
            .clamp(self.min_ttl_secs, self.max_ttl_secs)
    }

    #[must_use]
    pub const fn is_cacheable_rcode(rcode: u16) -> bool {
        matches!(
            rcode,
            DNS_RCODE_SUCCESS | DNS_RCODE_NAME_ERROR | DNS_RCODE_REFUSED
        )
    }
}

/// Metadata needed to apply resolver cache policy.
///
/// The caller extracts the minimum TTL across answer, authority and
/// additional records before inserting the response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsResponseMetadata {
    pub rcode: u16,
    pub answer_count: usize,
    pub minimum_record_ttl_secs: Option<u32>,
    pub is_connectivity_domain: bool,
    pub online: bool,
}

/// Normalized cache key for a DNS question.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DnsQueryKey {
    pub name: String,
    pub record_type: u16,
}

impl DnsQueryKey {
    pub fn new(name: &str, record_type: u16) -> Result<Self, DnsCacheConfigError> {
        if name.is_empty() {
            return Err(DnsCacheConfigError::EmptyName);
        }

        let lower = name.to_ascii_lowercase();
        let normalized = if lower.ends_with('.') {
            lower
        } else {
            format!("{lower}.")
        }

        Ok(Self {
            name: normalized,
            record_type,
        })
    }
}

/// Cached DNS response bytes and the policy metadata required to serve them.
///
/// The payload is intentionally opaque. DNS message parsing, validation,
/// answer filtering, and response encoding belong to separate resolver
/// components; this type only owns the cache lifecycle and TTL policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsCacheEntry {
    key: DnsQueryKey,
    rcode: u16,
    payload: Vec<u8>,
    expires_at_unix: u64,
    client_record_ttl_secs: u32,
    answer_count: usize,
    is_connectivity_domain: bool,
}

impl DnsCacheEntry {
    #[must_use]
    pub const fn key(&self) -> &DnsQueryKey {
        &self.key
    }

    #[must_use]
    pub const fn rcode(&self) -> u16 {
        self.rcode
    }

    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    #[must_use]
    pub const fn expires_at_unix(&self) -> u64 {
        self.expires_at_unix
    }

    /// The resolver replaces resource-record TTLs with this value before
    /// sending a response to clients.
    #[must_use]
    pub const fn client_record_ttl_secs(&self) -> u32 {
        self.client_record_ttl_secs
    }

    #[must_use]
    pub const fn answer_count(&self) -> usize {
        self.answer_count
    }

    #[must_use]
    pub const fn is_connectivity_domain(&self) -> bool {
        self.is_connectivity_domain
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsCacheLookupKind {
    Fresh,
    RefreshSoon,
    StaleSuccess,
    ExpiredBackup,
}

#[derive(Debug, Clone, Copy)]
pub struct DnsCacheLookup<'a> {
    pub entry: &'a DnsCacheEntry,
    pub kind: DnsCacheLookupKind,
}

struct StoredEntry {
    entry: DnsCacheEntry,
    generation: u64,
}

/// Bounded FIFO DNS response cache.
///
/// Expired successful responses remain available as a fallback while a
/// refresh is attempted. Expired negative/error responses are removed when
/// queried. Capacity is always bounded; inserts never evict an active
/// response without first reaching the configured limit.
pub struct DnsCache {
    capacity: usize,
    max_entry_bytes: usize,
    max_total_bytes: usize,
    total_payload_bytes: usize,
    policy: DnsCachePolicy,
    entries: HashMap<DnsQueryKey, StoredEntry>,
    insertion_order: VecDeque<(DnsQueryKey, u64)>,
    generation: u64,
}

impl DnsCache {
    pub fn new(
        capacity: usize,
        policy: DnsCachePolicy,
    ) -> Result<Self, DnsCacheConfigError> {
        Self::new_with_limits(capacity, 65_535, 32 * 1024 * 1024, policy)
    }

    /// Creates a DNS cache with explicit per-response and total payload limits.
    pub fn new_with_limits(
        capacity: usize,
        max_entry_bytes: usize,
        max_total_bytes: usize,
        policy: DnsCachePolicy,
    ) -> Result<Self, DnsCacheConfigError> {
        if capacity == 0 {
            return Err(DnsCacheConfigError::ZeroCapacity);
        }
        if capacity > MAX_CACHE_CAPACITY {
            return Err(DnsCacheConfigError::CapacityTooLarge);
        }
        if max_entry_bytes == 0 || max_total_bytes == 0 {
            return Err(DnsCacheConfigError::ZeroByteBudget);
        }
        if max_entry_bytes > max_total_bytes {
            return Err(DnsCacheConfigError::EntryBudgetExceedsTotal);
        }
        policy.validate()?;

        Ok(Self {
            capacity,
            max_entry_bytes,
            max_total_bytes,
            total_payload_bytes: 0,
            policy,
            entries: HashMap::new(),
            insertion_order: VecDeque::new(),
            generation: 0,
        })
    }

    /// Inserts a cacheable response. Returns false for no-cache requests,
    /// connectivity domains, and RCodes that Portmaster does not persist.
    pub fn insert(
        &mut self,
        key: DnsQueryKey,
        payload: Vec<u8>,
        metadata: DnsResponseMetadata,
        no_caching: bool,
        now_unix: u64,
    ) -> bool {
        if no_caching
            || metadata.is_connectivity_domain
            || !DnsCachePolicy::is_cacheable_rcode(metadata.rcode)
            || payload.len() > self.max_entry_bytes
        {
            return false;
        }

        let payload_size = payload.len();
        let lifetime = self.policy.lifetime_secs(&metadata);
        let entry = DnsCacheEntry {
            key: key.clone(),
            rcode: metadata.rcode,
            payload,
            expires_at_unix: now_unix.saturating_add(u64::from(lifetime)),
            client_record_ttl_secs: self.policy.client_record_ttl_secs,
            answer_count: metadata.answer_count,
            is_connectivity_domain: metadata.is_connectivity_domain,
        };

        if let Some(previous) = self.entries.remove(&key) {
            self.total_payload_bytes = self
                .total_payload_bytes
                .saturating_sub(previous.entry.payload.len());
        }

        while self.entries.len() >= self.capacity
            || self.total_payload_bytes.saturating_add(payload_size) > self.max_total_bytes
        {
            if !self.evict_oldest() {
                return false;
            }
        }

        self.generation = self.generation.wrapping_add(1);
        if self.generation == 0 {
            self.generation = 1;
        }

        let generation = self.generation;
        self.entries.insert(key.clone(), StoredEntry { entry, generation });
        self.total_payload_bytes = self.total_payload_bytes.saturating_add(payload_size);
        self.insertion_order.push_back((key, generation));
        self.compact_order();
        true
    }

    /// Looks up one DNS response using the resolver's stale-cache behavior.
    ///
    /// Fresh answers expiring within the refresh window are returned with
    /// RefreshSoon so the caller can start an asynchronous refresh. Expired
    /// successful answers can be returned stale or retained as a fallback
    /// while a new lookup is attempted. Expired negative answers are evicted.
    pub fn lookup(
        &mut self,
        key: &DnsQueryKey,
        now_unix: u64,
        use_stale_success: bool,
        is_connectivity_domain: bool,
    ) -> Option<DnsCacheLookup<'_>> {
        if is_connectivity_domain {
            return None;
        }

        let kind = {
            let stored = self.entries.get(key)?;
            let entry = &stored.entry;

            if entry.is_connectivity_domain {
                return None;
            }

            if now_unix >= entry.expires_at_unix {
                if entry.rcode != DNS_RCODE_SUCCESS {
                    self.remove_entry(key);
                    return None;
                }

                if use_stale_success {
                    DnsCacheLookupKind::StaleSuccess
                } else {
                    DnsCacheLookupKind::ExpiredBackup
                }
            } else if entry.expires_at_unix.saturating_sub(now_unix)
                <= u64::from(self.policy.refresh_window_secs)
            {
                DnsCacheLookupKind::RefreshSoon
            } else {
                DnsCacheLookupKind::Fresh
            }
        };

        self.entries
            .get(key)
            .map(|stored| DnsCacheLookup {
                entry: &stored.entry,
                kind,
            })
    }

    pub fn remove(&mut self, key: &DnsQueryKey) -> Option<DnsCacheEntry> {
        let removed = self.remove_entry(key);
        self.compact_order();
        removed
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        self.insertion_order.clear();
        self.total_payload_bytes = 0;
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub const fn total_payload_bytes(&self) -> usize {
        self.total_payload_bytes
    }

    #[must_use]
    pub const fn max_entry_bytes(&self) -> usize {
        self.max_entry_bytes
    }

    #[must_use]
    pub const fn max_total_bytes(&self) -> usize {
        self.max_total_bytes
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    #[must_use]
    pub const fn policy(&self) -> DnsCachePolicy {
        self.policy
    }

    fn evict_oldest(&mut self) -> bool {
        while let Some((key, generation)) = self.insertion_order.pop_front() {
            let is_current = self
                .entries
                .get(&key)
                .is_some_and(|stored| stored.generation == generation);

            if is_current {
                self.remove_entry(&key);
                return true;
            }
        }
        false
    }

    fn remove_entry(&mut self, key: &DnsQueryKey) -> Option<DnsCacheEntry> {
        let removed = self.entries.remove(key).map(|stored| stored.entry);
        if let Some(entry) = &removed {
            self.total_payload_bytes = self
                .total_payload_bytes
                .saturating_sub(entry.payload.len());
        }
        removed
    }

    fn compact_order(&mut self) {
        if self.insertion_order.len() <= self.capacity.saturating_mul(2).max(64) {
            return;
        }

        self.insertion_order.retain(|(key, generation)| {
            self.entries
                .get(key)
                .is_some_and(|stored| stored.generation == *generation)
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(name: &str, record_type: u16) -> DnsQueryKey {
        DnsQueryKey::new(name, record_type).unwrap()
    }

    fn metadata(
        rcode: u16,
        answer_count: usize,
        minimum_record_ttl_secs: Option<u32>,
        is_connectivity_domain: bool,
        online: bool,
    ) -> DnsResponseMetadata {
        DnsResponseMetadata {
            rcode,
            answer_count,
            minimum_record_ttl_secs,
            is_connectivity_domain,
            online,
        }
    }

    #[test]
    fn normalizes_domain_name_and_keeps_record_type_in_key() {
        let upper = key("ExAmPlE.com", 1);
        let lower = key("example.com.", 1);
        let different_type = key("example.com", 28);

        assert_eq!(upper.name, "example.com.");
        assert_eq!(upper, lower);
        assert_ne!(upper, different_type);
        assert_eq!(key(".", 1).name, ".");
    }

    #[test]
    fn rejects_empty_domain_name() {
        assert_eq!(
            DnsQueryKey::new("", 1).err(),
            Some(DnsCacheConfigError::EmptyName)
        );
    }

    #[test]
    fn applies_default_resolver_ttl_rules() {
        let policy = DnsCachePolicy::default();

        assert_eq!(
            policy.lifetime_secs(&metadata(DNS_RCODE_SUCCESS, 1, Some(15), false, true)),
            60
        );
        assert_eq!(
            policy.lifetime_secs(&metadata(DNS_RCODE_SUCCESS, 1, Some(200_000), false, true)),
            86_400
        );
        assert_eq!(
            policy.lifetime_secs(&metadata(DNS_RCODE_NAME_ERROR, 0, None, false, true)),
            10
        );
        assert_eq!(
            policy.lifetime_secs(&metadata(DNS_RCODE_REFUSED, 0, None, false, true)),
            10
        );
        assert_eq!(
            policy.lifetime_secs(&metadata(DNS_RCODE_SUCCESS, 1, Some(30), true, true)),
            3
        );
        assert_eq!(
            policy.lifetime_secs(&metadata(DNS_RCODE_SUCCESS, 0, None, false, true)),
            60
        );
        assert_eq!(
            policy.lifetime_secs(&metadata(DNS_RCODE_SUCCESS, 1, Some(300), false, false)),
            60
        );
    }

    #[test]
    fn caches_only_success_negative_and_refused_responses() {
        let policy = DnsCachePolicy::default();

        assert!(DnsCachePolicy::is_cacheable_rcode(DNS_RCODE_SUCCESS));
        assert!(DnsCachePolicy::is_cacheable_rcode(DNS_RCODE_NAME_ERROR));
        assert!(DnsCachePolicy::is_cacheable_rcode(DNS_RCODE_REFUSED));
        assert!(!DnsCachePolicy::is_cacheable_rcode(2));
        assert!(!DnsCachePolicy::is_cacheable_rcode(4));
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn rejects_invalid_policy_limits() {
        let policy = DnsCachePolicy {
            min_ttl_secs: 120,
            max_ttl_secs: 60,
            ..DnsCachePolicy::default()
        };

        assert_eq!(
            policy.validate().err(),
            Some(DnsCacheConfigError::MinimumTtlExceedsMaximum)
        );
    }

    #[test]
    fn caches_and_refreshes_records_close_to_expiry() {
        let mut cache = DnsCache::new(8, DnsCachePolicy::default()).unwrap();
        let question = key("example.com", 1);
        let response = metadata(DNS_RCODE_SUCCESS, 1, Some(120), false, true);

        assert!(cache.insert(
            question.clone(),
            vec![1, 2, 3],
            response,
            false,
            1_000
        ));

        let lookup = cache.lookup(&question, 1_060, false, false).unwrap();
        assert_eq!(lookup.kind, DnsCacheLookupKind::RefreshSoon);
        assert_eq!(lookup.entry.payload(), &[1, 2, 3]);
        assert_eq!(lookup.entry.client_record_ttl_secs(), 17);

        assert_eq!(
            cache.lookup(&question, 1_061, false, false).unwrap().kind,
            DnsCacheLookupKind::Fresh
        );
    }

    #[test]
    fn expired_success_can_be_served_stale_or_used_as_backup() {
        let mut cache = DnsCache::new(4, DnsCachePolicy::default()).unwrap();
        let question = key("example.net", 1);
        cache.insert(
            question.clone(),
            vec![9],
            metadata(DNS_RCODE_SUCCESS, 1, Some(1), false, true),
            false,
            10_000
        );

        assert_eq!(
            cache.lookup(&question, 10_060, true, false).unwrap().kind,
            DnsCacheLookupKind::StaleSuccess
        );
        assert_eq!(
            cache.lookup(&question, 10_060, false, false).unwrap().kind,
            DnsCacheLookupKind::ExpiredBackup
        );
    }

    #[test]
    fn expired_negative_response_is_removed() {
        let mut cache = DnsCache::new(4, DnsCachePolicy::default()).unwrap();
        let question = key("missing.example", 1);
        cache.insert(
            question.clone(),
            vec![0],
            metadata(DNS_RCODE_NAME_ERROR, 0, None, false, true),
            false,
            2_000
        );

        assert!(cache.lookup(&question, 2_010, true, false).is_none());
        assert!(cache.is_empty());
    }

    #[test]
    fn skips_no_cache_and_connectivity_requests() {
        let mut cache = DnsCache::new(4, DnsCachePolicy::default()).unwrap();
        let question = key("connectivity.example", 1);
        let connectivity = metadata(DNS_RCODE_SUCCESS, 1, Some(30), true, true);

        assert!(!cache.insert(
            question.clone(),
            vec![1],
            connectivity,
            false,
            3_000
        ));
        assert!(!cache.insert(
            question.clone(),
            vec![1],
            metadata(DNS_RCODE_SUCCESS, 1, Some(30), false, true),
            true,
            3_000
        ));
        assert!(cache.is_empty());
    }


    #[test]
    fn enforces_per_entry_and_total_payload_budgets() {
        let mut cache = DnsCache::new_with_limits(
            4,
            5,
            8,
            DnsCachePolicy::default(),
        )
        .unwrap();
        let first = key("first.example", 1);
        let second = key("second.example", 1);
        let too_large = key("large.example", 1);
        let response = metadata(DNS_RCODE_SUCCESS, 1, Some(120), false, true);

        assert!(cache.insert(first.clone(), vec![1; 5], response, false, 6_000));
        assert!(cache.insert(second.clone(), vec![2; 4], response, false, 6_001));
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.total_payload_bytes(), 4);
        assert!(cache.lookup(&first, 6_001, false, false).is_none());
        assert!(cache.lookup(&second, 6_001, false, false).is_some());

        assert!(!cache.insert(too_large, vec![3; 6], response, false, 6_002));
        assert_eq!(cache.total_payload_bytes(), 4);
    }

    #[test]
    fn replacing_a_response_updates_the_payload_budget() {
        let mut cache = DnsCache::new_with_limits(
            2,
            8,
            8,
            DnsCachePolicy::default(),
        )
        .unwrap();
        let question = key("replace.example", 1);
        let response = metadata(DNS_RCODE_SUCCESS, 1, Some(120), false, true);

        assert!(cache.insert(question.clone(), vec![1; 6], response, false, 7_000));
        assert!(cache.insert(question.clone(), vec![2; 3], response, false, 7_001));
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.total_payload_bytes(), 3);
        assert_eq!(
            cache.lookup(&question, 7_001, false, false).unwrap().entry.payload(),
            &[2, 2, 2]
        );
    }

    #[test]
    fn evicts_oldest_entry_at_capacity_without_growing_past_limit() {
        let mut cache = DnsCache::new(2, DnsCachePolicy::default()).unwrap();
        let first = key("one.example", 1);
        let second = key("two.example", 1);
        let third = key("three.example", 1);
        let response = metadata(DNS_RCODE_SUCCESS, 1, Some(120), false, true);

        assert!(cache.insert(first.clone(), vec![1], response, false, 4_000));
        assert!(cache.insert(second.clone(), vec![2], response, false, 4_000));
        assert!(cache.insert(third.clone(), vec![3], response, false, 4_000));

        assert_eq!(cache.len(), 2);
        assert!(cache.lookup(&first, 4_000, false, false).is_none());
        assert!(cache.lookup(&second, 4_000, false, false).is_some());
        assert!(cache.lookup(&third, 4_000, false, false).is_some());
    }

    #[test]
    fn replacing_a_key_does_not_leave_stale_eviction_records() {
        let mut cache = DnsCache::new(2, DnsCachePolicy::default()).unwrap();
        let first = key("one.example", 1);
        let second = key("two.example", 1);
        let third = key("three.example", 1);
        let response = metadata(DNS_RCODE_SUCCESS, 1, Some(120), false, true);

        cache.insert(first.clone(), vec![1], response, false, 5_000);
        cache.insert(second.clone(), vec![2], response, false, 5_000);
        cache.insert(first.clone(), vec![9], response, false, 5_001);
        cache.insert(third.clone(), vec![3], response, false, 5_002);

        assert_eq!(
            cache.lookup(&first, 5_002, false, false).unwrap().entry.payload(),
            &[9]
        );
        assert!(cache.lookup(&second, 5_002, false, false).is_none());
    }
}
