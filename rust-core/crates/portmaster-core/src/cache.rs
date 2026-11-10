use std::{
    collections::{HashMap, VecDeque},
    hash::Hash,
    time::{Duration, Instant},
};

const MAX_CAPACITY: usize = 1_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheConfigError {
    ZeroCapacity,
    CapacityTooLarge,
    ZeroTtl,
    TtlOutOfRange,
}

impl std::fmt::Display for CacheConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZeroCapacity => f.write_str("cache capacity must be greater than zero"),
            Self::CapacityTooLarge => write!(f, "cache capacity exceeds {MAX_CAPACITY}"),
            Self::ZeroTtl => f.write_str("cache TTL must be greater than zero"),
            Self::TtlOutOfRange => f.write_str("cache TTL exceeds the supported clock range"),
        }
    }
}

impl std::error::Error for CacheConfigError {}

struct Entry<V> {
    value: V,
    expires_at: Instant,
    generation: u64,
}

/// Fixed-capacity FIFO cache. Reads do not extend the entry's TTL.
pub struct BoundedTtlCache<K, V> {
    capacity: usize,
    ttl: Duration,
    entries: HashMap<K, Entry<V>>,
    order: VecDeque<(K, u64)>,
    generation: u64,
}

impl<K: Clone + Eq + Hash, V> BoundedTtlCache<K, V> {
    pub fn new(capacity: usize, ttl: Duration) -> Result<Self, CacheConfigError> {
        if capacity == 0 {
            return Err(CacheConfigError::ZeroCapacity);
        }
        if capacity > MAX_CAPACITY {
            return Err(CacheConfigError::CapacityTooLarge);
        }
        if ttl.is_zero() {
            return Err(CacheConfigError::ZeroTtl);
        }
        if Instant::now().checked_add(ttl).is_none() {
            return Err(CacheConfigError::TtlOutOfRange);
        }

        Ok(Self {
            capacity,
            ttl,
            entries: HashMap::new(),
            order: VecDeque::new(),
            generation: 0,
        })
    }

    pub fn get(&mut self, key: &K) -> Option<&V> {
        if self
            .entries
            .get(key)
            .is_some_and(|entry| entry.expires_at <= Instant::now())
        {
            self.entries.remove(key);
            self.compact();
            return None;
        }
        self.entries.get(key).map(|entry| &entry.value)
    }

    /// Inserts or replaces a value. Returns the replaced value, if present.
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        let now = Instant::now();
        self.purge_expired_at(now);

        let previous = self.entries.remove(&key).map(|entry| entry.value);
        if previous.is_none() && self.entries.len() >= self.capacity {
            self.evict_oldest();
        }

        self.generation = self.generation.wrapping_add(1);
        if self.generation == 0 {
            self.generation = 1;
        }

        let generation = self.generation;
        let expires_at = now
            .checked_add(self.ttl)
            .expect("TTL was validated when the cache was created");
        self.entries.insert(
            key.clone(),
            Entry {
                value,
                expires_at,
                generation,
            },
        );
        self.order.push_back((key, generation));
        self.compact();

        previous
    }

    pub fn remove(&mut self, key: &K) -> Option<V> {
        let value = self.entries.remove(key).map(|entry| entry.value);
        self.compact();
        value
    }

    pub fn purge_expired(&mut self) -> usize {
        self.purge_expired_at(Instant::now())
    }

    pub fn len(&mut self) -> usize {
        self.purge_expired();
        self.entries.len()
    }

    pub fn is_empty(&mut self) -> bool {
        self.len() == 0
    }

    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        self.order.clear();
    }

    fn purge_expired_at(&mut self, now: Instant) -> usize {
        let mut removed = 0;
        loop {
            let Some((key, generation)) = self.order.front() else {
                break;
            };
            let state = self
                .entries
                .get(key)
                .map(|entry| (entry.generation, entry.expires_at));
            match state {
                Some((current, expiry)) if current == *generation && expiry > now => break,
                Some((current, _)) if current == *generation => {
                    let (key, _) = self.order.pop_front().expect("front was present");
                    self.entries.remove(&key);
                    removed += 1;
                }
                _ => {
                    self.order.pop_front();
                }
            }
        }
        self.compact();
        removed
    }

    fn evict_oldest(&mut self) {
        while let Some((key, generation)) = self.order.pop_front() {
            if self
                .entries
                .get(&key)
                .is_some_and(|entry| entry.generation == generation)
            {
                self.entries.remove(&key);
                break;
            }
        }
    }

    fn compact(&mut self) {
        if self.order.len() <= self.capacity.saturating_mul(2).max(64) {
            return;
        }
        self.order.retain(|(key, generation)| {
            self.entries
                .get(key)
                .is_some_and(|entry| entry.generation == *generation)
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_zero_capacity_and_ttl() {
        assert_eq!(
            BoundedTtlCache::<u8, u8>::new(0, Duration::from_secs(1)).err(),
            Some(CacheConfigError::ZeroCapacity)
        );
        assert_eq!(
            BoundedTtlCache::<u8, u8>::new(1, Duration::ZERO).err(),
            Some(CacheConfigError::ZeroTtl)
        );
    }

    #[test]
    fn evicts_oldest_entry_at_capacity() {
        let mut cache = BoundedTtlCache::new(2, Duration::from_secs(60)).unwrap();
        cache.insert(1, "one");
        cache.insert(2, "two");
        cache.insert(3, "three");
        assert_eq!(cache.get(&1), None);
        assert_eq!(cache.get(&2), Some(&"two"));
        assert_eq!(cache.get(&3), Some(&"three"));
    }

    #[test]
    fn replacing_key_does_not_leave_stale_eviction_record() {
        let mut cache = BoundedTtlCache::new(2, Duration::from_secs(60)).unwrap();
        cache.insert(1, "old");
        cache.insert(2, "two");
        assert_eq!(cache.insert(1, "new"), Some("old"));
        cache.insert(3, "three");
        assert_eq!(cache.get(&1), Some(&"new"));
        assert_eq!(cache.get(&2), None);
    }

    #[test]
    fn expired_values_are_not_returned() {
        let mut cache = BoundedTtlCache::new(2, Duration::from_millis(1)).unwrap();
        cache.insert(1, "temporary");
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(cache.get(&1), None);
        assert!(cache.is_empty());
    }

    #[test]
    fn repeated_replacement_does_not_grow_order_without_bound() {
        let mut cache = BoundedTtlCache::new(1, Duration::from_secs(60)).unwrap();
        for value in 0..10_000 {
            cache.insert(1, value);
        }
        assert_eq!(cache.get(&1), Some(&9_999));
        assert!(cache.order.len() <= 64);
    }
}
