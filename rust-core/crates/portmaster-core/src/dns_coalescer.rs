use crate::dns_cache::DnsQueryKey;
use std::{
    collections::HashMap,
    sync::{Arc, Condvar, Mutex, Weak},
    time::{Duration, Instant},
};

const MAX_IN_FLIGHT_REQUESTS: usize = 1_000_000;
const CANCELLATION_POLL_INTERVAL: Duration = Duration::from_millis(25);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsCoalescerConfigError {
    ZeroCapacity,
    CapacityTooLarge,
    ZeroTimeout,
    TimeoutOutOfRange,
}

impl std::fmt::Display for DnsCoalescerConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZeroCapacity => {
                formatter.write_str("DNS coalescer capacity must be greater than zero")
            }
            Self::CapacityTooLarge => {
                write!(formatter, "DNS coalescer capacity exceeds {MAX_IN_FLIGHT_REQUESTS}")
            }
            Self::ZeroTimeout => {
                formatter.write_str("DNS coalescer request timeout must be greater than zero")
            }
            Self::TimeoutOutOfRange => {
                formatter.write_str("DNS coalescer request timeout exceeds the clock range")
            }
        }
    }
}

impl std::error::Error for DnsCoalescerConfigError {}

struct Flight {
    deadline: Instant,
    completed: Mutex<bool>,
    changed: Condvar,
}

impl Flight {
    fn new(timeout: Duration) -> Result<Self, DnsCoalescerConfigError> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(DnsCoalescerConfigError::TimeoutOutOfRange)?;

        Ok(Self {
            deadline,
            completed: Mutex::new(false),
            changed: Condvar::new(),
        })
    }

    fn finish(&self) {
        if let Ok(mut completed) = self.completed.lock() {
            *completed = true;
            self.changed.notify_all();
        }
    }
}

struct Registry {
    max_in_flight: usize,
    timeout: Duration,
    entries: Mutex<HashMap<DnsQueryKey, Arc<Flight>>>,
}

/// Bounded registry for coalescing identical DNS requests.
///
/// One caller becomes the leader. Other callers wait for it to finish and
/// then re-check the DNS cache. If the leader exceeds the configured timeout,
/// the next caller replaces it and becomes a new leader. Completion of the
/// old leader cannot remove the replacement.
///
/// If the registry is full, a new key is allowed to proceed as an untracked
/// leader rather than blocking unrelated DNS work. That fallback preserves
/// availability at the cost of coalescing for that one request.
#[derive(Clone)]
pub struct DnsRequestCoalescer {
    registry: Arc<Registry>,
}

/// Result returned when a caller attempts to start or join a DNS request.
pub enum DnsRequestStart {
    Leader(DnsRequestGuard),
    CompletedByPeer,
    Cancelled,
}

/// Guard held by the request leader.
///
/// Dropping the guard marks the flight as complete and wakes its waiters.
/// Explicit finish is available when the request's completion point is
/// clearer than the end of the scope.
pub struct DnsRequestGuard {
    registry: Weak<Registry>,
    key: Option<DnsQueryKey>,
    flight: Arc<Flight>,
    tracked: bool,
}

impl DnsRequestGuard {
    pub fn finish(mut self) {
        self.complete();
    }

    fn complete(&mut self) {
        self.flight.finish();

        if !self.tracked {
            return;
        }

        let Some(registry) = self.registry.upgrade() else {
            return;
        };
        let Some(key) = self.key.take() else {
            return;
        };

        if let Ok(mut entries) = registry.entries.lock() {
            let is_current = entries
                .get(&key)
                .is_some_and(|current| Arc::ptr_eq(current, &self.flight));

            if is_current {
                entries.remove(&key);
            }
        }

        self.tracked = false;
    }
}

impl Drop for DnsRequestGuard {
    fn drop(&mut self) {
        self.complete();
    }
}

impl DnsRequestCoalescer {
    pub fn new(
        max_in_flight: usize,
        timeout: Duration,
    ) -> Result<Self, DnsCoalescerConfigError> {
        if max_in_flight == 0 {
            return Err(DnsCoalescerConfigError::ZeroCapacity);
        }
        if max_in_flight > MAX_IN_FLIGHT_REQUESTS {
            return Err(DnsCoalescerConfigError::CapacityTooLarge);
        }
        if timeout.is_zero() {
            return Err(DnsCoalescerConfigError::ZeroTimeout);
        }
        if Instant::now().checked_add(timeout).is_none() {
            return Err(DnsCoalescerConfigError::TimeoutOutOfRange);
        }

        Ok(Self {
            registry: Arc::new(Registry {
                max_in_flight,
                timeout,
                entries: Mutex::new(HashMap::new()),
            }),
        })
    }

    /// Starts a request or waits for an existing identical request.
    ///
    /// is_cancelled is checked while waiting. A completed peer result means
    /// the caller should re-check the DNS cache before attempting any upstream
    /// request. A cancelled caller must not assume the peer has completed.
    pub fn begin<F>(&self, key: DnsQueryKey, mut is_cancelled: F) -> DnsRequestStart
    where
        F: FnMut() -> bool,
    {
        loop {
            if is_cancelled() {
                return DnsRequestStart::Cancelled;
            }

            let existing = {
                let Ok(mut entries) = self.registry.entries.lock() else {
                    return DnsRequestStart::Cancelled;
                };

                match entries.get(&key).cloned() {
                    Some(flight) if Instant::now() < flight.deadline => Some(flight),
                    Some(_) => {
                        let flight = match Flight::new(self.registry.timeout) {
                            Ok(flight) => Arc::new(flight),
                            Err(_) => return DnsRequestStart::Cancelled,
                        };
                        entries.insert(key.clone(), Arc::clone(&flight));
                        return DnsRequestStart::Leader(DnsRequestGuard {
                            registry: Arc::downgrade(&self.registry),
                            key: Some(key),
                            flight,
                            tracked: true,
                        });
                    }
                    None if entries.len() < self.registry.max_in_flight => {
                        let flight = match Flight::new(self.registry.timeout) {
                            Ok(flight) => Arc::new(flight),
                            Err(_) => return DnsRequestStart::Cancelled,
                        };
                        entries.insert(key.clone(), Arc::clone(&flight));
                        return DnsRequestStart::Leader(DnsRequestGuard {
                            registry: Arc::downgrade(&self.registry),
                            key: Some(key),
                            flight,
                            tracked: true,
                        });
                    }
                    None => {
                        let flight = match Flight::new(self.registry.timeout) {
                            Ok(flight) => Arc::new(flight),
                            Err(_) => return DnsRequestStart::Cancelled,
                        };
                        return DnsRequestStart::Leader(DnsRequestGuard {
                            registry: Arc::downgrade(&self.registry),
                            key: None,
                            flight,
                            tracked: false,
                        });
                    }
                }
            };

            let Some(flight) = existing else {
                continue;
            };

            let Ok(mut completed) = flight.completed.lock() else {
                return DnsRequestStart::Cancelled;
            };

            loop {
                if *completed {
                    return DnsRequestStart::CompletedByPeer;
                }
                if is_cancelled() {
                    return DnsRequestStart::Cancelled;
                }

                let remaining = flight.deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }

                let wait_for = remaining.min(CANCELLATION_POLL_INTERVAL);
                match flight.changed.wait_timeout(completed, wait_for) {
                    Ok((next_state, _)) => completed = next_state,
                    Err(_) => return DnsRequestStart::Cancelled,
                }
            }
        }
    }

    /// Returns the number of tracked in-flight query keys.
    pub fn len(&self) -> usize {
        self.registry
            .entries
            .lock()
            .map(|entries| entries.len())
            .unwrap_or(0)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.registry.max_in_flight
    }

    pub fn clear_completed(&self) -> usize {
        let Ok(mut entries) = self.registry.entries.lock() else {
            return 0;
        };

        let before = entries.len();
        entries.retain(|_, flight| {
            flight
                .completed
                .lock()
                .map(|completed| !*completed)
                .unwrap_or(false)
        });
        before - entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{thread, time::Duration};

    fn key(name: &str) -> DnsQueryKey {
        DnsQueryKey::new(name, 1).unwrap()
    }

    #[test]
    fn rejects_invalid_limits() {
        assert_eq!(
            DnsRequestCoalescer::new(0, Duration::from_secs(1)).err(),
            Some(DnsCoalescerConfigError::ZeroCapacity)
        );
        assert_eq!(
            DnsRequestCoalescer::new(1, Duration::ZERO).err(),
            Some(DnsCoalescerConfigError::ZeroTimeout)
        );
    }

    #[test]
    fn first_request_becomes_leader_and_drop_wakes_waiter() {
        let coalescer = DnsRequestCoalescer::new(8, Duration::from_secs(2)).unwrap();
        let request_key = key("example.com");
        let DnsRequestStart::Leader(guard) =
            coalescer.begin(request_key.clone(), || false)
        else {
            panic!("first request should become leader");
        };

        let other = coalescer.clone();
        let waiter_key = request_key;
        let waiter = thread::spawn(move || other.begin(waiter_key, || false));

        thread::sleep(Duration::from_millis(30));
        drop(guard);

        assert!(matches!(
            waiter.join().unwrap(),
            DnsRequestStart::CompletedByPeer
        ));
        assert!(coalescer.is_empty());
    }

    #[test]
    fn timed_out_leader_can_be_superseded_without_removing_new_flight() {
        let coalescer = DnsRequestCoalescer::new(8, Duration::from_millis(40)).unwrap();
        let request_key = key("slow.example");
        let DnsRequestStart::Leader(old_guard) =
            coalescer.begin(request_key.clone(), || false)
        else {
            panic!("first request should become leader");
        };

        thread::sleep(Duration::from_millis(60));

        let DnsRequestStart::Leader(new_guard) =
            coalescer.begin(request_key.clone(), || false)
        else {
            panic!("expired flight should be replaced");
        };

        drop(old_guard);
        assert_eq!(coalescer.len(), 1);

        let other = coalescer.clone();
        let waiter = thread::spawn(move || other.begin(request_key, || false));
        thread::sleep(Duration::from_millis(20));
        drop(new_guard);

        assert!(matches!(
            waiter.join().unwrap(),
            DnsRequestStart::CompletedByPeer
        ));
        assert!(coalescer.is_empty());
    }

    #[test]
    fn cancelled_waiter_returns_without_finishing_the_leader() {
        let coalescer = DnsRequestCoalescer::new(8, Duration::from_secs(1)).unwrap();
        let request_key = key("cancel.example");
        let DnsRequestStart::Leader(_leader) =
            coalescer.begin(request_key.clone(), || false)
        else {
            panic!("first request should become leader");
        };

        assert!(matches!(
            coalescer.begin(request_key, || true),
            DnsRequestStart::Cancelled
        ));
        assert_eq!(coalescer.len(), 1);
    }

    #[test]
    fn full_registry_allows_an_untracked_leader() {
        let coalescer = DnsRequestCoalescer::new(1, Duration::from_secs(1)).unwrap();
        let DnsRequestStart::Leader(_first) =
            coalescer.begin(key("one.example"), || false)
        else {
            panic!("first request should be leader");
        };

        let DnsRequestStart::Leader(second) =
            coalescer.begin(key("two.example"), || false)
        else {
            panic!("full registry should allow untracked work");
        };

        assert_eq!(coalescer.len(), 1);
        drop(second);
        assert_eq!(coalescer.len(), 1);
    }
}
