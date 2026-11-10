use crate::dns_resolver::{
    DnsResolveOptions, DnsResolveResult, DnsResolver, DnsResolverError,
};
use std::{
    io,
    sync::{
        mpsc::{sync_channel, Receiver, SyncSender, TrySendError},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
};

const MAX_DNS_WORKERS: usize = 256;
const MAX_DNS_QUEUE_CAPACITY: usize = 1_000_000;

struct ResolveJob {
    query: Vec<u8>,
    options: DnsResolveOptions,
    reply: SyncSender<Result<DnsResolveResult, DnsResolverError>>,
}

/// Configuration errors for the bounded DNS worker service.
#[derive(Debug)]
pub enum DnsServiceError {
    ZeroWorkers,
    TooManyWorkers,
    ZeroQueueCapacity,
    QueueTooLarge,
    QueueFull,
    Disconnected,
    ThreadSpawn(io::Error),
}

impl std::fmt::Display for DnsServiceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZeroWorkers => formatter.write_str("DNS service requires at least one worker"),
            Self::TooManyWorkers => {
                write!(formatter, "DNS worker count exceeds {MAX_DNS_WORKERS}")
            }
            Self::ZeroQueueCapacity => {
                formatter.write_str("DNS service queue capacity must be greater than zero")
            }
            Self::QueueTooLarge => {
                write!(formatter, "DNS service queue capacity exceeds {MAX_DNS_QUEUE_CAPACITY}")
            }
            Self::QueueFull => formatter.write_str("DNS worker queue is full"),
            Self::Disconnected => formatter.write_str("DNS worker service is disconnected"),
            Self::ThreadSpawn(error) => write!(formatter, "could not start DNS worker: {error}"),
        }
    }
}

impl std::error::Error for DnsServiceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ThreadSpawn(error) => Some(error),
            _ => None,
        }
    }
}

/// Fixed-size worker pool for the synchronous DNS resolver.
///
/// The bounded queue provides explicit backpressure instead of creating one
/// OS thread per incoming DNS request. Each worker runs one resolver request
/// at a time. The service does not open a local DNS socket; the host service
/// supplies parsed requests and returns the receiver to its client handler.
pub struct DnsResolverService {
    sender: Option<SyncSender<ResolveJob>>,
    workers: Vec<JoinHandle<()>>,
    worker_count: usize,
    queue_capacity: usize,
}

impl DnsResolverService {
    /// Starts a fixed number of workers with a bounded waiting queue.
    pub fn new(
        resolver: Arc<DnsResolver>,
        worker_count: usize,
        queue_capacity: usize,
    ) -> Result<Self, DnsServiceError> {
        if worker_count == 0 {
            return Err(DnsServiceError::ZeroWorkers);
        }
        if worker_count > MAX_DNS_WORKERS {
            return Err(DnsServiceError::TooManyWorkers);
        }
        if queue_capacity == 0 {
            return Err(DnsServiceError::ZeroQueueCapacity);
        }
        if queue_capacity > MAX_DNS_QUEUE_CAPACITY {
            return Err(DnsServiceError::QueueTooLarge);
        }

        let (sender, receiver) = sync_channel::<ResolveJob>(queue_capacity);
        let receiver = Arc::new(Mutex::new(receiver));
        let mut workers = Vec::with_capacity(worker_count);

        for worker_index in 0..worker_count {
            let worker_receiver = Arc::clone(&receiver);
            let worker_resolver = Arc::clone(&resolver);
            let worker = thread::Builder::new()
                .name(format!("portmaster-dns-{worker_index}"))
                .spawn(move || loop {
                    let job = {
                        let Ok(receiver) = worker_receiver.lock() else {
                            break;
                        };
                        match receiver.recv() {
                            Ok(job) => job,
                            Err(_) => break,
                        }
                    };

                    let result = worker_resolver.resolve(&job.query, job.options);
                    let _ = job.reply.send(result);
                })
                .map_err(|error| {
                    drop(sender.clone());
                    DnsServiceError::ThreadSpawn(error)
                })?;

            workers.push(worker);
        }

        Ok(Self {
            sender: Some(sender),
            workers,
            worker_count,
            queue_capacity,
        })
    }

    /// Enqueues a DNS question without blocking.
    ///
    /// QueueFull means the caller should apply its upstream backpressure
    /// policy (for example, return a temporary failure) rather than spawning
    /// a separate thread or growing an unbounded request list.
    pub fn try_resolve(
        &self,
        query: &[u8],
        options: DnsResolveOptions,
    ) -> Result<Receiver<Result<DnsResolveResult, DnsResolverError>>, DnsServiceError> {
        let sender = self.sender.as_ref().ok_or(DnsServiceError::Disconnected)?;
        let (reply, response) = sync_channel(1);
        let job = ResolveJob {
            query: query.to_vec(),
            options,
            reply,
        };

        match sender.try_send(job) {
            Ok(()) => Ok(response),
            Err(TrySendError::Full(_)) => Err(DnsServiceError::QueueFull),
            Err(TrySendError::Disconnected(_)) => Err(DnsServiceError::Disconnected),
        }
    }

    #[must_use]
    pub const fn worker_count(&self) -> usize {
        self.worker_count
    }

    #[must_use]
    pub const fn queue_capacity(&self) -> usize {
        self.queue_capacity
    }

    /// Closes the queue and waits for active jobs to finish.
    pub fn shutdown(mut self) {
        self.stop();
    }

    fn stop(&mut self) {
        self.sender.take();
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}

impl Drop for DnsResolverService {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        dns_cache::{DnsCache, DnsCachePolicy},
        dns_coalescer::DnsRequestCoalescer,
        dns_query::{build_dns_query, DnsQueryOptions},
        dns_upstream::{DnsUpstreamClient, DnsUpstreamConfig},
    };
    use std::{
        io::{Read, Write},
        net::UdpSocket,
        sync::mpsc,
        time::Duration,
    };

    fn query() -> Vec<u8> {
        build_dns_query(
            "worker.example",
            1,
            0x5678,
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
        let flags = u16::from_be_bytes([response[2], response[3]]) | 0x8080;
        response[2..4].copy_from_slice(&flags.to_be_bytes());
        response[6..8].copy_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&120_u32.to_be_bytes());
        response.extend_from_slice(&4_u16.to_be_bytes());
        response.extend_from_slice(&[10, 20, 30, 40]);
        response
    }

    fn resolver(remote: std::net::SocketAddr) -> DnsResolver {
        let upstream = DnsUpstreamClient::new(
            remote,
            DnsUpstreamConfig {
                timeout: Duration::from_secs(2),
                attempts: 1,
                max_response_size: 4096,
                prefer_tcp: false,
                allow_tcp_fallback: true,
            },
        )
        .unwrap();
        DnsResolver::new(
            upstream,
            DnsCache::new(32, DnsCachePolicy::default()).unwrap(),
            DnsRequestCoalescer::new(32, Duration::from_secs(3)).unwrap(),
        )
    }

    #[test]
    fn rejects_zero_worker_or_queue_limits() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let resolver = Arc::new(resolver(socket.local_addr().unwrap()));

        assert!(matches!(
            DnsResolverService::new(Arc::clone(&resolver), 0, 1),
            Err(DnsServiceError::ZeroWorkers)
        ));
        assert!(matches!(
            DnsResolverService::new(Arc::clone(&resolver), 1, 0),
            Err(DnsServiceError::ZeroQueueCapacity)
        ));
    }

    #[test]
    fn worker_processes_dns_question_and_returns_result() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let remote = server.local_addr().unwrap();
        let server_thread = thread::spawn(move || {
            let mut request = [0_u8; 512];
            let (length, peer) = server.recv_from(&mut request).unwrap();
            let response = response_for(&request[..length]);
            server.send_to(&response, peer).unwrap();
        });

        let service = DnsResolverService::new(
            Arc::new(resolver(remote)),
            1,
            2,
        )
        .unwrap();
        let response = service
            .try_resolve(&query(), DnsResolveOptions::default())
            .unwrap()
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .unwrap();

        assert_eq!(response.source, crate::dns_resolver::DnsResolveSource::Upstream);
        assert_eq!(response.metadata.minimum_record_ttl_secs, Some(17));
        server_thread.join().unwrap();
    }

    #[test]
    fn queue_applies_backpressure_when_worker_is_busy() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let remote = server.local_addr().unwrap();
        let (received_tx, received_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();

        let server_thread = thread::spawn(move || {
            let mut request = [0_u8; 512];
            let (length, peer) = server.recv_from(&mut request).unwrap();
            received_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            let response = response_for(&request[..length]);
            server.send_to(&response, peer).unwrap();
        });

        let service = DnsResolverService::new(
            Arc::new(resolver(remote)),
            1,
            1,
        )
        .unwrap();
        let first = service
            .try_resolve(&query(), DnsResolveOptions::default())
            .unwrap();

        received_rx.recv_timeout(Duration::from_secs(1)).unwrap();

        let second = service
            .try_resolve(&query(), DnsResolveOptions::default())
            .unwrap();
        assert!(matches!(
            service.try_resolve(&query(), DnsResolveOptions::default()),
            Err(DnsServiceError::QueueFull)
        ));

        release_tx.send(()).unwrap();
        assert!(first.recv_timeout(Duration::from_secs(2)).unwrap().is_ok());
        assert!(second.recv_timeout(Duration::from_secs(2)).unwrap().is_ok());
        server_thread.join().unwrap();
    }
}
