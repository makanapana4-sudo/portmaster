use crate::dns_wire::{parse_dns_message, validate_dns_response, DnsWireError, DNS_HEADER_SIZE};
use std::{
    io::{self, Read, Write},
    net::{IpAddr, SocketAddr, TcpStream, UdpSocket},
    time::Duration,
};

const MAX_DNS_ATTEMPTS: usize = 16;
const MAX_DNS_PACKET_SIZE: usize = u16::MAX as usize;

/// Configuration for one upstream DNS endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsUpstreamConfig {
    pub timeout: Duration,
    pub attempts: usize,
    pub max_response_size: usize,
    pub prefer_tcp: bool,
    pub allow_tcp_fallback: bool,
}

impl Default for DnsUpstreamConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(2),
            attempts: 2,
            max_response_size: MAX_DNS_PACKET_SIZE,
            prefer_tcp: false,
            allow_tcp_fallback: true,
        }
    }
}

/// Errors returned by the UDP/TCP DNS upstream transport.
#[derive(Debug)]
pub enum DnsUpstreamError {
    InvalidTimeout,
    InvalidAttemptCount,
    InvalidResponseLimit,
    InvalidQuery,
    QueryTooLarge,
    ResponseTooLarge { length: usize, maximum: usize },
    TruncatedResponse,
    Timeout { attempts: usize },
    Io(io::Error),
    Wire(DnsWireError),
}

impl std::fmt::Display for DnsUpstreamError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidTimeout => formatter.write_str("DNS upstream timeout must be greater than zero"),
            Self::InvalidAttemptCount => write!(
                formatter,
                "DNS upstream attempts must be between 1 and {MAX_DNS_ATTEMPTS}"
            ),
            Self::InvalidResponseLimit => write!(
                formatter,
                "DNS upstream response limit must be between {DNS_HEADER_SIZE} and {MAX_DNS_PACKET_SIZE} bytes"
            ),
            Self::InvalidQuery => formatter.write_str("DNS upstream request must be a query with exactly one question"),
            Self::QueryTooLarge => formatter.write_str("DNS query exceeds the TCP length-prefix limit"),
            Self::ResponseTooLarge { length, maximum } => write!(
                formatter,
                "DNS upstream response is too large: {length} bytes (maximum {maximum})"
            ),
            Self::TruncatedResponse => formatter.write_str("DNS response remained truncated over TCP"),
            Self::Timeout { attempts } => {
                write!(formatter, "DNS upstream timed out after {attempts} attempts")
            }
            Self::Io(error) => write!(formatter, "DNS upstream I/O error: {error}"),
            Self::Wire(error) => write!(formatter, "invalid DNS upstream response: {error}"),
        }
    }
}

impl std::error::Error for DnsUpstreamError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Wire(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for DnsUpstreamError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<DnsWireError> for DnsUpstreamError {
    fn from(error: DnsWireError) -> Self {
        Self::Wire(error)
    }
}

/// Synchronous upstream client supporting DNS over UDP and TCP.
///
/// A new connected socket is created per exchange, isolating concurrent
/// requests and allowing the operating system to reject datagrams from
/// unexpected source addresses. Transaction IDs and questions are validated
/// before a response is returned.
#[derive(Debug, Clone)]
pub struct DnsUpstreamClient {
    remote: SocketAddr,
    config: DnsUpstreamConfig,
}

impl DnsUpstreamClient {
    pub fn new(
        remote: SocketAddr,
        config: DnsUpstreamConfig,
    ) -> Result<Self, DnsUpstreamError> {
        if config.timeout.is_zero() || std::time::Instant::now().checked_add(config.timeout).is_none() {
            return Err(DnsUpstreamError::InvalidTimeout);
        }
        if config.attempts == 0 || config.attempts > MAX_DNS_ATTEMPTS {
            return Err(DnsUpstreamError::InvalidAttemptCount);
        }
        if !(DNS_HEADER_SIZE..=MAX_DNS_PACKET_SIZE).contains(&config.max_response_size) {
            return Err(DnsUpstreamError::InvalidResponseLimit);
        }

        Ok(Self { remote, config })
    }

    #[must_use]
    pub const fn remote(&self) -> SocketAddr {
        self.remote
    }

    #[must_use]
    pub const fn config(&self) -> DnsUpstreamConfig {
        self.config
    }

    /// Exchanges a validated single-question DNS query with the configured
    /// upstream. UDP is retried on timeout; a truncated response can fall back
    /// to TCP using the same endpoint.
    pub fn exchange(&self, query: &[u8]) -> Result<Vec<u8>, DnsUpstreamError> {
        let query_metadata = parse_dns_message(query)?;
        if query_metadata.is_response() || query_metadata.question_count != 1 {
            return Err(DnsUpstreamError::InvalidQuery);
        }

        if self.config.prefer_tcp {
            return self.exchange_tcp(query);
        }

        self.exchange_udp(query, &query_metadata)
    }

    fn exchange_udp(
        &self,
        query: &[u8],
        query_metadata: &crate::dns_wire::DnsMessageMetadata,
    ) -> Result<Vec<u8>, DnsUpstreamError> {
        let bind_address = match self.remote.ip() {
            IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0),
            IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0),
        };

        let socket = UdpSocket::bind(bind_address)?;
        socket.connect(self.remote)?;
        socket.set_read_timeout(Some(self.config.timeout))?;
        socket.set_write_timeout(Some(self.config.timeout))?;

        let mut response_buffer = vec![0_u8; self.config.max_response_size + 1];

        for _ in 0..self.config.attempts {
            let written = socket.send(query)?;
            if written != query.len() {
                return Err(DnsUpstreamError::Io(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "partial UDP DNS datagram send",
                )));
            }

            match socket.recv(&mut response_buffer) {
                Ok(length) => {
                    if length > self.config.max_response_size {
                        return Err(DnsUpstreamError::ResponseTooLarge {
                            length,
                            maximum: self.config.max_response_size,
                        });
                    }
                    let response = &response_buffer[..length];

                    if is_truncated_datagram(response, query_metadata.id) {
                        if self.config.allow_tcp_fallback {
                            return self.exchange_tcp(query);
                        }
                        return Err(DnsUpstreamError::TruncatedResponse);
                    }

                    let metadata = validate_dns_response(query, response)?;
                    if metadata.is_truncated() {
                        if self.config.allow_tcp_fallback {
                            return self.exchange_tcp(query);
                        }
                        return Err(DnsUpstreamError::TruncatedResponse);
                    }

                    return Ok(response.to_vec());
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                    ) =>
                {
                    // Try the next attempt on the same connected socket.
                }
                Err(error) => return Err(DnsUpstreamError::Io(error)),
            }
        }

        Err(DnsUpstreamError::Timeout {
            attempts: self.config.attempts,
        })
    }

    fn exchange_tcp(&self, query: &[u8]) -> Result<Vec<u8>, DnsUpstreamError> {
        let mut stream = TcpStream::connect_timeout(&self.remote, self.config.timeout)?;
        stream.set_read_timeout(Some(self.config.timeout))?;
        stream.set_write_timeout(Some(self.config.timeout))?;
        self.exchange_over_tcp_stream(query, &mut stream)
    }

    /// Performs one DNS-over-TCP exchange on an existing stream.
    ///
    /// The stream can be a plain TCP connection or an authenticated TLS
    /// stream supplied by a future DNS-over-TLS integration. The caller owns
    /// connection setup, peer authentication and stream timeouts.
    pub fn exchange_over_tcp_stream<S: Read + Write>(
        &self,
        query: &[u8],
        stream: &mut S,
    ) -> Result<Vec<u8>, DnsUpstreamError> {
        let query_metadata = parse_dns_message(query)?;
        if query_metadata.is_response() || query_metadata.question_count != 1 {
            return Err(DnsUpstreamError::InvalidQuery);
        }

        let query_length =
            u16::try_from(query.len()).map_err(|_| DnsUpstreamError::QueryTooLarge)?;
        stream.write_all(&query_length.to_be_bytes())?;
        stream.write_all(query)?;

        let mut response_length = [0_u8; 2];
        stream.read_exact(&mut response_length)?;
        let response_length = usize::from(u16::from_be_bytes(response_length));

        if response_length < DNS_HEADER_SIZE {
            return Err(DnsUpstreamError::Wire(DnsWireError::TruncatedHeader));
        }
        if response_length > self.config.max_response_size {
            return Err(DnsUpstreamError::ResponseTooLarge {
                length: response_length,
                maximum: self.config.max_response_size,
            });
        }

        let mut response = vec![0_u8; response_length];
        stream.read_exact(&mut response)?;

        let metadata = validate_dns_response(query, &response)?;
        if metadata.is_truncated() {
            return Err(DnsUpstreamError::TruncatedResponse);
        }

        Ok(response)
    }}

fn is_truncated_datagram(response: &[u8], expected_id: u16) -> bool {
    if response.len() < 4 {
        return false;
    }

    let id = u16::from_be_bytes([response[0], response[1]]);
    let flags = u16::from_be_bytes([response[2], response[3]]);
    id == expected_id && flags & 0x0200 != 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns_query::{build_dns_query, DnsQueryOptions};
    use std::{
        net::{TcpListener, UdpSocket},
        thread,
        time::Duration,
    };

    fn query() -> Vec<u8> {
        build_dns_query(
            "example.com",
            1,
            0x4321,
            DnsQueryOptions {
                recursion_desired: true,
                udp_payload_size: None,
                dnssec_ok: false,
            },
        )
        .unwrap()
    }

    fn response_for(query: &[u8], truncated: bool) -> Vec<u8> {
        let mut response = query.to_vec();
        let mut flags = u16::from_be_bytes([response[2], response[3]]);
        flags |= 0x8080;
        if truncated {
            flags |= 0x0200;
        }
        response[2..4].copy_from_slice(&flags.to_be_bytes());
        response
    }

    fn test_config() -> DnsUpstreamConfig {
        DnsUpstreamConfig {
            timeout: Duration::from_millis(500),
            attempts: 1,
            max_response_size: 4096,
            prefer_tcp: false,
            allow_tcp_fallback: true,
        }
    }

    #[test]
    fn rejects_invalid_configuration() {
        let remote = "127.0.0.1:53".parse().unwrap();

        assert!(matches!(
            DnsUpstreamClient::new(
                remote,
                DnsUpstreamConfig {
                    timeout: Duration::ZERO,
                    ..test_config()
                }
            ),
            Err(DnsUpstreamError::InvalidTimeout)
        ));
        assert!(matches!(
            DnsUpstreamClient::new(
                remote,
                DnsUpstreamConfig {
                    attempts: 0,
                    ..test_config()
                }
            ),
            Err(DnsUpstreamError::InvalidAttemptCount)
        ));
    }

    #[test]
    fn exchanges_a_response_over_connected_udp() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let remote = server.local_addr().unwrap();
        let server_thread = thread::spawn(move || {
            let mut buffer = [0_u8; 512];
            let (length, source) = server.recv_from(&mut buffer).unwrap();
            let response = response_for(&buffer[..length], false);
            server.send_to(&response, source).unwrap();
        });

        let client = DnsUpstreamClient::new(remote, test_config()).unwrap();
        let query = query();
        let response = client.exchange(&query).unwrap();
        validate_dns_response(&query, &response).unwrap();
        server_thread.join().unwrap();
    }

    #[test]
    fn falls_back_to_tcp_for_truncated_udp_response() {
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let remote = udp.local_addr().unwrap();
        let tcp = TcpListener::bind(remote).unwrap();

        let server_thread = thread::spawn(move || {
            let mut buffer = [0_u8; 512];
            let (length, source) = udp.recv_from(&mut buffer).unwrap();
            let truncated = response_for(&buffer[..length], true);
            udp.send_to(&truncated, source).unwrap();

            let (mut stream, _) = tcp.accept().unwrap();
            let mut query_length = [0_u8; 2];
            stream.read_exact(&mut query_length).unwrap();
            let mut query = vec![0; usize::from(u16::from_be_bytes(query_length))];
            stream.read_exact(&mut query).unwrap();

            let response = response_for(&query, false);
            stream
                .write_all(&(response.len() as u16).to_be_bytes())
                .unwrap();
            stream.write_all(&response).unwrap();
        });

        let client = DnsUpstreamClient::new(remote, test_config()).unwrap();
        let query = query();
        let response = client.exchange(&query).unwrap();
        validate_dns_response(&query, &response).unwrap();
        server_thread.join().unwrap();
    }

    struct BufferedStream {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
    }

    impl Read for BufferedStream {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            self.input.read(output)
        }
    }

    impl Write for BufferedStream {
        fn write(&mut self, input: &[u8]) -> io::Result<usize> {
            self.output.extend_from_slice(input);
            Ok(input.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn tcp_exchange_can_use_an_existing_stream() {
        let query_packet = query();
        let response = response_for(&query_packet, false);
        let mut input = Vec::new();
        input.extend_from_slice(&(response.len() as u16).to_be_bytes());
        input.extend_from_slice(&response);
        let mut stream = BufferedStream {
            input: Cursor::new(input),
            output: Vec::new(),
        };
        let client = DnsUpstreamClient::new(
            "127.0.0.1:53".parse().unwrap(),
            test_config(),
        )
        .unwrap();

        let received = client
            .exchange_over_tcp_stream(&query_packet, &mut stream)
            .unwrap();

        assert_eq!(received, response);
        assert_eq!(
            &stream.output[..2],
            &(query_packet.len() as u16).to_be_bytes()
        );
        assert_eq!(&stream.output[2..], query_packet.as_slice());
    }

    #[test]
    fn rejects_a_response_with_the_wrong_transaction_id() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let remote = server.local_addr().unwrap();
        let server_thread = thread::spawn(move || {
            let mut buffer = [0_u8; 512];
            let (length, source) = server.recv_from(&mut buffer).unwrap();
            let mut response = response_for(&buffer[..length], false);
            response[0] ^= 0xff;
            server.send_to(&response, source).unwrap();
        });

        let client = DnsUpstreamClient::new(remote, test_config()).unwrap();
        assert!(matches!(
            client.exchange(&query()),
            Err(DnsUpstreamError::Wire(
                DnsWireError::TransactionIdMismatch
            ))
        ));
        server_thread.join().unwrap();
    }

    #[test]
    fn retries_a_timed_out_udp_exchange() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let remote = server.local_addr().unwrap();
        let server_thread = thread::spawn(move || {
            let mut buffer = [0_u8; 512];
            let (length, source) = server.recv_from(&mut buffer).unwrap();
            assert!(length > DNS_HEADER_SIZE);

            let (length, source) = server.recv_from(&mut buffer).unwrap();
            let response = response_for(&buffer[..length], false);
            server.send_to(&response, source).unwrap();
        });

        let client = DnsUpstreamClient::new(
            remote,
            DnsUpstreamConfig {
                timeout: Duration::from_millis(40),
                attempts: 2,
                ..test_config()
            },
        )
        .unwrap();

        let query = query();
        let response = client.exchange(&query).unwrap();
        validate_dns_response(&query, &response).unwrap();
        server_thread.join().unwrap();
    }
}
