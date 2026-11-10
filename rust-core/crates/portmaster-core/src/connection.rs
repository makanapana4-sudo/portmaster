use std::net::IpAddr;

/// Transport protocol associated with a network connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NetworkProtocol {
    Tcp,
    Udp,
}

/// Stable key for identifying a network connection in core-owned state.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConnectionKey {
    pub protocol: NetworkProtocol,
    pub local_address: IpAddr,
    pub local_port: u16,
    pub remote_address: IpAddr,
    pub remote_port: u16,
}

impl ConnectionKey {
    #[must_use]
    pub const fn new(
        protocol: NetworkProtocol,
        local_address: IpAddr,
        local_port: u16,
        remote_address: IpAddr,
        remote_port: u16,
    ) -> Self {
        Self {
            protocol,
            local_address,
            local_port,
            remote_address,
            remote_port,
        }
    }

    #[must_use]
    pub const fn is_loopback(&self) -> bool {
        self.local_address.is_loopback() && self.remote_address.is_loopback()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn connection_keys_compare_by_all_fields() {
        let address = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let first = ConnectionKey::new(NetworkProtocol::Tcp, address, 10, address, 20);
        let second = ConnectionKey::new(NetworkProtocol::Tcp, address, 10, address, 21);

        assert_ne!(first, second);
    }

    #[test]
    fn loopback_requires_both_endpoints_to_be_loopback() {
        let local = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let remote = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let key = ConnectionKey::new(NetworkProtocol::Udp, local, 53, remote, 53);

        assert!(key.is_loopback());
    }

    #[test]
    fn external_remote_address_is_not_loopback() {
        let local = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let remote = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let key = ConnectionKey::new(NetworkProtocol::Tcp, local, 1234, remote, 443);

        assert!(!key.is_loopback());
    }
}
