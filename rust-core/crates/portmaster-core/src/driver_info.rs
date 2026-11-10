use crate::driver_protocol::{
    parse_info_frame, InfoFrame, InfoKind, ProtocolError, DEFAULT_MAX_INFO_PAYLOAD,
};

const IPV4_BANDWIDTH_RECORD_SIZE: usize = 28;
const IPV6_BANDWIDTH_RECORD_SIZE: usize = 52;

/// A decoded IPv4 connection event. Packet bytes remain borrowed from the frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionInfoV4<'a> {
    pub id: u64,
    pub process_id: u64,
    pub direction: u8,
    pub protocol: u8,
    pub local_address: [u8; 4],
    pub remote_address: [u8; 4],
    pub local_port: u16,
    pub remote_port: u16,
    pub payload_layer: u8,
    pub packet_payload: &'a [u8],
}

/// A decoded IPv6 connection event. Packet bytes remain borrowed from the frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionInfoV6<'a> {
    pub id: u64,
    pub process_id: u64,
    pub direction: u8,
    pub protocol: u8,
    pub local_address: [u8; 16],
    pub remote_address: [u8; 16],
    pub local_port: u16,
    pub remote_port: u16,
    pub payload_layer: u8,
    pub packet_payload: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionEndV4 {
    pub process_id: u64,
    pub direction: u8,
    pub protocol: u8,
    pub local_address: [u8; 4],
    pub remote_address: [u8; 4],
    pub local_port: u16,
    pub remote_port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionEndV6 {
    pub process_id: u64,
    pub direction: u8,
    pub protocol: u8,
    pub local_address: [u8; 16],
    pub remote_address: [u8; 16],
    pub local_port: u16,
    pub remote_port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BandwidthValueV4 {
    pub local_address: [u8; 4],
    pub local_port: u16,
    pub remote_address: [u8; 4],
    pub remote_port: u16,
    pub transmitted_bytes: u64,
    pub received_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BandwidthValueV6 {
    pub local_address: [u8; 16],
    pub local_port: u16,
    pub remote_address: [u8; 16],
    pub remote_port: u16,
    pub transmitted_bytes: u64,
    pub received_bytes: u64,
}

/// A borrowed view over the fixed-size IPv4 bandwidth records in a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BandwidthStatsV4<'a> {
    pub protocol: u8,
    records: &'a [u8],
    count: usize,
}

impl BandwidthStatsV4<'_> {
    #[must_use]
    pub const fn len(&self) -> usize {
        self.count
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    #[must_use]
    pub fn get(&self, index: usize) -> Option<BandwidthValueV4> {
        if index >= self.count {
            return None;
        }

        let start = index.checked_mul(IPV4_BANDWIDTH_RECORD_SIZE)?;
        let end = start.checked_add(IPV4_BANDWIDTH_RECORD_SIZE)?;
        let mut reader = SliceReader::new(self.records.get(start..end)?);

        Some(BandwidthValueV4 {
            local_address: reader.array().ok()?,
            local_port: reader.u16().ok()?,
            remote_address: reader.array().ok()?,
            remote_port: reader.u16().ok()?,
            transmitted_bytes: reader.u64().ok()?,
            received_bytes: reader.u64().ok()?,
        })
    }

    pub fn iter(&self) -> impl Iterator<Item = BandwidthValueV4> + '_ {
        (0..self.count).filter_map(|index| self.get(index))
    }
}

/// A borrowed view over the fixed-size IPv6 bandwidth records in a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BandwidthStatsV6<'a> {
    pub protocol: u8,
    records: &'a [u8],
    count: usize,
}

impl BandwidthStatsV6<'_> {
    #[must_use]
    pub const fn len(&self) -> usize {
        self.count
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    #[must_use]
    pub fn get(&self, index: usize) -> Option<BandwidthValueV6> {
        if index >= self.count {
            return None;
        }

        let start = index.checked_mul(IPV6_BANDWIDTH_RECORD_SIZE)?;
        let end = start.checked_add(IPV6_BANDWIDTH_RECORD_SIZE)?;
        let mut reader = SliceReader::new(self.records.get(start..end)?);

        Some(BandwidthValueV6 {
            local_address: reader.array().ok()?,
            local_port: reader.u16().ok()?,
            remote_address: reader.array().ok()?,
            remote_port: reader.u16().ok()?,
            transmitted_bytes: reader.u64().ok()?,
            received_bytes: reader.u64().ok()?,
        })
    }

    pub fn iter(&self) -> impl Iterator<Item = BandwidthValueV6> + '_ {
        (0..self.count).filter_map(|index| self.get(index))
    }
}

/// Fully decoded driver message. Packet data and record arrays borrow the
/// original input frame, so parsing does not copy large payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverInfo<'a> {
    LogLine {
        severity: u8,
        message: &'a [u8],
    },
    ConnectionV4(ConnectionInfoV4<'a>),
    ConnectionV6(ConnectionInfoV6<'a>),
    ConnectionEndV4(ConnectionEndV4),
    ConnectionEndV6(ConnectionEndV6),
    BandwidthV4(BandwidthStatsV4<'a>),
    BandwidthV6(BandwidthStatsV6<'a>),
}

/// Parses and decodes one complete frame using the default 16 MiB size limit.
pub fn parse_driver_info_frame(
    input: &[u8],
) -> Result<(DriverInfo<'_>, usize), ProtocolError> {
    let (frame, consumed) = parse_info_frame(input, DEFAULT_MAX_INFO_PAYLOAD)?;
    let info = parse_driver_info(frame)?;
    Ok((info, consumed))
}

/// Decodes a frame produced by the existing Windows driver protocol.

/// The function validates each fixed-size field and each advertised payload
/// length. Variable-length packet bytes and bandwidth records are borrowed
/// from the original frame rather than copied into new allocations.
pub fn parse_driver_info<'a>(
    frame: InfoFrame<'a>,
) -> Result<DriverInfo<'a>, ProtocolError> {
    let mut reader = SliceReader::new(frame.payload);

    match frame.kind {
        InfoKind::LogLine => {
            let severity = reader.u8()?;
            let message = reader.remaining();
            Ok(DriverInfo::LogLine { severity, message })
        }
        InfoKind::ConnectionIpv4 => {
            let id = reader.u64()?;
            let process_id = reader.u64()?;
            let direction = reader.u8()?;
            let protocol = reader.u8()?;
            let local_address = reader.array()?;
            let remote_address = reader.array()?;
            let local_port = reader.u16()?;
            let remote_port = reader.u16()?;
            let payload_layer = reader.u8()?;
            let payload_len = reader.u32()? as usize;
            let packet_payload = reader.take(payload_len)?;

            Ok(DriverInfo::ConnectionV4(ConnectionInfoV4 {
                id,
                process_id,
                direction,
                protocol,
                local_address,
                remote_address,
                local_port,
                remote_port,
                payload_layer,
                packet_payload,
            }))
        }
        InfoKind::ConnectionIpv6 => {
            let id = reader.u64()?;
            let process_id = reader.u64()?;
            let direction = reader.u8()?;
            let protocol = reader.u8()?;
            let local_address = reader.array()?;
            let remote_address = reader.array()?;
            let local_port = reader.u16()?;
            let remote_port = reader.u16()?;
            let payload_layer = reader.u8()?;
            let payload_len = reader.u32()? as usize;
            let packet_payload = reader.take(payload_len)?;

            Ok(DriverInfo::ConnectionV6(ConnectionInfoV6 {
                id,
                process_id,
                direction,
                protocol,
                local_address,
                remote_address,
                local_port,
                remote_port,
                payload_layer,
                packet_payload,
            }))
        }
        InfoKind::ConnectionEndV4 => Ok(DriverInfo::ConnectionEndV4(ConnectionEndV4 {
            process_id: reader.u64()?,
            direction: reader.u8()?,
            protocol: reader.u8()?,
            local_address: reader.array()?,
            remote_address: reader.array()?,
            local_port: reader.u16()?,
            remote_port: reader.u16()?,
        })),
        InfoKind::ConnectionEndV6 => Ok(DriverInfo::ConnectionEndV6(ConnectionEndV6 {
            process_id: reader.u64()?,
            direction: reader.u8()?,
            protocol: reader.u8()?,
            local_address: reader.array()?,
            remote_address: reader.array()?,
            local_port: reader.u16()?,
            remote_port: reader.u16()?,
        })),
        InfoKind::BandwidthStatsV4 => {
            let protocol = reader.u8()?;
            let count = reader.u32()? as usize;
            let byte_count = count
                .checked_mul(IPV4_BANDWIDTH_RECORD_SIZE)
                .ok_or(ProtocolError::LengthOverflow)?;
            let records = reader.take(byte_count)?;

            Ok(DriverInfo::BandwidthV4(BandwidthStatsV4 {
                protocol,
                records,
                count,
            }))
        }
        InfoKind::BandwidthStatsV6 => {
            let protocol = reader.u8()?;
            let count = reader.u32()? as usize;
            let byte_count = count
                .checked_mul(IPV6_BANDWIDTH_RECORD_SIZE)
                .ok_or(ProtocolError::LengthOverflow)?;
            let records = reader.take(byte_count)?;

            Ok(DriverInfo::BandwidthV6(BandwidthStatsV6 {
                protocol,
                records,
                count,
            }))
        }
    }
}

struct SliceReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> SliceReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], ProtocolError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(ProtocolError::LengthOverflow)?;

        if end > self.bytes.len() {
            return Err(ProtocolError::TruncatedPayload {
                expected: length,
                available: self.bytes.len().saturating_sub(self.offset),
            });
        }

        let output = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(output)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ProtocolError> {
        let bytes = self.take(N)?;
        let mut output = [0; N];
        output.copy_from_slice(bytes);
        Ok(output)
    }

    fn u8(&mut self) -> Result<u8, ProtocolError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, ProtocolError> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, ProtocolError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, ProtocolError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn remaining(&self) -> &'a [u8] {
        &self.bytes[self.offset..]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_u16(bytes: &mut Vec<u8>, value: u16) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn push_u32(bytes: &mut Vec<u8>, value: u32) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn push_u64(bytes: &mut Vec<u8>, value: u64) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn frame(kind: InfoKind, payload: &[u8]) -> InfoFrame<'_> {
        InfoFrame { kind, payload }
    }

    #[test]
    fn decodes_ipv4_connection_and_borrows_packet_payload() {
        let mut bytes = Vec::new();
        push_u64(&mut bytes, 7);
        push_u64(&mut bytes, 42);
        bytes.extend_from_slice(&[1, 6]);
        bytes.extend_from_slice(&[10, 0, 0, 1]);
        bytes.extend_from_slice(&[1, 1, 1, 1]);
        push_u16(&mut bytes, 1234);
        push_u16(&mut bytes, 443);
        bytes.push(2);
        push_u32(&mut bytes, 3);
        bytes.extend_from_slice(&[9, 8, 7]);

        let parsed = parse_driver_info(frame(InfoKind::ConnectionIpv4, &bytes)).unwrap();
        let DriverInfo::ConnectionV4(connection) = parsed else {
            panic!("expected IPv4 connection");
        };

        assert_eq!(connection.id, 7);
        assert_eq!(connection.process_id, 42);
        assert_eq!(connection.direction, 1);
        assert_eq!(connection.protocol, 6);
        assert_eq!(connection.local_address, [10, 0, 0, 1]);
        assert_eq!(connection.remote_address, [1, 1, 1, 1]);
        assert_eq!(connection.local_port, 1234);
        assert_eq!(connection.remote_port, 443);
        assert_eq!(connection.payload_layer, 2);
        assert_eq!(connection.packet_payload, &[9, 8, 7]);
        assert!(std::ptr::eq(connection.packet_payload.as_ptr(), bytes[35..].as_ptr()));
    }

    #[test]
    fn decodes_ipv6_connection() {
        let mut bytes = Vec::new();
        push_u64(&mut bytes, 11);
        push_u64(&mut bytes, 99);
        bytes.extend_from_slice(&[0, 17]);
        bytes.extend_from_slice(&[1; 16]);
        bytes.extend_from_slice(&[2; 16]);
        push_u16(&mut bytes, 53);
        push_u16(&mut bytes, 5353);
        bytes.push(4);
        push_u32(&mut bytes, 0);

        let parsed = parse_driver_info(frame(InfoKind::ConnectionIpv6, &bytes)).unwrap();
        let DriverInfo::ConnectionV6(connection) = parsed else {
            panic!("expected IPv6 connection");
        };

        assert_eq!(connection.id, 11);
        assert_eq!(connection.process_id, 99);
        assert_eq!(connection.local_address, [1; 16]);
        assert_eq!(connection.remote_address, [2; 16]);
        assert_eq!(connection.packet_payload, &[]);
    }

    #[test]
    fn decodes_connection_end_events() {
        let mut v4 = Vec::new();
        push_u64(&mut v4, 5);
        v4.extend_from_slice(&[1, 6, 10, 0, 0, 1, 1, 1, 1, 1]);
        push_u16(&mut v4, 1000);
        push_u16(&mut v4, 443);

        let parsed = parse_driver_info(frame(InfoKind::ConnectionEndV4, &v4)).unwrap();
        let DriverInfo::ConnectionEndV4(end) = parsed else {
            panic!("expected IPv4 connection end");
        };
        assert_eq!(end.process_id, 5);
        assert_eq!(end.local_address, [10, 0, 0, 1]);
        assert_eq!(end.remote_address, [1, 1, 1, 1]);

        let mut v6 = Vec::new();
        push_u64(&mut v6, 6);
        v6.extend_from_slice(&[0, 17]);
        v6.extend_from_slice(&[3; 16]);
        v6.extend_from_slice(&[4; 16]);
        push_u16(&mut v6, 2000);
        push_u16(&mut v6, 5353);

        let parsed = parse_driver_info(frame(InfoKind::ConnectionEndV6, &v6)).unwrap();
        let DriverInfo::ConnectionEndV6(end) = parsed else {
            panic!("expected IPv6 connection end");
        };
        assert_eq!(end.process_id, 6);
        assert_eq!(end.local_address, [3; 16]);
        assert_eq!(end.remote_address, [4; 16]);
    }

    #[test]
    fn decodes_log_line_without_copying_message() {
        let bytes = [3, b'o', b'k'];
        let parsed = parse_driver_info(frame(InfoKind::LogLine, &bytes)).unwrap();
        let DriverInfo::LogLine { severity, message } = parsed else {
            panic!("expected log line");
        };

        assert_eq!(severity, 3);
        assert_eq!(message, b"ok");
        assert!(std::ptr::eq(message.as_ptr(), bytes[1..].as_ptr()));
    }

    #[test]
    fn exposes_bandwidth_records_without_allocating_a_second_record_array() {
        let mut bytes = Vec::new();
        bytes.push(6);
        push_u32(&mut bytes, 1);
        bytes.extend_from_slice(&[10, 0, 0, 1]);
        push_u16(&mut bytes, 1234);
        bytes.extend_from_slice(&[1, 1, 1, 1]);
        push_u16(&mut bytes, 443);
        push_u64(&mut bytes, 100);
        push_u64(&mut bytes, 200);

        let parsed = parse_driver_info(frame(InfoKind::BandwidthStatsV4, &bytes)).unwrap();
        let DriverInfo::BandwidthV4(stats) = parsed else {
            panic!("expected IPv4 bandwidth stats");
        };

        assert_eq!(stats.protocol, 6);
        assert_eq!(stats.len(), 1);
        assert_eq!(
            stats.get(0),
            Some(BandwidthValueV4 {
                local_address: [10, 0, 0, 1],
                local_port: 1234,
                remote_address: [1, 1, 1, 1],
                remote_port: 443,
                transmitted_bytes: 100,
                received_bytes: 200,
            })
        );
        assert_eq!(stats.get(1), None);
    }

    #[test]
    fn decodes_ipv6_bandwidth_records() {
        let mut bytes = Vec::new();
        bytes.push(17);
        push_u32(&mut bytes, 1);
        bytes.extend_from_slice(&[1; 16]);
        push_u16(&mut bytes, 5353);
        bytes.extend_from_slice(&[2; 16]);
        push_u16(&mut bytes, 443);
        push_u64(&mut bytes, 300);
        push_u64(&mut bytes, 400);

        let parsed = parse_driver_info(frame(InfoKind::BandwidthStatsV6, &bytes)).unwrap();
        let DriverInfo::BandwidthV6(stats) = parsed else {
            panic!("expected IPv6 bandwidth stats");
        };

        assert_eq!(stats.protocol, 17);
        assert_eq!(stats.len(), 1);
        assert_eq!(
            stats.get(0),
            Some(BandwidthValueV6 {
                local_address: [1; 16],
                local_port: 5353,
                remote_address: [2; 16],
                remote_port: 443,
                transmitted_bytes: 300,
                received_bytes: 400,
            })
        );
    }

    #[test]
    fn parses_and_decodes_a_complete_frame_with_default_limit() {
        let bytes = [InfoKind::LogLine as u8, 2, 0, 0, 0, 3, b'o'];

        let (parsed, consumed) = parse_driver_info_frame(&bytes).unwrap();
        let DriverInfo::LogLine { severity, message } = parsed else {
            panic!("expected log line");
        };

        assert_eq!(severity, 3);
        assert_eq!(message, b"o");
        assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn default_frame_parser_rejects_oversized_payloads() {
        let mut header = [0; 5];
        header[0] = InfoKind::LogLine as u8;
        header[1..5].copy_from_slice(&((DEFAULT_MAX_INFO_PAYLOAD as u32) + 1).to_le_bytes());

        assert_eq!(
            parse_driver_info_frame(&header).err(),
            Some(ProtocolError::PayloadTooLarge {
                length: DEFAULT_MAX_INFO_PAYLOAD + 1,
                maximum: DEFAULT_MAX_INFO_PAYLOAD,
            })
        );
    }

    #[test]
    fn accepts_empty_bandwidth_arrays() {
        let bytes = [6, 0, 0, 0, 0];
        let parsed = parse_driver_info(frame(InfoKind::BandwidthStatsV4, &bytes)).unwrap();
        let DriverInfo::BandwidthV4(stats) = parsed else {
            panic!("expected IPv4 bandwidth stats");
        };
        assert_eq!(stats.len(), 0);
        assert!(stats.is_empty());
        assert_eq!(stats.iter().count(), 0);

        let parsed = parse_driver_info(frame(InfoKind::BandwidthStatsV6, &bytes)).unwrap();
        let DriverInfo::BandwidthV6(stats) = parsed else {
            panic!("expected IPv6 bandwidth stats");
        };
        assert_eq!(stats.len(), 0);
        assert!(stats.is_empty());
        assert_eq!(stats.iter().count(), 0);
    }

    #[test]
    fn rejects_bandwidth_count_that_exceeds_the_frame() {
        let bytes = [6, 0xff, 0xff, 0xff, 0xff];
        assert!(matches!(
            parse_driver_info(frame(InfoKind::BandwidthStatsV6, &bytes)),
            Err(ProtocolError::TruncatedPayload { .. }) | Err(ProtocolError::LengthOverflow)
        ));
    }

    #[test]
    fn rejects_truncated_fixed_fields_and_payload_lengths() {
        assert!(matches!(
            parse_driver_info(frame(InfoKind::ConnectionEndV4, &[0; 4])),
            Err(ProtocolError::TruncatedPayload { .. })
        ));

        let mut bytes = Vec::new();
        push_u64(&mut bytes, 1);
        push_u64(&mut bytes, 2);
        bytes.extend_from_slice(&[0, 6]);
        bytes.extend_from_slice(&[0; 8]);
        push_u16(&mut bytes, 80);
        push_u16(&mut bytes, 443);
        bytes.push(1);
        push_u32(&mut bytes, 100);

        assert!(matches!(
            parse_driver_info(frame(InfoKind::ConnectionIpv4, &bytes)),
            Err(ProtocolError::TruncatedPayload { .. })
        ));
    }
}
