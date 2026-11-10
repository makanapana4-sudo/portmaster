use protocol::{command::CommandType, info::InfoType as DriverInfoType};
use std::convert::TryFrom;

/// Maximum payload accepted by the default driver-info parser.
pub const DEFAULT_MAX_INFO_PAYLOAD: usize = 16 * 1024 * 1024;

/// Message kinds emitted by the existing Windows kernel driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum InfoKind {
    LogLine = 0,
    ConnectionIpv4 = 1,
    ConnectionIpv6 = 2,
    ConnectionEndV4 = 3,
    ConnectionEndV6 = 4,
    BandwidthStatsV4 = 5,
    BandwidthStatsV6 = 6,
}

const INFO_LOG_LINE: u8 = DriverInfoType::LogLine as u8;
const INFO_CONNECTION_IPV4: u8 = DriverInfoType::ConnectionIpv4 as u8;
const INFO_CONNECTION_IPV6: u8 = DriverInfoType::ConnectionIpv6 as u8;
const INFO_CONNECTION_END_V4: u8 = DriverInfoType::ConnectionEndEventV4 as u8;
const INFO_CONNECTION_END_V6: u8 = DriverInfoType::ConnectionEndEventV6 as u8;
const INFO_BANDWIDTH_STATS_V4: u8 = DriverInfoType::BandwidthStatsV4 as u8;
const INFO_BANDWIDTH_STATS_V6: u8 = DriverInfoType::BandwidthStatsV6 as u8;

impl TryFrom<u8> for InfoKind {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            INFO_LOG_LINE => Ok(Self::LogLine),
            INFO_CONNECTION_IPV4 => Ok(Self::ConnectionIpv4),
            INFO_CONNECTION_IPV6 => Ok(Self::ConnectionIpv6),
            INFO_CONNECTION_END_V4 => Ok(Self::ConnectionEndV4),
            INFO_CONNECTION_END_V6 => Ok(Self::ConnectionEndV6),
            INFO_BANDWIDTH_STATS_V4 => Ok(Self::BandwidthStatsV4),
            INFO_BANDWIDTH_STATS_V6 => Ok(Self::BandwidthStatsV6),
            other => Err(ProtocolError::UnknownInfoType(other)),
        }
    }
}

/// Errors raised while validating a driver protocol frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolError {
    TruncatedHeader,
    TruncatedPayload { expected: usize, available: usize },
    PayloadTooLarge { length: usize, maximum: usize },
    LengthOverflow,
    UnknownInfoType(u8),
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TruncatedHeader => formatter.write_str("driver info header is incomplete"),
            Self::TruncatedPayload {
                expected,
                available,
            } => write!(
                formatter,
                "driver info payload is truncated: expected {expected} bytes, got {available}"
            ),
            Self::PayloadTooLarge { length, maximum } => write!(
                formatter,
                "driver info payload is too large: {length} bytes exceeds {maximum}"
            ),
            Self::LengthOverflow => formatter.write_str("driver info frame length overflowed"),
            Self::UnknownInfoType(value) => write!(formatter, "unknown driver info type: {value}"),
        }
    }
}

impl std::error::Error for ProtocolError {}

/// A borrowed view of one driver info frame.
///
/// The wire header is one info-type byte followed by a little-endian 32-bit
/// payload length. The payload is borrowed from the input buffer; parsing
/// does not allocate or copy it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InfoFrame<'a> {
    pub kind: InfoKind,
    pub payload: &'a [u8],
}

/// Validates and reads the first frame in a stream buffer.
///
/// Returns the borrowed frame and the number of input bytes it consumes.
/// Bytes after that frame are left untouched for the next parser call.
pub fn parse_info_frame(
    input: &[u8],
    maximum_payload_len: usize,
) -> Result<(InfoFrame<'_>, usize), ProtocolError> {
    const HEADER_SIZE: usize = 5;

    if input.len() < HEADER_SIZE {
        return Err(ProtocolError::TruncatedHeader);
    }

    let kind = InfoKind::try_from(input[0])?;
    let payload_len = u32::from_le_bytes([input[1], input[2], input[3], input[4]]) as usize;

    if payload_len > maximum_payload_len {
        return Err(ProtocolError::PayloadTooLarge {
            length: payload_len,
            maximum: maximum_payload_len,
        });
    }

    let frame_len = HEADER_SIZE
        .checked_add(payload_len)
        .ok_or(ProtocolError::LengthOverflow)?;

    if input.len() < frame_len {
        return Err(ProtocolError::TruncatedPayload {
            expected: payload_len,
            available: input.len() - HEADER_SIZE,
        });
    }

    Ok((
        InfoFrame {
            kind,
            payload: &input[HEADER_SIZE..frame_len],
        },
        frame_len,
    ))
}

/// Commands supported by the current Windows kernel-driver interface.
///
/// This encoder uses the command discriminants from the existing
/// windows_kext/protocol crate and preserves the Go-compatible packed
/// little-endian wire layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriverCommand {
    Shutdown,
    Verdict {
        id: u64,
        verdict: u8,
    },
    UpdateV4 {
        protocol: u8,
        local_address: [u8; 4],
        local_port: u16,
        remote_address: [u8; 4],
        remote_port: u16,
        verdict: u8,
    },
    UpdateV6 {
        protocol: u8,
        local_address: [u8; 16],
        local_port: u16,
        remote_address: [u8; 16],
        remote_port: u16,
        verdict: u8,
    },
    ClearCache,
    GetLogs,
    GetBandwidthStats,
    PrintMemoryStats,
    CleanEndedConnections,
}

impl DriverCommand {
    /// Returns the exact number of bytes required by this command.
    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        match self {
            Self::Shutdown
            | Self::ClearCache
            | Self::GetLogs
            | Self::GetBandwidthStats
            | Self::PrintMemoryStats
            | Self::CleanEndedConnections => 1,
            Self::Verdict { .. } => 10,
            Self::UpdateV4 { .. } => 15,
            Self::UpdateV6 { .. } => 39,
        }
    }

    /// Encodes the command into a reusable buffer.
    ///
    /// The buffer is cleared first. Reserving the exact encoded size allows
    /// callers to reuse one allocation for repeated driver commands.
    pub fn encode_into(&self, output: &mut Vec<u8>) {
        output.clear();
        output.reserve(self.encoded_len());

        match self {
            Self::Shutdown => output.push(CommandType::Shutdown as u8),
            Self::Verdict { id, verdict } => {
                output.push(CommandType::Verdict as u8);
                output.extend_from_slice(&id.to_le_bytes());
                output.push(*verdict);
            }
            Self::UpdateV4 {
                protocol,
                local_address,
                local_port,
                remote_address,
                remote_port,
                verdict,
            } => {
                output.push(CommandType::UpdateV4 as u8);
                output.push(*protocol);
                output.extend_from_slice(local_address);
                output.extend_from_slice(&local_port.to_le_bytes());
                output.extend_from_slice(remote_address);
                output.extend_from_slice(&remote_port.to_le_bytes());
                output.push(*verdict);
            }
            Self::UpdateV6 {
                protocol,
                local_address,
                local_port,
                remote_address,
                remote_port,
                verdict,
            } => {
                output.push(CommandType::UpdateV6 as u8);
                output.push(*protocol);
                output.extend_from_slice(local_address);
                output.extend_from_slice(&local_port.to_le_bytes());
                output.extend_from_slice(remote_address);
                output.extend_from_slice(&remote_port.to_le_bytes());
                output.push(*verdict);
            }
            Self::ClearCache => output.push(CommandType::ClearCache as u8),
            Self::GetLogs => output.push(CommandType::GetLogs as u8),
            Self::GetBandwidthStats => output.push(CommandType::GetBandwidthStats as u8),
            Self::PrintMemoryStats => output.push(CommandType::PrintMemoryStats as u8),
            Self::CleanEndedConnections => {
                output.push(CommandType::CleanEndedConnections as u8);
            }
        }
    }

    /// Encodes the command into a newly allocated byte vector.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(self.encoded_len());
        self.encode_into(&mut output);
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_frame_without_copying_or_consuming_following_frame() {
        let bytes = [1, 2, 0, 0, 0, 10, 11, 0, 0, 0, 0];
        let (frame, consumed) = parse_info_frame(&bytes, 64).unwrap();

        assert_eq!(frame.kind, InfoKind::ConnectionIpv4);
        assert_eq!(frame.payload, &[10, 11]);
        assert_eq!(consumed, 7);
    }

    #[test]
    fn rejects_truncated_and_oversized_frames() {
        assert_eq!(
            parse_info_frame(&[1, 0, 0], 64).err(),
            Some(ProtocolError::TruncatedHeader)
        );

        assert_eq!(
            parse_info_frame(&[1, 3, 0, 0, 0, 10], 64).err(),
            Some(ProtocolError::TruncatedPayload {
                expected: 3,
                available: 1,
            })
        );

        assert_eq!(
            parse_info_frame(&[1, 2, 0, 0, 0, 10, 11], 1).err(),
            Some(ProtocolError::PayloadTooLarge {
                length: 2,
                maximum: 1,
            })
        );
    }

    #[test]
    fn rejects_unknown_info_types() {
        assert_eq!(
            parse_info_frame(&[255, 0, 0, 0, 0], 64).err(),
            Some(ProtocolError::UnknownInfoType(255))
        );
    }

    #[test]
    fn encodes_verdict_using_driver_wire_layout() {
        let command = DriverCommand::Verdict { id: 1, verdict: 2 };
        assert_eq!(command.encoded_len(), 10);
        assert_eq!(
            command.encode().as_slice(),
            &[1, 1, 0, 0, 0, 0, 0, 0, 0, 2]
        );
    }

    #[test]
    fn encodes_ipv4_update_in_little_endian_order() {
        let command = DriverCommand::UpdateV4 {
            protocol: 6,
            local_address: [10, 0, 0, 1],
            local_port: 0x1234,
            remote_address: [1, 1, 1, 1],
            remote_port: 443,
            verdict: 2,
        };
        let bytes = command.encode();

        assert_eq!(bytes.len(), 15);
        assert_eq!(bytes[0], CommandType::UpdateV4 as u8);
        assert_eq!(&bytes[6..8], &[0x34, 0x12]);
        assert_eq!(&bytes[12..14], &[0xbb, 0x01]);
    }

    #[test]
    fn encodes_ipv6_update_in_driver_wire_order() {
        let command = DriverCommand::UpdateV6 {
            protocol: 17,
            local_address: [1; 16],
            local_port: 0x1234,
            remote_address: [2; 16],
            remote_port: 0x5678,
            verdict: 4,
        };
        let bytes = command.encode();

        assert_eq!(bytes.len(), 39);
        assert_eq!(bytes[0], CommandType::UpdateV6 as u8);
        assert_eq!(bytes[1], 17);
        assert_eq!(&bytes[18..20], &[0x34, 0x12]);
        assert_eq!(&bytes[36..38], &[0x78, 0x56]);
        assert_eq!(bytes[38], 4);
    }

    #[test]
    fn encodes_single_byte_control_commands() {
        let commands = [
            (DriverCommand::Shutdown, CommandType::Shutdown),
            (DriverCommand::ClearCache, CommandType::ClearCache),
            (DriverCommand::GetLogs, CommandType::GetLogs),
            (
                DriverCommand::GetBandwidthStats,
                CommandType::GetBandwidthStats,
            ),
            (
                DriverCommand::PrintMemoryStats,
                CommandType::PrintMemoryStats,
            ),
            (
                DriverCommand::CleanEndedConnections,
                CommandType::CleanEndedConnections,
            ),
        ];

        for (command, expected) in commands {
            assert_eq!(command.encoded_len(), 1);
            assert_eq!(command.encode().as_slice(), &[expected as u8]);
        }
    }

    #[test]
    fn reuses_preallocated_command_buffer() {
        let command = DriverCommand::UpdateV6 {
            protocol: 17,
            local_address: [0; 16],
            local_port: 53,
            remote_address: [1; 16],
            remote_port: 443,
            verdict: 2,
        };
        let mut output = Vec::with_capacity(64);
        let original_capacity = output.capacity();

        command.encode_into(&mut output);

        assert_eq!(output.len(), command.encoded_len());
        assert_eq!(output.capacity(), original_capacity);
    }
}
