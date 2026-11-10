use crate::driver_info::{parse_driver_info, DriverInfo};
use crate::driver_protocol::{InfoFrame, InfoKind, ProtocolError};

const INFO_HEADER_SIZE: usize = 5;

/// Bounded incremental decoder for the Windows driver's info stream.
///
/// Input can arrive in arbitrary chunks. Complete messages are decoded and
/// passed to the callback immediately; incomplete trailing bytes stay in the
/// buffer for the next call. The pending buffer cannot exceed one maximum
/// frame, and packet payloads are borrowed only for the duration of the
/// callback.
pub struct DriverInfoStream {
    max_payload_len: usize,
    max_frame_size: usize,
    pending: Vec<u8>,
}

impl DriverInfoStream {
    /// Creates a stream decoder with a maximum payload size.
    pub fn new(max_payload_len: usize) -> Result<Self, ProtocolError> {
        if max_payload_len > u32::MAX as usize {
            return Err(ProtocolError::PayloadTooLarge {
                length: max_payload_len,
                maximum: u32::MAX as usize,
            });
        }

        let max_frame_size = max_payload_len
            .checked_add(INFO_HEADER_SIZE)
            .ok_or(ProtocolError::LengthOverflow)?;

        Ok(Self {
            max_payload_len,
            max_frame_size,
            pending: Vec::new(),
        })
    }

    /// Creates a decoder using the standard 16 MiB payload limit.
    pub fn with_default_limit() -> Self {
        Self::new(crate::driver_protocol::DEFAULT_MAX_INFO_PAYLOAD)
            .expect("the default driver frame limit is valid")
    }

    /// Adds bytes to the stream and synchronously processes each complete
    /// frame. Returns the number of decoded messages.
    ///
    /// The callback runs before the internal buffer is reused. Do not retain
    /// slices from the supplied DriverInfo; copy data that must outlive
    /// the callback.
    pub fn feed<F>(&mut self, mut input: &[u8], mut on_info: F) -> Result<usize, ProtocolError>
    where
        F: FnMut(DriverInfo<'_>),
    {
        let mut decoded = 0;

        loop {
            decoded += self.process_pending(&mut on_info)?;
            if input.is_empty() {
                return Ok(decoded);
            }

            let available = self.max_frame_size - self.pending.len();
            if available == 0 {
                return Err(ProtocolError::PayloadTooLarge {
                    length: self.pending.len().saturating_sub(INFO_HEADER_SIZE),
                    maximum: self.max_payload_len,
                });
            }

            let take = available.min(input.len());
            self.pending.extend_from_slice(&input[..take]);
            input = &input[take..];
        }
    }

    /// Returns the number of bytes waiting for a complete frame.
    #[must_use]
    pub fn pending_bytes(&self) -> usize {
        self.pending.len()
    }

    /// Discards any partial frame after a terminal stream error.
    pub fn clear(&mut self) {
        self.pending.clear();
    }

    fn process_pending<F>(&mut self, on_info: &mut F) -> Result<usize, ProtocolError>
    where
        F: FnMut(DriverInfo<'_>),
    {
        let mut offset = 0;
        let mut decoded = 0;
        let mut failure = None;

        loop {
            let available = self.pending.len() - offset;
            if available < INFO_HEADER_SIZE {
                break;
            }

            let kind = match InfoKind::try_from(self.pending[offset]) {
                Ok(kind) => kind,
                Err(err) => {
                    failure = Some(err);
                    break;
                }
            };

            let payload_start = offset + 1;
            let payload_len = u32::from_le_bytes([
                self.pending[payload_start],
                self.pending[payload_start + 1],
                self.pending[payload_start + 2],
                self.pending[payload_start + 3],
            ]) as usize;

            if payload_len > self.max_payload_len {
                failure = Some(ProtocolError::PayloadTooLarge {
                    length: payload_len,
                    maximum: self.max_payload_len,
                });
                break;
            }

            let frame_len = match INFO_HEADER_SIZE.checked_add(payload_len) {
                Some(length) => length,
                None => {
                    failure = Some(ProtocolError::LengthOverflow);
                    break;
                }
            };

            if available < frame_len {
                break;
            }

            let payload_begin = offset + INFO_HEADER_SIZE;
            let payload_end = offset + frame_len;
            let frame = InfoFrame {
                kind,
                payload: &self.pending[payload_begin..payload_end],
            };

            let info = match parse_driver_info(frame) {
                Ok(info) => info,
                Err(err) => {
                    failure = Some(err);
                    break;
                }
            };

            on_info(info);
            offset += frame_len;
            decoded += 1;
        }

        if offset > 0 {
            let remaining = self.pending.len() - offset;
            self.pending.copy_within(offset.., 0);
            self.pending.truncate(remaining);
        }

        match failure {
            Some(err) => Err(err),
            None => Ok(decoded),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn log_frame(severity: u8) -> [u8; 6] {
        [InfoKind::LogLine as u8, 1, 0, 0, 0, severity]
    }

    #[test]
    fn handles_headers_split_across_reads() {
        let mut stream = DriverInfoStream::new(16).unwrap();
        let frame = log_frame(3);
        let mut values = Vec::new();

        assert_eq!(
            stream.feed(&frame[..3], |info| {
                if let DriverInfo::LogLine { severity, .. } = info {
                    values.push(severity);
                }
            }),
            Ok(0)
        );
        assert_eq!(stream.pending_bytes(), 3);

        assert_eq!(
            stream.feed(&frame[3..], |info| {
                if let DriverInfo::LogLine { severity, .. } = info {
                    values.push(severity);
                }
            }),
            Ok(1)
        );
        assert_eq!(values, [3]);
        assert_eq!(stream.pending_bytes(), 0);
    }

    #[test]
    fn handles_multiple_frames_in_a_chunk_larger_than_one_frame_limit() {
        let mut stream = DriverInfoStream::new(1).unwrap();
        let first = log_frame(2);
        let second = log_frame(5);
        let mut input = Vec::from(first);
        input.extend_from_slice(&second);

        let mut values = Vec::new();
        let count = stream
            .feed(&input, |info| {
                if let DriverInfo::LogLine { severity, .. } = info {
                    values.push(severity);
                }
            })
            .unwrap();

        assert_eq!(count, 2);
        assert_eq!(values, [2, 5]);
        assert_eq!(stream.pending_bytes(), 0);
    }

    #[test]
    fn rejects_oversized_frame_and_can_be_reset() {
        let mut stream = DriverInfoStream::new(8).unwrap();
        let input = [InfoKind::LogLine as u8, 9, 0, 0, 0, 1];

        assert_eq!(
            stream.feed(&input, |_| {}),
            Err(ProtocolError::PayloadTooLarge {
                length: 9,
                maximum: 8,
            })
        );

        stream.clear();
        assert_eq!(stream.pending_bytes(), 0);
        assert_eq!(stream.feed(&log_frame(7), |_| {}), Ok(1));
    }

    #[test]
    fn rejects_unknown_message_kind_without_invoking_callback() {
        let mut stream = DriverInfoStream::new(8).unwrap();
        let mut called = false;

        assert_eq!(
            stream.feed(&[255, 0, 0, 0, 0], |_| called = true),
            Err(ProtocolError::UnknownInfoType(255))
        );
        assert!(!called);
    }
}
