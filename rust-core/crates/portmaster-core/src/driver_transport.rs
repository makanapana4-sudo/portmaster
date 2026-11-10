use crate::{
    driver_info::DriverInfo,
    driver_protocol::{DriverCommand, ProtocolError},
    driver_stream::DriverInfoStream,
};
use std::io::{self, Read, Write};

/// Maximum amount of driver data read in one transport call.
pub const DRIVER_READ_BUFFER_SIZE: usize = 16 * 1024;

/// Result of one non-blocking-capable driver read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverReadOutcome {
    /// Number of complete messages delivered to the callback.
    Messages(usize),
    /// The underlying transport currently has no data available.
    WouldBlock,
    /// The underlying transport reached end-of-stream.
    EndOfStream,
}

/// Errors returned by the generic driver transport.
#[derive(Debug)]
pub enum DriverTransportError {
    Io(io::Error),
    Protocol(ProtocolError),
}

impl std::fmt::Display for DriverTransportError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "driver transport I/O error: {error}"),
            Self::Protocol(error) => write!(formatter, "driver protocol error: {error}"),
        }
    }
}

impl std::error::Error for DriverTransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Protocol(error) => Some(error),
        }
    }
}

impl From<io::Error> for DriverTransportError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<ProtocolError> for DriverTransportError {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

/// Small transport adapter joining the existing driver command encoder and
/// bounded event stream decoder.
///
/// The adapter does not install or open a device, change firewall policy, or
/// manage driver lifecycle. A platform-specific layer supplies the Read and
/// Write implementation after its handle and access rights are validated.
pub struct DriverTransport<T> {
    io: T,
    decoder: DriverInfoStream,
    read_buffer: [u8; DRIVER_READ_BUFFER_SIZE],
}

impl<T> DriverTransport<T> {
    /// Creates a transport with the default 16 MiB maximum message size.
    pub fn new(io: T) -> Self {
        Self::with_max_payload(io, crate::driver_protocol::DEFAULT_MAX_INFO_PAYLOAD)
            .expect("the default driver payload limit is valid")
    }

    /// Creates a transport with a caller-selected maximum message size.
    pub fn with_max_payload(
        io: T,
        maximum_payload: usize,
    ) -> Result<Self, ProtocolError> {
        Ok(Self {
            io,
            decoder: DriverInfoStream::new(maximum_payload)?,
            read_buffer: [0; DRIVER_READ_BUFFER_SIZE],
        })
    }

    /// Returns the number of bytes retained for an incomplete event.
    #[must_use]
    pub fn pending_bytes(&self) -> usize {
        self.decoder.pending_bytes()
    }

    /// Discards an incomplete event after a terminal protocol error.
    pub fn clear_pending(&mut self) {
        self.decoder.clear();
    }

    /// Returns the underlying platform transport.
    pub fn into_inner(self) -> T {
        self.io
    }
}

impl<T: Write> DriverTransport<T> {
    /// Sends one command using the encoder's fixed-size stack buffer.
    pub fn send(&mut self, command: &DriverCommand) -> Result<(), DriverTransportError> {
        command.write_to(&mut self.io)?;
        Ok(())
    }
}

impl<T: Read> DriverTransport<T> {
    /// Reads once from the driver and delivers all complete events received.
    ///
    /// Interrupted reads are retried. WouldBlock is returned as a normal
    /// outcome for nonblocking transports. The callback is synchronous and
    /// receives borrowed event payloads; copy any bytes that must outlive it.
    pub fn read_once<F>(
        &mut self,
        mut on_info: F,
    ) -> Result<DriverReadOutcome, DriverTransportError>
    where
        F: FnMut(DriverInfo<'_>),
    {
        let count = loop {
            match self.io.read(&mut self.read_buffer) {
                Ok(count) => break count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    return Ok(DriverReadOutcome::WouldBlock);
                }
                Err(error) => return Err(DriverTransportError::Io(error)),
            }
        };

        if count == 0 {
            return Ok(DriverReadOutcome::EndOfStream);
        }

        let messages = self
            .decoder
            .feed(&self.read_buffer[..count], &mut on_info)
            .map_err(DriverTransportError::Protocol)?;

        Ok(DriverReadOutcome::Messages(messages))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver_protocol::InfoKind;
    use std::io::Cursor;

    struct ChunkedDuplex {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
        max_read: usize,
        max_write: usize,
    }

    impl Read for ChunkedDuplex {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            let count = output.len().min(self.max_read);
            self.input.read(&mut output[..count])
        }
    }

    impl Write for ChunkedDuplex {
        fn write(&mut self, input: &[u8]) -> io::Result<usize> {
            let count = input.len().min(self.max_write);
            self.output.extend_from_slice(&input[..count]);
            Ok(count)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct WouldBlockDuplex;

    impl Read for WouldBlockDuplex {
        fn read(&mut self, _output: &mut [u8]) -> io::Result<usize> {
            Err(io::ErrorKind::WouldBlock.into())
        }
    }

    fn log_frame(severity: u8) -> [u8; 6] {
        [InfoKind::LogLine as u8, 1, 0, 0, 0, severity]
    }

    #[test]
    fn delivers_multiple_messages_from_one_read() {
        let mut input = Vec::from(log_frame(2));
        input.extend_from_slice(&log_frame(4));
        let transport = Cursor::new(input);
        let mut transport = DriverTransport::new(transport);
        let mut severities = Vec::new();

        let result = transport
            .read_once(|info| {
                if let DriverInfo::LogLine { severity, .. } = info {
                    severities.push(severity);
                }
            })
            .unwrap();

        assert_eq!(result, DriverReadOutcome::Messages(2));
        assert_eq!(severities, [2, 4]);
        assert_eq!(
            transport.read_once(|_| {}).unwrap(),
            DriverReadOutcome::EndOfStream
        );
    }

    #[test]
    fn retains_partial_frames_between_reads() {
        let mut input = Vec::from(log_frame(5));
        input.extend_from_slice(&log_frame(6));
        let duplex = ChunkedDuplex {
            input: Cursor::new(input),
            output: Vec::new(),
            max_read: 3,
            max_write: 2,
        };
        let mut transport = DriverTransport::new(duplex);
        let mut severities = Vec::new();

        assert_eq!(
            transport
                .read_once(|info| {
                    if let DriverInfo::LogLine { severity, .. } = info {
                        severities.push(severity);
                    }
                })
                .unwrap(),
            DriverReadOutcome::Messages(0)
        );
        assert_eq!(transport.pending_bytes(), 3);

        assert_eq!(
            transport
                .read_once(|info| {
                    if let DriverInfo::LogLine { severity, .. } = info {
                        severities.push(severity);
                    }
                })
                .unwrap(),
            DriverReadOutcome::Messages(1)
        );
        assert_eq!(severities, [5]);
        assert_eq!(transport.pending_bytes(), 0);
    }

    #[test]
    fn reports_would_block_without_treating_it_as_eof() {
        let mut transport = DriverTransport::new(WouldBlockDuplex);

        assert_eq!(
            transport.read_once(|_| {}).unwrap(),
            DriverReadOutcome::WouldBlock
        );
    }

    #[test]
    fn sends_commands_through_short_writes() {
        let duplex = ChunkedDuplex {
            input: Cursor::new(Vec::new()),
            output: Vec::new(),
            max_read: 4,
            max_write: 2,
        };
        let mut transport = DriverTransport::new(duplex);
        let command = DriverCommand::Verdict { id: 123, verdict: 4 };

        transport.send(&command).unwrap();

        let duplex = transport.into_inner();
        assert_eq!(duplex.output, command.encode());
    }

    #[test]
    fn rejects_invalid_frame_without_invoking_callback() {
        let input = Cursor::new(vec![255, 0, 0, 0, 0]);
        let mut transport = DriverTransport::new(input);
        let mut called = false;

        assert!(matches!(
            transport.read_once(|_| called = true),
            Err(DriverTransportError::Protocol(
                ProtocolError::UnknownInfoType(255)
            ))
        ));
        assert!(!called);
    }
}
