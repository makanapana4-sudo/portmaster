use std::sync::mpsc::{sync_channel, Receiver, SyncSender};

const MAX_CAPACITY: usize = 1_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueConfigError {
    ZeroCapacity,
    CapacityTooLarge,
}

impl std::fmt::Display for QueueConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZeroCapacity => f.write_str("event queue capacity must be greater than zero"),
            Self::CapacityTooLarge => write!(f, "event queue capacity exceeds {MAX_CAPACITY}"),
        }
    }
}

impl std::error::Error for QueueConfigError {}

/// Creates a bounded multi-producer, single-consumer queue.
///
/// Use try_send on latency-sensitive producers. A full queue is reported
/// instead of blocking; callers must define how a full queue is handled.
pub fn bounded_event_queue<T>(
    capacity: usize,
) -> Result<(SyncSender<T>, Receiver<T>), QueueConfigError> {
    if capacity == 0 {
        return Err(QueueConfigError::ZeroCapacity);
    }
    if capacity > MAX_CAPACITY {
        return Err(QueueConfigError::CapacityTooLarge);
    }
    Ok(sync_channel(capacity))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::{TryRecvError, TrySendError};

    #[test]
    fn rejects_zero_capacity() {
        assert_eq!(
            bounded_event_queue::<u8>(0).err(),
            Some(QueueConfigError::ZeroCapacity)
        );
    }

    #[test]
    fn full_queue_reports_backpressure_without_blocking() {
        let (sender, receiver) = bounded_event_queue(1).unwrap();
        sender.try_send(1).unwrap();
        assert!(matches!(sender.try_send(2), Err(TrySendError::Full(2))));
        assert_eq!(receiver.try_recv(), Ok(1));
        sender.try_send(3).unwrap();
        assert_eq!(receiver.try_recv(), Ok(3));
        assert_eq!(receiver.try_recv(), Err(TryRecvError::Empty));
    }

    #[test]
    fn disconnected_receiver_is_reported() {
        let (sender, receiver) = bounded_event_queue::<u8>(1).unwrap();
        drop(receiver);
        assert!(matches!(
            sender.try_send(1),
            Err(TrySendError::Disconnected(1))
        ));
    }
}
