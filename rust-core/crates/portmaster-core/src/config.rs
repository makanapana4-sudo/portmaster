use crate::CoreError;

/// Upper bounds for in-memory work queues and caches.
///
/// These are defensive limits, not performance targets. Values must be
/// selected from measurements before being used by a production service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceLimits {
    pub event_queue_capacity: usize,
    pub dns_cache_capacity: usize,
    pub max_concurrent_lookups: usize,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            event_queue_capacity: 4_096,
            dns_cache_capacity: 16_384,
            max_concurrent_lookups: 128,
        }
    }
}

/// Minimal configuration for the experimental user-mode core.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CoreConfig {
    pub limits: ResourceLimits,
    pub enable_metrics: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    ZeroLimit(&'static str),
    LimitTooLarge {
        name: &'static str,
        value: usize,
        maximum: usize,
    },
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZeroLimit(name) => write!(formatter, "{name} must be greater than zero"),
            Self::LimitTooLarge {
                name,
                value,
                maximum,
            } => {
                write!(formatter, "{name} ({value}) exceeds maximum ({maximum})")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

impl CoreConfig {
    pub fn validate(&self) -> Result<(), CoreError> {
        const MAX_QUEUE_CAPACITY: usize = 1_000_000;
        const MAX_CACHE_CAPACITY: usize = 1_000_000;
        const MAX_CONCURRENT_LOOKUPS: usize = 65_536;

        let limits = self.limits;
        for (name, value, maximum) in [
            (
                "event_queue_capacity",
                limits.event_queue_capacity,
                MAX_QUEUE_CAPACITY,
            ),
            (
                "dns_cache_capacity",
                limits.dns_cache_capacity,
                MAX_CACHE_CAPACITY,
            ),
            (
                "max_concurrent_lookups",
                limits.max_concurrent_lookups,
                MAX_CONCURRENT_LOOKUPS,
            ),
        ] {
            if value == 0 {
                return Err(CoreError::InvalidConfiguration(
                    ConfigError::ZeroLimit(name).to_string(),
                ));
            }
            if value > maximum {
                return Err(CoreError::InvalidConfiguration(
                    ConfigError::LimitTooLarge {
                        name,
                        value,
                        maximum,
                    }
                    .to_string(),
                ));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_configuration_is_valid() {
        assert!(CoreConfig::default().validate().is_ok());
    }

    #[test]
    fn zero_capacity_is_rejected() {
        let config = CoreConfig {
            limits: ResourceLimits {
                event_queue_capacity: 0,
                ..ResourceLimits::default()
            },
            ..CoreConfig::default()
        };

        assert!(matches!(
            config.validate(),
            Err(CoreError::InvalidConfiguration(_))
        ));
    }

    #[test]
    fn excessive_capacity_is_rejected() {
        let config = CoreConfig {
            limits: ResourceLimits {
                dns_cache_capacity: 1_000_001,
                ..ResourceLimits::default()
            },
            ..CoreConfig::default()
        };

        assert!(matches!(
            config.validate(),
            Err(CoreError::InvalidConfiguration(_))
        ));
    }
}
