#[cfg(feature = "defaults")]
pub mod sync;

pub mod asynchronous;

/// Detemines how much compression to use.
/// `None` is no compression.
/// `SpeedOptimized` uses a special compression scheme optimized for speed.
/// `Variable` takes a value from 0-8 where 0 is the fastest compression with the worst compression
/// and 8 is the best compression with the worst speed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Compression {
    None,
    SpeedOptimized,
    Variable(u8),
}

impl Default for Compression {
    fn default() -> Self {
        Self::Variable(4)
    }
}

#[allow(clippy::from_over_into)]
impl Into<u8> for Compression {
    fn into(self) -> u8 {
        match self {
            Self::None => 0,
            Self::SpeedOptimized => 1,
            Self::Variable(x) => 10.max(2 + x),
        }
    }
}
