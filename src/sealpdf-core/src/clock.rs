use chrono::{DateTime, FixedOffset, Local, Utc};

/// Time source passed into signing so output is deterministic in tests.
pub trait Clock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct FixedClock(pub DateTime<Utc>);

impl Clock for FixedClock {
    fn now(&self) -> DateTime<Utc> {
        self.0
    }
}

/// The offset from UTC of the system's time zone right now, daylight saving time included.
/// Used to show a signing time as the signer's clock would.
pub fn local_utc_offset() -> FixedOffset {
    *Local::now().offset()
}
