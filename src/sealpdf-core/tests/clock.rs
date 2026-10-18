use chrono::{TimeZone, Utc};
use sealpdf_core::{Clock, FixedClock, SystemClock};

fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn fixed_clock_is_constant() {
    let t = Utc.with_ymd_and_hms(2024, 5, 17, 10, 30, 0).unwrap();
    let c = FixedClock(t);
    assert_eq!(c.now(), t);
    assert_eq!(c.now(), c.now());
}

#[test]
fn system_clock_is_recent_and_monotonic_enough() {
    let before = Utc::now();
    let t = SystemClock.now();
    let after = Utc::now();
    assert!(before <= t && t <= after);
}

#[test]
fn usable_as_trait_object() {
    let t = Utc.with_ymd_and_hms(2000, 1, 1, 0, 0, 0).unwrap();
    let clocks: Vec<Box<dyn Clock>> = vec![Box::new(FixedClock(t)), Box::new(SystemClock)];
    assert_eq!(clocks[0].now(), t);
    assert!(clocks[1].now() > t);
}

#[test]
fn clocks_are_send_sync() {
    assert_send_sync::<FixedClock>();
    assert_send_sync::<SystemClock>();
    assert_send_sync::<Box<dyn Clock>>();
}
