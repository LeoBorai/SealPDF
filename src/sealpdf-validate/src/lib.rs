#![doc = include_str!("../README.md")]

mod date;
mod inspect;
mod report;
mod verdicts;

pub use inspect::{inspect, signature_count};
pub use report::{REPORT_VERSION, Report, SignatureInfo};
pub use verdicts::order;
