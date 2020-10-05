use std::time::{Duration, SystemTime};

mod cache;
mod compress;
mod utils;

pub use cache::Cache;
pub use compress::HuffmanCodec;

#[derive(Clone)]
pub(crate) struct Value<T> {
    pub val: T,
    expiration: Option<SystemTime>,
}

impl<T> Value<T> {
    pub fn new(val: T, duration: Option<Duration>) -> Self {
        Value {
            val,
            expiration: duration.map(|dur| SystemTime::now() + dur),
        }
    }

    pub fn has_expired(&self, time_now: SystemTime) -> bool {
        self.expiration.map_or(false, |time| time_now >= time)
    }
}
