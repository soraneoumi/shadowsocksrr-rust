use std::ops::Deref;
use std::time::{SystemTime, UNIX_EPOCH};

const PREFIX_BUFFER_COMPACT_THRESHOLD: usize = 1024;

#[derive(Clone, Debug, Default)]
pub struct PrefixBuffer {
    buf: Vec<u8>,
    head: usize,
}

impl PrefixBuffer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn extend_from_slice(&mut self, data: &[u8]) {
        self.maybe_compact_for_append(data.len());
        self.buf.extend_from_slice(data);
    }

    pub fn consume(&mut self, n: usize) {
        assert!(n <= self.len(), "consume beyond prefix buffer length");
        if n == 0 {
            return;
        }

        self.head += n;
        if self.head == self.buf.len() {
            self.clear();
            return;
        }

        if self.head >= PREFIX_BUFFER_COMPACT_THRESHOLD && self.head * 2 >= self.buf.len() {
            self.compact();
        }
    }

    pub fn clear(&mut self) {
        self.buf.clear();
        self.head = 0;
    }

    fn maybe_compact_for_append(&mut self, additional: usize) {
        if self.head == 0 {
            return;
        }

        let tail_capacity = self.buf.capacity().saturating_sub(self.buf.len());
        if tail_capacity < additional
            || (self.head >= PREFIX_BUFFER_COMPACT_THRESHOLD && self.head * 2 >= self.buf.len())
        {
            self.compact();
        }
    }

    fn compact(&mut self) {
        if self.head == 0 {
            return;
        }

        let remaining = self.len();
        self.buf.copy_within(self.head.., 0);
        self.buf.truncate(remaining);
        self.head = 0;
    }
}

impl From<Vec<u8>> for PrefixBuffer {
    fn from(buf: Vec<u8>) -> Self {
        Self { buf, head: 0 }
    }
}

impl Deref for PrefixBuffer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.buf[self.head..]
    }
}

pub fn now_secs_u32() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

pub fn int32(x: i64) -> i32 {
    let mut v = x;
    if !(0..=0xFFFF_FFFF).contains(&v) {
        v &= 0xFFFF_FFFF;
    }
    if v > 0x7FFF_FFFF {
        let y = 0x1_0000_0000_i64 - v;
        if y < 0x8000_0000 {
            return -(y as i32);
        }
        return i32::MIN;
    }
    v as i32
}

pub fn parse_protocol_param_max_client(protocol_param: &str, default_value: usize) -> usize {
    protocol_param
        .split('#')
        .next()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(default_value)
}

#[cfg(test)]
mod tests {
    use super::{PrefixBuffer, now_secs_u32, parse_protocol_param_max_client};
    use std::thread;
    use std::time::Duration;

    #[test]
    fn prefix_buffer_preserves_remaining_bytes_after_consume() {
        let mut buf = PrefixBuffer::new();
        buf.extend_from_slice(b"abcdef");
        buf.consume(2);
        assert_eq!(&*buf, b"cdef");

        buf.extend_from_slice(b"gh");
        assert_eq!(&*buf, b"cdefgh");
    }

    #[test]
    fn prefix_buffer_clears_when_fully_consumed() {
        let mut buf = PrefixBuffer::new();
        buf.extend_from_slice(b"hello");
        buf.consume(5);
        assert!(buf.is_empty());

        buf.extend_from_slice(b"world");
        assert_eq!(&*buf, b"world");
    }

    #[test]
    fn protocol_param_max_client_falls_back_on_invalid_input() {
        assert_eq!(parse_protocol_param_max_client("bad#3600", 64), 64);
        assert_eq!(parse_protocol_param_max_client("#3600", 32), 32);
    }

    #[test]
    fn now_secs_u32_is_monotonic_enough_for_runtime_use() {
        let first = now_secs_u32();
        thread::sleep(Duration::from_millis(5));
        let second = now_secs_u32();
        assert_ne!(first, 0, "unix timestamp should be nonzero");
        assert!(
            second >= first,
            "later timestamp should not move backwards: {first} -> {second}"
        );
    }
}
