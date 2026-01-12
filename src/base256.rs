// src/lib.rs
use std::fmt;

const START: u32 = 0x2600; 

#[derive(Debug, Clone)]
pub struct MyBase256 {
    start: char,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MapError {
    InvalidRange(char),
    NonMappedChar(char),
    NonChar(u32),
}

impl fmt::Display for MapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MapError::InvalidRange(ch) => write!(f, "Invalid 256-range starting at '{}'", ch),
            MapError::NonMappedChar(ch) => write!(f, "Character '{}' not in mapped range", ch),
            MapError::NonChar(u) => write!(f, "Codepoint U+{:04X} is not a valid char", u),
        }
    }
}

impl std::error::Error for MapError {}

impl MyBase256 {
    /// Create a mapper with a fixed start at U+2600 (☀).
    pub fn new() -> Self {
        let start_u = START;          // 固定起点
        Self { start: char::from_u32(start_u).unwrap() }
    }

    /// Encode bytes to a String of mapped characters.
    pub fn encode(&self, data: &[u8]) -> String {
        let base = self.start as u32;
        let mut out = String::with_capacity(data.len() * 3); // most symbols are 3-byte UTF-8
        for &b in data {
            out.push(char::from_u32(base + b as u32).expect("validated codepoint"));
        }
        out
    }

    /// Decode a String of mapped characters back to bytes.
    pub fn decode(&self, s: &str) -> Result<Vec<u8>, MapError> {
        let base = self.start as u32;
        let end = base + 255;
        let mut out = Vec::with_capacity(s.chars().count());

        for ch in s.chars() {
            let cp = ch as u32;
            if cp < base || cp > end {
                return Err(MapError::NonMappedChar(ch));
            }
            out.push((cp - base) as u8);
        }
        Ok(out)
    }

    /// Range description for debugging
    pub fn range(&self) -> (char, char) {
        let start = self.start;
        let end = char::from_u32(self.start as u32 + 255).unwrap();
        (start, end)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_encode_decode() {
        // Start at '☀' U+2600
        let mapper = MyBase256::new();

        let data = b"\x00\x01\xfe\xffHello\x00";
        let encoded = mapper.encode(data);
        let decoded = mapper.decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_range_end() {
        let mapper = MyBase256::new();
        let (s, e) = mapper.range();
        assert_eq!(s, '☀');
        assert_eq!(e as u32, '☀' as u32 + 255);
    }

    #[test]
    fn reject_outside_range() {
        let mapper = MyBase256::new();
        let mut s = mapper.encode(&[0, 1, 2]);
        s.push('一'); // 这个字符不在 2600..=26FF 区间
        assert!(mapper.decode(&s).is_err());
}
}
