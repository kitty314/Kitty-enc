// src/lib.rs
// use std::fmt;

#[derive(Debug, Clone)]
pub struct MyBase256 {
    mode: Base256Mode
}

#[derive(Debug, Clone, Copy)]
pub enum Base256Mode {
    CjkIdeographA, //0x3400
    YiSyllable, //0xA000
    CjkIdeograph, //0x4E00
    MiscellaneousSymbols, //0x2600
}


impl MyBase256 {
    /// Create a mapper with a fixed start at U+2600 (☀).
    pub fn new(mode: Base256Mode) -> Self {
        Self { mode: mode }
    }

    /// Encode bytes to a String of mapped characters.
    pub fn encode(&self, data: &[u8]) -> String {
        let base = self.get_base_from_mode();
        let mut out = String::with_capacity(data.len() * 3); // most symbols are 3-byte UTF-8
        for &b in data {
            out.push(char::from_u32(base + b as u32).expect("validated codepoint"));
        }
        out
    }

    /// Decode a String of mapped characters back to bytes.
    pub fn decode(&self, s: &str) -> Vec<u8> {
        let base = self.get_base_from_mode();
        let end = base + 255;
        let mut out = Vec::with_capacity(s.chars().count());

        for ch in s.chars() {
            let cp = ch as u32;
            if cp < base || cp > end {
                // return Err(MapError::NonMappedChar(ch));
                continue;
            }
            out.push((cp - base) as u8);
        }
        out
    }

    fn get_base_from_mode(&self) -> u32 {
        match self.mode {
            Base256Mode::CjkIdeographA => 0x3400,
            Base256Mode::CjkIdeograph => 0x4E00,
            Base256Mode::YiSyllable => 0xA000,
            Base256Mode::MiscellaneousSymbols => 0x2600
        }
    }
}

#[cfg(any())]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MapError {
    InvalidRange(char),
    NonMappedChar(char),
    NonChar(u32),
}
#[cfg(any())]
impl fmt::Display for MapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MapError::InvalidRange(ch) => write!(f, "Invalid 256-range starting at '{}'", ch),
            MapError::NonMappedChar(ch) => write!(f, "Character '{}' not in mapped range", ch),
            MapError::NonChar(u) => write!(f, "Codepoint U+{:04X} is not a valid char", u),
        }
    }
}
#[cfg(any())]
impl std::error::Error for MapError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_encode_decode() {
        // Start at '☀' U+2600
        let mapper = MyBase256::new(Base256Mode::YiSyllable);

        let data = b"\x00\x01\xfe\xffHello\x00";
        let encoded = mapper.encode(data);
        let decoded = mapper.decode(&encoded);
        assert_eq!(decoded, data);
    }

    #[test]
    fn reject_outside_range() {
        let mapper = MyBase256::new(Base256Mode::MiscellaneousSymbols);
        let s = mapper.encode(&[0, 1, 2]);
        let mut s2 = mapper.encode(&[0, 1, 2]);
        s2.push('一'); // 这个字符不在 2600..=26FF 区间
        assert_eq!(mapper.decode(&s), mapper.decode(&s2));
}
}
