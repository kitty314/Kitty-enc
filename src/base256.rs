// src/lib.rs
use anyhow::{anyhow, Result};
use zeroize::Zeroize;

#[derive(Debug, Clone)]
pub struct MyBase256 {
    mode: Base256Mode
}

// 存在空白字符的区段
// U+0000 ~ U+00FF, U+1680, U+2000 ~ U+20FF, U+3000
// 禁止使用
#[derive(Debug, Clone, Copy)]
pub enum Base256Mode {
    ///0x3400
    CjkIdeographA, 
    ///0x4E00
    CjkIdeograph, 
    ///0x0100
    LatinExtended, 
    ///0xA000
    YiSyllable, 
    ///0x10600
    LinearA, 
    ///0x2600
    MiscellaneousSymbols, 
    ///0x13000
    EgyptianHieroglyphs, 
}


impl MyBase256 {
    pub fn new(base256mode_code: u32) -> Self {
        let base256mode = match base256mode_code {
            0 => Base256Mode::CjkIdeographA,
            1 => Base256Mode::CjkIdeograph,
            2 => Base256Mode::LatinExtended,
            3 => Base256Mode::YiSyllable,
            4 => Base256Mode::LinearA,
            5 => Base256Mode::MiscellaneousSymbols,
            6 => Base256Mode::EgyptianHieroglyphs,
            _ => Base256Mode::CjkIdeographA,
        };
        Self { mode: base256mode }
    }

    /// Encode bytes to a String of mapped characters.
    pub fn encode(&self, data: &[u8]) -> String {
        let base = self.get_base_from_mode();
        let mut out = String::with_capacity(data.len() * 4); // 最大 4-byte 一个字符
        for &b in data {
            out.push(char::from_u32(base + b as u32).expect("validated codepoint"));
        }
        out.shrink_to_fit();
        out
    }

    /// Decode a String of mapped characters back to bytes.
    pub fn decode(&self, s: &str) -> Vec<u8> {
        let base = self.get_base_from_mode();
        let end = base + 255;
        let mut out = Vec::with_capacity(s.len());

        for ch in s.chars() {
            let cp = ch as u32;
            if cp < base || cp > end {
                continue;
            }
            out.push((cp - base) as u8);
        }
        out.shrink_to_fit();
        out
    }

    pub fn try_decode(&self, s: &str) -> Result<Vec<u8>> {
        let base = self.get_base_from_mode();
        let end = base + 255;
        let mut out = Vec::with_capacity(s.len());

        for ch in s.chars() {
            // 尝试删除空白, 可能由用户意外加入
            if ch.is_whitespace() {continue;}

            let cp = ch as u32;
            if cp < base || cp > end {
                out.zeroize(); // 返回之前清零
                return Err(anyhow!("Character '{}' not in mapped range", ch));
            }
            out.push((cp - base) as u8);
        }
        out.shrink_to_fit();
        Ok(out)
    }

    fn get_base_from_mode(&self) -> u32 {
        match self.mode {
            Base256Mode::CjkIdeographA => 0x3400,
            Base256Mode::CjkIdeograph => 0x4E00,
            Base256Mode::LatinExtended => 0x0100,
            Base256Mode::YiSyllable => 0xA000,
            Base256Mode::LinearA => 0x10600,
            Base256Mode::MiscellaneousSymbols => 0x2600,
            Base256Mode::EgyptianHieroglyphs => 0x13000,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_encode_decode() {
        // Start at '☀' U+2600
        let mapper = MyBase256::new(0);

        let data = b"\x00\x01\xfe\xffHello\x00";
        let encoded = mapper.encode(data);
        let decoded = mapper.decode(&encoded);
        assert_eq!(decoded, data);
    }

    #[test]
    fn reject_outside_range() {
        let mapper = MyBase256::new(3);
        let s = mapper.encode(&[0, 1, 2]);
        let mut s2 = mapper.encode(&[0, 1, 2]);
        s2.push('一'); // 这个字符不在 2600..=26FF 区间
        assert_eq!(mapper.decode(&s), mapper.decode(&s2));
}
}
