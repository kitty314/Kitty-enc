use anyhow::Result;
use zeroize::Zeroizing;
use libsodium_rs::crypto_aead::xchacha20poly1305;

use crate::MY_ADDITIONAL_DATA;

#[derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct MyCipher{
    key: xchacha20poly1305::Key
}
impl MyCipher {
    pub fn new(key:&[u8])->Result<MyCipher>{
        let newkey = xchacha20poly1305::Key::from_bytes(key)?;
        Ok(MyCipher{key: newkey})
    }
    pub fn encrypt(&self, nonce:&MyXnonce, data:&[u8]) ->Result<Zeroizing<Vec<u8>>>{
        Ok(Zeroizing::new(xchacha20poly1305::encrypt(
            data,
            MY_ADDITIONAL_DATA,
            nonce,
            &self.key,
        )?))
    }
    pub fn decrypt(&self, nonce:&MyXnonce, data:&[u8]) ->Result<Zeroizing<Vec<u8>>>{
        Ok(Zeroizing::new(xchacha20poly1305::decrypt(
            data,
            MY_ADDITIONAL_DATA,
            nonce,
            &self.key,
        )?))
    }
}

pub type MyXnonce = xchacha20poly1305::Nonce;