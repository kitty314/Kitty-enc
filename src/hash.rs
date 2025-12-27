use anyhow::{anyhow, Result};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305};
use zeroize::Zeroizing;

/// 加密文件哈希
/// 输入：原始哈希（32字节）、子密钥（32字节）、xnonce（24字节）
/// 输出：加密后的哈希（32字节密文 + 16字节认证标签 = 48字节）
pub fn encrypt_file_hash(original_hash: &[u8; 32], subkey: &[u8; 32], xnonce_bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    use chacha20poly1305::XNonce;
    
    // 验证 xnonce 长度
    if xnonce_bytes.len() != 24 {
        return Err(anyhow!("Invalid hash xnonce length: expected 24 bytes, got {} bytes", xnonce_bytes.len()));
    }
    // 创建密码器
    let cipher = XChaCha20Poly1305::new(Key::from_slice(subkey));
    let xnonce = XNonce::from_slice(xnonce_bytes);
    
    // 加密哈希
    let encrypted_hash: Zeroizing<Vec<u8>> = match cipher.encrypt(xnonce, original_hash.as_ref()) {
        Ok(ct) => Zeroizing::new(ct),
        Err(_) => {
            return Err(anyhow!("Failed to encrypt file hash"));
        }
    };
    
    // 验证加密后的哈希长度：32字节明文 + 16字节认证标签 = 48字节
    if encrypted_hash.len() != 48 {
        return Err(anyhow!("Unexpected encrypted hash length: expected 48 bytes, got {}", encrypted_hash.len()));
    }
    
    Ok(encrypted_hash)
}

/// 解密文件哈希
/// 输入：加密后的哈希（48字节）、子密钥（32字节）、xnonce（24字节）
/// 输出：原始哈希（32字节）
pub fn decrypt_file_hash(encrypted_hash: &[u8], subkey: &[u8; 32], xnonce_bytes: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    use chacha20poly1305::XNonce;
    
    // 验证输入长度
    if encrypted_hash.len() != 48 {
        return Err(anyhow!("Invalid encrypted hash length: expected 48 bytes, got {}", encrypted_hash.len()));
    }
    
    // 验证 xnonce 长度
    if xnonce_bytes.len() != 24 {
        return Err(anyhow!("Invalid hash xnonce length: expected 24 bytes, got {} bytes", xnonce_bytes.len()));
    }
    
    // 创建密码器
    let cipher = XChaCha20Poly1305::new(Key::from_slice(subkey));
    let xnonce = XNonce::from_slice(xnonce_bytes);
    
    // 解密哈希
    let decrypted_hash: Zeroizing<Vec<u8>> = Zeroizing::new(cipher.decrypt(xnonce, encrypted_hash)
        .map_err(|_| anyhow!("Failed to decrypt file hash"))?);
    
    // 验证解密后的哈希长度
    if decrypted_hash.len() != 32 {
        return Err(anyhow!("Unexpected decrypted hash length: expected 32 bytes, got {}", decrypted_hash.len()));
    }
    
    // 转换为固定大小的数组
    let mut hash_array: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
    hash_array.copy_from_slice(&decrypted_hash);
    
    Ok(hash_array)
}
