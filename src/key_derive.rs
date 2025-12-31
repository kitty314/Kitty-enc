use anyhow::{anyhow, Context, Result};
use std::fs::{self};
use std::path::Path;
use zeroize::Zeroizing;
use libsodium_rs::crypto_pwhash;

use crate::*;

/// 简化的密钥派生函数：从主密钥和salt派生子密钥（32字节）
/// 使用Argon2id：subkey = Argon2id(master_key, salt)
pub fn derive_subkey_simple(master_key: &[u8; 32], salt: &[u8]) -> Result<Zeroizing<[u8;32]>> { 
    // 派生密钥 - 使用 hash_password_into 直接写入可变数组
    let mut subkey: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
    if let Err(_) = my_argon2_into(master_key, salt, subkey.as_mut()) {
        return Err(anyhow!("Failed to derive subkey"));
    }
    Ok(subkey)
}

/// 从密码派生密钥（32字节）
/// 使用Argon2id密钥派生函数，使用密码作为salt (16字节)，如果密码太短则补0
pub fn derive_key_from_password(password: Zeroizing<String>) -> Result<Zeroizing<[u8;32]>> {
    // 使用密码作为salt，如果密码太短则补0到16字节 // 此时盐需要保护
    let password_bytes = password.as_bytes();
    let mut salt_bytes: Zeroizing<[u8; 16]> = Zeroizing::new([0u8; SALT_LENGTH]);
    
    // 复制密码字节到salt数组，如果密码长度小于16则剩余部分保持为0
    let copy_len = std::cmp::min(password_bytes.len(), SALT_LENGTH);
    salt_bytes[..copy_len].copy_from_slice(&password_bytes[..copy_len]);
    
    // 派生密钥 - 使用 hash_password_into 直接写入可变数组
    let mut key_bytes: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
    if let Err(_e) = my_argon2_into(password_bytes, salt_bytes.as_ref(), key_bytes.as_mut()) {
        return Err(anyhow!("Failed to derive key from password"));
    }
    
    Ok(key_bytes)
}

/// 从任意文件派生密钥（32字节）
/// 使用Argon2id密钥派生函数
/// 参数：
/// - file_path: 用于派生密钥的文件路径
/// - use_password: 是否使用密码
/// - need_confirm: 密码是否需要确认
/// 流程：
/// 1. 检查文件是否存在且大小至少32字节
/// 2. 读取文件至多前1MB内容作为输入数据
/// 3. 如果使用密码，根据need_confirm调用相应的密码读取函数
/// 4. 如果不使用密码，使用文件前16字节作为盐
/// 5. 使用Argon2id派生密钥
pub fn derive_key_from_any_file(file_path: &Path, use_password: bool, need_confirm: bool) -> Result<Zeroizing<[u8;32]>> {    
    // 检查文件是否存在且大小至少32字节 //2025.12.18会追溯软链接，如果链接破损或无权限返回false
    if !file_path.exists() {
        return Err(anyhow!("File does not exist: {}", file_path.display()));
    }
    // 2025.12.18 Path.is_file()会追溯软链接，如果链接破损或无权限返回false
    if !file_path.is_file() {
        return Err(anyhow!("Path is not a file: {}", file_path.display()));
    }
    
    let metadata = fs::metadata(file_path)
        .with_context(|| format!("Failed to get metadata for file: {}", file_path.display()))?;
    
    if metadata.len() < 32 {
        return Err(anyhow!("File must be at least 32 bytes, but is only {} bytes", metadata.len()));
    }

    // 获取密码
    let password: Zeroizing<String> = if use_password {
        if need_confirm {
            read_passwd_interactive()?
        } else {
            read_passwd_interactive_once()?
        }
    } else {
        Zeroizing::new(String::new())
    };

    // 读取文件至多前1MB内容
    let mut file = match fs::File::open(file_path) {
        Ok(f) => f,
        Err(e) => {
            return Err(e).with_context(|| format!("Failed to open file: {}", file_path.display()));
        }
    };
    
    // 限制读取大小为1MB
    let read_size = std::cmp::min(metadata.len(), ANY_FILE_MAX_READ_SIZE as u64) as usize;
    
    let mut file_data: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0u8; read_size]);
    use std::io::Read;
    if let Err(e) = file.read_exact(&mut file_data) {
        return Err(e).with_context(|| format!("Failed to read file data: {}", file_path.display()));
    }
    
    
    // 准备盐：如果不使用密码，使用文件前16字节作为盐；如果使用密码，使用密码派生密钥作为盐
    let salt: Zeroizing<Vec<u8>>;
    
    if use_password {
        // 使用密码派生密钥作为盐
        let mut salt_from_passwd: Zeroizing<[u8; 32]> = Zeroizing::new([0u8;32]);
        if let Err(_e) = my_argon2_into(password.as_bytes(), &file_data, salt_from_passwd.as_mut()) {
            return Err(anyhow!("Failed to derive salt from password"));
        }
        salt = Zeroizing::new(salt_from_passwd.to_vec());
    } else {
        // 使用文件前16字节作为盐
        let copy_len = std::cmp::min(file_data.len(), SALT_LENGTH);
        salt = Zeroizing::new(file_data[..copy_len].to_vec());
    }
    
    
    // 派生密钥 - 使用 hash_password_into 直接写入可变数组
    let mut key_bytes: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
    if let Err(_e) = my_argon2_into(&file_data, &salt, key_bytes.as_mut()) {
        return Err(anyhow!("Failed to derive key from any file"));
    }
       
    Ok(key_bytes)
}

pub fn my_argon2_into(password:&[u8], salt:&[u8], out:&mut [u8]) -> Result<()> {
    if password.len() == 0{
        return Err(anyhow!("派生密钥失败, 输入密码为空"));
    }
    if out.len() != 32{
        return Err(anyhow!("派生密钥失败, 输出缓冲区长度不正确"));
    }
    let salt: Zeroizing<Vec<u8>> = argon2_input_to_16(salt)?;
    let key: Zeroizing<Vec<u8>> = Zeroizing::new(crypto_pwhash::pwhash(
    32,
    password,
    &salt,
    MY_ARGON2_OPSLIMIT_32,
    MY_ARGON2_MEMLIMIT_32,
    crypto_pwhash::ALG_DEFAULT
)?);
    out.copy_from_slice(&key);
    Ok(())
}

/// 单一输入转换为16字节
pub fn argon2_input_to_16(input:&[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if input.len() == 0{
        return Err(anyhow!("转换为16字节失败, 输入为空"));
    }
    let mut salt: Zeroizing<[u8; 16]> = Zeroizing::new([0u8; SALT_LENGTH]);
    // 尽力而为的锁定, 使用者有责任自行阻断内存转储和交换
    // utils::mlock(salt.as_mut()).context("转换为16字节失败, 无法锁定内存")?;
    // 复制密码字节到salt数组，如果密码长度小于16则剩余部分保持为0
    let copy_len = std::cmp::min(input.len(), SALT_LENGTH);
    salt[..copy_len].copy_from_slice(&input[..copy_len]);
    
    let key_16: Zeroizing<Vec<u8>> = Zeroizing::new(crypto_pwhash::pwhash(
        SALT_LENGTH,
        input,
        salt.as_ref(),
        MY_ARGON2_OPSLIMIT_16,
        MY_ARGON2_MEMLIMIT_16,
        crypto_pwhash::ALG_DEFAULT
    )?);

    // utils::mlock(salt.as_mut()).context("转换为16字节失败, 无法解锁内存")?;
    Ok(key_16)
}