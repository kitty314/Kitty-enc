use anyhow::{anyhow, Context, Result};
use rand::rngs::OsRng;
use rand::TryRngCore;
use std::fs::{self};
use std::path::{Path, PathBuf};
use chrono::Local;
use zeroize::Zeroizing;

use crate::*;

/// 获取或创建密钥文件路径（公共函数）
pub fn get_or_create_key_path(target_dir_or_file: &Path, key_opt: &Option<PathBuf>, operation: &str) -> Result<(PathBuf,Option<Zeroizing<String>>)> {
    match key_opt {
        Some(p) => Ok((p.clone(),None)),
        None => {
            // 确定目标目录：如果target_dir_or_file是文件，则取其父目录；否则就是目录本身
            let target_dir = if target_dir_or_file.is_file() {
                target_dir_or_file.parent().unwrap_or(target_dir_or_file)// 文件不可能没有父目录，但还是兜底
            } else {
                target_dir_or_file
            };
            
            // 优先在目标目录中查找现有的密钥文件
            match find_existing_key_file(target_dir) {
                Ok(Some(existing_key)) => {
                    my_println!("Using existing key in {} directory: {}", operation, existing_key.display());
                    Ok((existing_key,None))
                }
                Ok(None) => {
                    if operation == "decryption" || operation == "fix" {
                        return Err(anyhow!("No key file found in {} directory. Please specify key file with -k option.", operation));
                    }
                    // 没有现有密钥文件，生成新的（生成在目标目录中）
                    let key_filename = generate_key_filename(target_dir);
                    let p = target_dir.join(key_filename);
                    my_println!("No key file found in {} directory. Generating new key file: {}", operation, p.display());
                    let passphrase_opt: Option<Zeroizing<String>> = match read_passphrase_interactive() {
                        Ok(passphrase) => Some(passphrase),
                        Err(e) => {
                            my_eprintln!("Error reading passphrase: {}", e);
                            return Err(e);
                        }
                    };
                    if let Err(e) = generate_key_file(&p, passphrase_opt.as_ref()){
                        return Err(e);
                    }
                    
                    my_println!("Generated key: {}", p.display());
                    Ok((p, passphrase_opt))
                }
                Err(e) => Err(e), // 处理 find_existing_key_file 返回的错误
            }
        }
    }
}

/// 在指定目录中查找现有的密钥文件
/// 如果找到多个密钥文件，返回错误要求用户手动指定
fn find_existing_key_file(dir: &Path) -> Result<Option<PathBuf>> {
    let mut key_files = Vec::new();
    
    let entries = fs::read_dir(dir)
        .with_context(|| format!("Failed to read directory: {}", dir.display()))?;
    
    for entry in entries {
        let entry = entry.with_context(|| format!("Failed to read directory entry in: {}", dir.display()))?;
        
        let file_type = entry.file_type()
            .with_context(|| format!("Failed to get file type for: {}", entry.path().display()))?;
        
        if file_type.is_file() {
            if let Some(file_ext) = entry.path().extension() {
                // 查找以 ".kitty_key" 结尾的文件
                if file_ext == DEFAULT_KEY_SUFFIX {
                    key_files.push(entry.path());
                }
            }
        }
    }
    
    match key_files.len() {
        0 => Ok(None),
        1 => Ok(Some(key_files[0].clone())),
        _ => {
            // 找到多个密钥文件，列出所有文件并报错
            my_eprintln!("Found multiple key files in directory: {}", dir.display());
            for key_file in &key_files {
                my_eprintln!("  - {}", key_file.display());
            }
            Err(anyhow!("Multiple key files found. Please specify which key file to use with -k option."))
        }
    }
}

fn generate_key_filename(dir: &Path) -> String {
    // 获取目录名
    let dir_name = dir
        .file_name()
        .and_then(|n| Some(n.to_string_lossy()))
        .map(|s| s.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    
    // 获取当前时间，格式化为 YYYYMMDD_HHMMSS
    let now = Local::now();
    let time_str = now.format("%Y%m%d_%H%M%S").to_string();
    
    // 清理目录名中的非法字符（只保留字母、数字、下划线、连字符和空格）
    let clean_dir_name: String = dir_name
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-' || *c == ' ')
        .collect();
    
    // 如果清理后为空，使用默认名称
    let final_dir_name = if clean_dir_name.is_empty() {
        "unknown".to_string()
    } else {
        clean_dir_name
    };
    
    // 生成文件名：目录名-时间.kitty_key
    format!("{}-{}.{}", final_dir_name, time_str, DEFAULT_KEY_SUFFIX)
}

fn generate_key_file(path: &Path, passphrase_opt: Option<&Zeroizing<String>>) -> Result<()> {
    // 总是生成随机密钥
    let mut key_bytes: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
    if let Err(e) = OsRng.try_fill_bytes(key_bytes.as_mut()) {
        return Err(e).context("Failed to generate random key");
    }
    
    let key_data: Zeroizing<Vec<u8>> = prepare_key_data(key_bytes, passphrase_opt)?;// 如果失败这一次密钥生成就失败了,应该不需要清理内存

    // 写入密钥文件，如果失败则清理内存
    if let Err(e) = fs::write(path, &key_data).with_context(|| format!("Failed to write key file: {}", path.display())) {
        return Err(e);
    }
    
    Ok(())
}

/// 准备密钥数据，根据是否使用密码短语进行相应处理
fn prepare_key_data(key_bytes: Zeroizing<[u8; 32]>, passphrase_opt: Option<&Zeroizing<String>>) -> Result<Zeroizing<Vec<u8>>> {
    match passphrase_opt {
        Some(passphrase) if !passphrase.is_empty() => {
            // 使用密码短语加密密钥
            encrypt_key_with_passphrase(key_bytes, passphrase)
        }
        _ => {
            // 没有密码短语或密码短语为空，直接存储原始密钥
            Ok(Zeroizing::new(key_bytes.to_vec()))
        }
    }
}

/// 使用密码短语加密密钥（改进版）
fn encrypt_key_with_passphrase(key: Zeroizing<[u8; 32]>, passphrase: &str) -> Result<Zeroizing<Vec<u8>>> {
    // 生成随机 salt
    let mut salt_bytes = [0u8; SALT_LENGTH];
    if let Err(e) = OsRng.try_fill_bytes(&mut salt_bytes) {
        return Err(e).context("Failed to generate random salt for key encryption");
    }
    // 派生密钥 - 使用 hash_password_into 直接写入可变数组
    let mut key_encryption_key_bytes: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
    my_argon2_into(passphrase.as_bytes(), &salt_bytes, key_encryption_key_bytes.as_mut())
        .map_err(|_e| anyhow!("Failed to derive key for key encryption"))?;
    
    // 使用 XChaCha20Poly1305 加密密钥
    let cipher = MyCipher::new(key_encryption_key_bytes.as_ref())?;
    
    // 随机 xnonce
    let mut xnonce_bytes = [0u8; 24];
    if let Err(e) = OsRng.try_fill_bytes(&mut xnonce_bytes) {
        return Err(e).context("Failed to generate random nonce for key encryption");
    }
    let xnonce = MyXnonce::try_from_slice(&xnonce_bytes)?;
    
    // 加密密钥
    let encrypted_key: Zeroizing<Vec<u8>> = match cipher.encrypt(&xnonce, key.as_ref()) {
        Ok(encrypted) => encrypted,
        Err(_) => {
            return Err(anyhow!("Failed to encrypt key with passphrase"));
        }
    };
    
    // 输出格式: [salt (SALT_LENGTH bytes) || xnonce (24 bytes) || encrypted_key]
    let mut output: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(SALT_LENGTH + 24 + encrypted_key.len()));
    output.extend_from_slice(&salt_bytes);
    output.extend_from_slice(&xnonce_bytes);
    output.extend_from_slice(&encrypted_key);
     
    Ok(output)
}

pub fn load_key(path: &Path, passphrase_opt_from_creat: Option<Zeroizing<String>>) -> Result<Zeroizing<[u8; 32]>> {
    let bytes: Zeroizing<Vec<u8>> = match fs::read(path).with_context(|| format!("Failed to read key file: {}", path.display())) {
        Ok(bytes) => Zeroizing::new(bytes),
        Err(e) => {
            return Err(e);
        }
    };
    
    // 确定要使用的密码短语
    let passphrase_opt: Option<Zeroizing<String>> = match passphrase_opt_from_creat {
        Some(passphrase) => Some(passphrase),
        None => {
            match read_passphrase_interactive_once() {
                Ok(passphrase) => Some(passphrase),
                Err(e) => {
                    my_eprintln!("Error reading passphrase: {}", e);
                    return Err(e);
                }
            }
        }
    };
    
    // 处理密码短语
    let result = match passphrase_opt {
        Some(passphrase) if !passphrase.is_empty() => {
            // 尝试用密码短语解密密钥
            match decrypt_key_with_passphrase(bytes, passphrase) {
                Ok(decrypted_key) => {
                    Ok(decrypted_key)
                }
                Err(_) => {
                    // 使用通用错误信息，避免泄露密码短语验证失败的具体原因
                    Err(anyhow!("Failed to load key. Please check your passphrase or key file."))
                }
            }
        } 
        _ => {
            // 没有密码短语，直接使用文件中的密钥 // 2025.12.24 不可能到这一步
            if bytes.len() != 32 {
                Err(anyhow!("Invalid key length: expected 32 bytes, got {}", bytes.len()))
            } else {
                let mut key_bytes: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
                key_bytes.copy_from_slice(&bytes);
                Ok(key_bytes)
            }
        }
    };
    result
}

/// 使用密码短语解密密钥（改进版）
fn decrypt_key_with_passphrase(encrypted_data: Zeroizing<Vec<u8>>, passphrase: Zeroizing<String>) -> Result<Zeroizing<[u8; 32]>> {
    if encrypted_data.len() < SALT_LENGTH + 24 {
        return Err(anyhow!("Invalid encrypted key data (too short)"));
    }
    
    // 分离 salt、xnonce 和加密的密钥
    let (salt_bytes, rest) = encrypted_data.split_at(SALT_LENGTH);
    let (xnonce_bytes, encrypted_key) = rest.split_at(24);

    // 派生密钥 - 使用 hash_password_into 直接写入可变数组
    let mut key_encryption_key_bytes: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
    my_argon2_into(passphrase.as_bytes(), salt_bytes, key_encryption_key_bytes.as_mut())
        .map_err(|_e| anyhow!("Failed to derive key for key decryption"))?;
    
    // 使用 XChaCha20Poly1305 解密密钥
    let cipher = MyCipher::new(key_encryption_key_bytes.as_ref())?;
    let xnonce = MyXnonce::try_from_slice(xnonce_bytes)?;
    
    // 解密密钥
    let decrypted_key: Zeroizing<Vec<u8>> = match cipher.decrypt(&xnonce, encrypted_key) {
        Ok(decrypted) => decrypted,
        Err(_) => {
            return Err(anyhow!("Failed to decrypt key with passphrase"));
        }
    };
    
    if decrypted_key.len() != 32 {
        return Err(anyhow!("Decrypted key has wrong length: {} bytes", decrypted_key.len()));
    }
    
    let mut key_bytes: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
    key_bytes.copy_from_slice(&decrypted_key);
    
    Ok(key_bytes)
}

