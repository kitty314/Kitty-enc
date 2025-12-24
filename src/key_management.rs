use anyhow::{anyhow, Context, Result};
use chacha20poly1305::Key;
use rand::rngs::OsRng;
use rand::TryRngCore;
use std::fs::{self};
use std::path::{Path, PathBuf};
use chrono::Local;
use zeroize::Zeroize;

use crate::*;

pub fn generate_key_file(path: &Path, passphrase_opt: Option<&str>) -> Result<()> {
    // 总是生成随机密钥
    let mut key_bytes = [0u8; 32];
    if let Err(e) = OsRng.try_fill_bytes(&mut key_bytes) {
        return Err(e).context("Failed to generate random key");
    }
    
    let mut key_data = prepare_key_data(&key_bytes, passphrase_opt)?;// 如果失败这一次密钥生成就失败了,应该不需要清理内存
    
    // 安全擦除密钥内存
    key_bytes.zeroize();
    
    // 写入密钥文件，如果失败则清理内存
    if let Err(e) = fs::write(path, &key_data).with_context(|| format!("Failed to write key file: {}", path.display())) {
        // 安全擦除密钥数据内存 (感觉是冗余的, 根本没有写入成功)
        key_data.zeroize();
        return Err(e);
    }
    
    // 写入成功，清理内存
    key_data.zeroize();
    Ok(())
}

/// 准备密钥数据，根据是否使用密码短语进行相应处理
pub fn prepare_key_data(key_bytes: &[u8; 32], passphrase_opt: Option<&str>) -> Result<Vec<u8>> {
    match passphrase_opt {
        Some(passphrase) if !passphrase.is_empty() => {
            // 使用密码短语加密密钥
            encrypt_key_with_passphrase(key_bytes, passphrase)
        }
        _ => {
            // 没有密码短语或密码短语为空，直接存储原始密钥
            Ok(key_bytes.to_vec())
        }
    }
}

pub fn generate_key_filename(dir: &Path) -> String {
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

/// 在指定目录中查找现有的密钥文件
/// 如果找到多个密钥文件，返回错误要求用户手动指定
pub fn find_existing_key_file(dir: &Path) -> Result<Option<PathBuf>> {
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
            eprintln!("Found multiple key files in directory: {}", dir.display());
            for key_file in &key_files {
                eprintln!("  - {}", key_file.display());
            }
            Err(anyhow!("Multiple key files found. Please specify which key file to use with -k option."))
        }
    }
}

/// 获取或创建密钥文件路径（公共函数）
pub fn get_or_create_key_path(
    target_dir_or_file: &Path,
    key_opt: &Option<PathBuf>,
    operation: &str,
) -> Result<(PathBuf,Option<String>)> {
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
                    println!("Using existing key in {} directory: {}", operation, existing_key.display());
                    Ok((existing_key,None))
                }
                Ok(None) => {
                    if operation == "decryption" || operation == "fix" {
                        return Err(anyhow!("No key file found in {} directory. Please specify key file with -k option.", operation));
                    }
                    // 没有现有密钥文件，生成新的（生成在目标目录中）
                    let key_filename = generate_key_filename(target_dir);
                    let p = target_dir.join(key_filename);
                    println!("No key file found in {} directory. Generating new key file: {}", operation, p.display());
                    let mut passphrase_opt = match read_passphrase_interactive() {
                        Ok(passphrase) => Some(passphrase),
                        Err(e) => {
                            eprintln!("Error reading passphrase: {}", e);
                            return Err(e);
                        }
                    };
                    if let Err(e) = generate_key_file(&p, passphrase_opt.as_deref()){
                        passphrase_opt.zeroize();
                        return Err(e);
                    }
                    
                    println!("Generated key: {}", p.display());
                    Ok((p, passphrase_opt))
                }
                Err(e) => Err(e), // 处理 find_existing_key_file 返回的错误
            }
        }
    }
}

pub fn load_key(path: &Path, mut passphrase_opt_from_creat: Option<String>) -> Result<Key> {
    let mut bytes = match fs::read(path).with_context(|| format!("Failed to read key file: {}", path.display())) {
        Ok(bytes) => bytes,
        Err(e) => {
            // 清理传入的密码短语
            passphrase_opt_from_creat.zeroize();
            return Err(e);
        }
    };
    
    // 确定要使用的密码短语
    let mut passphrase_opt = match passphrase_opt_from_creat {
        Some(passphrase) => Some(passphrase),
        None => {
            match read_passphrase_interactive_once() {
                Ok(passphrase) => Some(passphrase),
                Err(e) => {
                    eprintln!("Error reading passphrase: {}", e);
                    // 清理已读取的文件数据
                    bytes.zeroize();
                    return Err(e);
                }
            }
        }
    };
    
    // 处理密码短语
    let result = if let Some(passphrase) = passphrase_opt.as_ref() {
        if !passphrase.is_empty() {
            // 尝试用密码短语解密密钥
            match decrypt_key_with_passphrase(&bytes, passphrase) {
                Ok(mut decrypted_key) => {
                    let key = Key::from_slice(&decrypted_key).to_owned();
                    // 安全擦除解密后的密钥数据
                    decrypted_key.zeroize();
                    Ok(key)
                }
                Err(_) => {
                    // 使用通用错误信息，避免泄露密码短语验证失败的具体原因
                    Err(anyhow!("Failed to load key. Please check your passphrase or key file."))
                }
            }
        } else {
            // 密码短语为空，直接使用文件中的密钥
            if bytes.len() != 32 {
                Err(anyhow!("Invalid key length: expected 32 bytes, got {}", bytes.len()))
            } else {
                Ok(Key::from_slice(&bytes).to_owned())
            }
        }
    } else {
        // 没有密码短语，直接使用文件中的密钥 // 2025.12.24 不可能到这一步
        if bytes.len() != 32 {
            Err(anyhow!("Invalid key length: expected 32 bytes, got {}", bytes.len()))
        } else {
            Ok(Key::from_slice(&bytes).to_owned())
        }
    };
    
    // 安全擦除内存
    // if let Some(mut passphrase) = passphrase_opt.take() {
    //     passphrase.zeroize();
    // }
    passphrase_opt.zeroize();
    bytes.zeroize();
    
    result
}

/// 安全地读取密码短语（交互式输入，不显示在屏幕上）
fn read_passphrase_interactive() -> Result<String> {
    // 第一次读取密码
    let mut passphrase = match read_password_utf8("Enter passphrase (input will be hidden)") {
        Ok(p) => p,
        Err(e) => {
            // 读取失败，没有密码需要清理
            return Err(e);
        }
    };
    
    // 如果第一次输入为空，给第二次确认机会
    if passphrase.is_empty() {
        match read_password_utf8("Empty passphrase entered. Press Enter again to confirm no passphrase, or enter a passphrase") {
            Ok(second_input) => {
                // 如果第二次输入非空，则使用第二次输入作为密码短语
                if !second_input.is_empty() {
                    // 安全擦除第一次输入的密码（空字符串）
                    passphrase.zeroize();
                    passphrase = second_input;
                }
                // 如果第二次输入也为空，保持 passphrase 为空
            }
            Err(e) => {
                // 读取第二次输入失败，清理第一次输入的密码
                passphrase.zeroize();
                return Err(e);
            }
        }
    }
    
    // 如果密码非空，需要确认
    if !passphrase.is_empty() {
        // 确认密码短语
        let mut confirm = match read_password_utf8("Confirm passphrase") {
            Ok(c) => c,
            Err(e) => {
                // 读取确认密码失败，清理主密码
                passphrase.zeroize();
                return Err(e);
            }
        };
        
        if passphrase != confirm {
            // 密码不匹配，清理两个密码
            passphrase.zeroize();
            confirm.zeroize();
            return Err(anyhow::anyhow!("Passphrases do not match"));
        }
        
        // 密码匹配，清理确认密码
        confirm.zeroize();
        
        // 返回主密码（调用者负责清理）
        return Ok(passphrase);
    }
    
    // 密码为空，直接返回（空字符串不需要特殊清理）
    Ok(passphrase)
}

/// 安全地读取密码短语一次（交互式输入，不显示在屏幕上）
fn read_passphrase_interactive_once() -> Result<String> {
    let passphrase = read_password_utf8("Enter passphrase (input will be hidden)")?;
    Ok(passphrase)
}

/// 安全地读取密码（交互式输入，不显示在屏幕上），一直读取直到输入非空
pub fn read_passwd_interactive() -> Result<String> {
    loop {
        // 读取密码
        let mut passwd = match read_password_utf8("Enter password (input will be hidden)") {
            Ok(p) => p,
            Err(e) => {
                // 读取失败，没有密码需要清理
                return Err(e);
            }
        };
        
        // 如果密码为空，提示并重新输入
        if passwd.is_empty() {
            println!("Password cannot be empty. Please try again.");
            passwd.zeroize();
            continue;
        }
        
        // 确认密码
        let mut confirm = match read_password_utf8("Confirm password") {
            Ok(c) => c,
            Err(e) => {
                // 读取确认密码失败，清理主密码
                passwd.zeroize();
                return Err(e);
            }
        };
        
        if passwd != confirm {
            // 密码不匹配，清理两个密码
            passwd.zeroize();
            confirm.zeroize();
            return Err(anyhow::anyhow!("Passphrases do not match"));
            // println!("Passwords do not match. Please try again.");
            // continue;
        }
        
        // 密码匹配，清理确认密码
        confirm.zeroize();
        
        // 返回密码（调用者负责清理）
        return Ok(passwd);
    }
}

/// 安全地读取密码一次（交互式输入，不显示在屏幕上）
pub fn read_passwd_interactive_once() -> Result<String> {
    loop {
        let passwd = read_password_utf8("Enter password (input will be hidden)")?;
        
        // 如果密码为空，提示并重新输入
        if passwd.is_empty() {
            println!("Password cannot be empty. Please try again.");
            continue;
        }
        
        return Ok(passwd);
    }
}

/// 读取密码并正确处理 UTF-8 编码（使用 dialoguer 库）
fn read_password_utf8(prompt:&str) -> Result<String> {
    let result = dialoguer::Password::new()
        .with_prompt(prompt)
        .allow_empty_password(true)
        .interact()
        .map_err(|e| anyhow::anyhow!("Failed to read password: {}", e));
        // 检查中断标志
    if crate::cli::is_interrupted() {
        if let Ok(mut passwd) = result {
            println!("Cleaning up what you've typed...");
            passwd.zeroize();
        }
        println!("The program may report some errors, but don't worry.");
        return Err(anyhow!("User interrupted. Goodbye."));
    }
    result
}

/// 简化的密钥派生函数：从主密钥和salt派生子密钥（32字节）
/// 使用Argon2id：subkey = Argon2id(master_key, salt)
pub fn derive_subkey_simple(master_key: &[u8; 32], salt: &[u8]) -> Result<[u8; 32]> {
    use argon2::{self, Argon2};
    
    // 使用 Argon2id 派生密钥
    let params = match argon2::Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, None) {
        Ok(params) => params,
        Err(_) => {
            return Err(anyhow!("Failed to create Argon2 parameters during subkey derivation"));
        }
    };
    
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params,
    );
    
    // 派生密钥 - 使用 hash_password_into 直接写入可变数组
    let mut subkey = [0u8; 32];
    if let Err(_) = argon2.hash_password_into(master_key, salt, &mut subkey) {
        subkey.zeroize();
        return Err(anyhow!("Failed to derive subkey"));
    }
    
    Ok(subkey)
}

/// 从密码派生密钥（32字节）
/// 使用Argon2id密钥派生函数，使用密码作为salt (16字节)，如果密码太短则补0
pub fn derive_key_from_password(mut password: String) -> Result<Key> {
    use argon2::{self, Argon2};
    
    // 使用 Argon2id 派生密钥
    let params = match argon2::Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, None) {
        Ok(params) => params,
        Err(_e) => {
            password.zeroize();
            return Err(anyhow!("Failed to create Argon2 parameters for deriving key from password"));
        }
    };
    
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params,
    );
    
    // 使用密码作为salt，如果密码太短则补0到16字节
    let password_bytes = password.as_bytes();
    let mut salt_bytes = [0u8; SALT_LENGTH];
    
    // 复制密码字节到salt数组，如果密码长度小于16则剩余部分保持为0
    let copy_len = std::cmp::min(password_bytes.len(), SALT_LENGTH);
    salt_bytes[..copy_len].copy_from_slice(&password_bytes[..copy_len]);
    
    // 派生密钥 - 使用 hash_password_into 直接写入可变数组
    let mut key_bytes = [0u8; 32];
    if let Err(_e) = argon2.hash_password_into(password_bytes, &salt_bytes, &mut key_bytes) {
        password.zeroize();
        key_bytes.zeroize();
        salt_bytes.zeroize();
        return Err(anyhow!("Failed to derive key from password"));
    }
    
    let key = Key::from_slice(&key_bytes).to_owned();
    
        // 安全擦除密码和密钥字节数组
    password.zeroize();
    key_bytes.zeroize();
    salt_bytes.zeroize();
    
    Ok(key)
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
pub fn derive_key_from_any_file(
    file_path: &Path,
    use_password: bool,
    need_confirm: bool,
) -> Result<Key> {
    use argon2::{self, Argon2};
    
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

    // 配置Argon2
    let params = match argon2::Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, None) {
        Ok(params) => params,
        Err(_e) => {
            return Err(anyhow!("Failed to create Argon2 params for deriving key from any file"));
        }
    };
    
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params,
    );

    // 获取密码
    let mut password = if use_password {
        if need_confirm {
            read_passwd_interactive()?
        } else {
            read_passwd_interactive_once()?
        }
    } else {
        String::new()
    };

    // 读取文件至多前1MB内容
    let mut file = match fs::File::open(file_path) {
        Ok(f) => f,
        Err(e) => {
            password.zeroize();
            return Err(e).with_context(|| format!("Failed to open file: {}", file_path.display()));
        }
    };
    
    // 限制读取大小为1MB
    let read_size = std::cmp::min(metadata.len(), ANY_FILE_MAX_READ_SIZE as u64) as usize;
    
    let mut file_data = vec![0u8; read_size];
    use std::io::Read;
    if let Err(e) = file.read_exact(&mut file_data) {
        password.zeroize();
        file_data.zeroize();
        return Err(e).with_context(|| format!("Failed to read file data: {}", file_path.display()));
    }
    
    
    // 准备盐：如果不使用密码，使用文件前16字节作为盐；如果使用密码，使用密码派生密钥作为盐
    let mut salt: Vec<u8>;
    
    if use_password {
        // 使用密码派生密钥作为盐
        let mut salt_from_passwd = [0u8;32];
        if let Err(_e) = argon2.hash_password_into(password.as_bytes(), &file_data, &mut salt_from_passwd) {
            password.zeroize();
            file_data.zeroize();
            salt_from_passwd.zeroize();
            return Err(anyhow!("Failed to derive salt from password"));
        }
        salt = salt_from_passwd.to_vec();
        salt_from_passwd.zeroize();
    } else {
        // 使用文件前16字节作为盐
        let copy_len = std::cmp::min(file_data.len(), SALT_LENGTH);
        salt = file_data[..copy_len].to_vec();
    }
    
    
    // 派生密钥 - 使用 hash_password_into 直接写入可变数组
    let mut key_bytes = [0u8; 32];
    if let Err(_e) = argon2.hash_password_into(&file_data, &salt, &mut key_bytes) {
        password.zeroize();
        file_data.zeroize();
        key_bytes.zeroize();
        salt.zeroize();
        return Err(anyhow!("Failed to derive key from any file"));
    }
    
    let key = Key::from_slice(&key_bytes).to_owned();
    
    // 安全擦除所有敏感数据
    password.zeroize();
    file_data.zeroize();
    key_bytes.zeroize();
    salt.zeroize();
    
    Ok(key)
}

