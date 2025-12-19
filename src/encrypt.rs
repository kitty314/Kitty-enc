use anyhow::{anyhow, Context, Result};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::TryRngCore;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use sha2::{Sha256, Digest};
use argon2::{self, Argon2};
use zeroize::Zeroize;
use rayon::prelude::*;  // 添加 rayon 并行处理
use ignore::WalkBuilder;
use ignore::DirEntry as ignore_DirEntry;

use crate::*;

pub fn encrypt_file(path: &Path, master_key: &Key) -> Result<i32> {
    // 检查中断标志
    if crate::cli::is_interrupted() {
        println!("Interrupt signal received, skipping encryption of {}", path.display());
        return Ok(1);
    }
    
    // 检查文件是否可访问
    if let Err(_e) = fs::OpenOptions::new().read(true).write(true).open(path) {
        eprintln!("Warning: File {} cannot be opened (file open exception).", path.display());
        return Ok(2); // 返回特殊代码表示文件打开异常
    }
    
    // Write to new file with .kitty_enc suffix // 2025.12.6 已检查, 应当相当于直接追加后缀, 包括.开头的文件
    let mut out_path = PathBuf::from(path);
    if let Some(orig_ext) = path.extension() {
        // keep original base, add dual extension: .orig + .kitty_enc
        let mut s = orig_ext.to_os_string();
        s.push(format!(".{}", ENC_SUFFIX));
        out_path.set_extension(s);
    } else {
        out_path.set_extension(ENC_SUFFIX);
    };

    // 检查加密目标文件是否已经存在，存在则跳过
    if out_path.exists() {
        eprintln!("Warning: Target encrypted file {} already exists, you need to fix it", out_path.display());
        return Ok(3); // 返回代码3表示目标文件已存在而跳过
    }

    // 读取源文件并计算哈希
    let mut data = Vec::new();
    File::open(path)
        .with_context(|| format!("Failed to open file for encryption: {}", path.display()))?
        .read_to_end(&mut data)
        .with_context(|| format!("Failed to read file: {}", path.display()))?;
    
    // 计算源文件的 SHA256 哈希用于完整性验证
    let mut hasher = Sha256::new();
    hasher.update(&data);
    let original_hash = hasher.finalize();

    // Random XNonce per file (24 bytes)
    let mut xnonce_bytes = [0u8; 24];
    if let Err(e) = OsRng.try_fill_bytes(&mut xnonce_bytes) {
        // 安全擦除文件数据（虽然不是密钥材料，但出于安全考虑）
        data.zeroize();
        return Err(e).context("Failed to generate random nonce for file encryption");
    }
    let xnonce = XNonce::from_slice(&xnonce_bytes);
    
    // 使用主密钥和nonce作为盐派生子密钥
    let mut subkey = derive_subkey_simple(master_key.as_slice().try_into().unwrap(), &xnonce_bytes)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&subkey));

    let ct = match cipher.encrypt(xnonce, data.as_ref()) {
        Ok(ct) => ct,
        Err(_) => {
            // 安全擦除敏感数据
            data.zeroize();
            xnonce_bytes.zeroize();
            subkey.zeroize();
            return Err(anyhow!("Encryption failed for {}", path.display()));
        }
    };

    // Output: [xnonce (24 bytes) || 4 bytes 0 (普通加密标记) || ciphertext || original_hash]
    let mut out = Vec::with_capacity(24 + 4 + ct.len() + 32);
    out.extend_from_slice(&xnonce_bytes);
    out.extend_from_slice(&[0u8; 4]); // 普通加密标记：4字节0
    out.extend_from_slice(&ct);
    out.extend_from_slice(&original_hash);

    // 先写入加密文件
    if let Err(e) = fs::write(&out_path, &out)
        .with_context(|| format!("Failed to write encrypted file: {}", out_path.display()))
    {
        // 安全擦除敏感数据
        data.zeroize();
        xnonce_bytes.zeroize();
        subkey.zeroize();
        out.zeroize();
        // 清理可能已创建的加密文件
        fs::remove_file(&out_path).ok();
        return Err(e);
    };

    // 文件写入成功后，立即清理加密时使用的内存
    data.zeroize();
    xnonce_bytes.zeroize();
    subkey.zeroize();
    out.zeroize();

    // 验证加密文件是否写入成功
    if let Err(e) = verify_file_not_empty(&out_path) {
        fs::remove_file(&out_path).ok(); // 清理无效的加密文件
        return Err(e);
    };

    // 验证加密文件可以正确解密
    let encrypted_data = match read_file_for_verification(&out_path) {
        Ok(data) => data,
        Err(e) => {
        fs::remove_file(&out_path).ok(); // 清理无效的加密文件
        return Err(e);
        }
    };

    if encrypted_data.len() < 24 + 4 + 32 {
        fs::remove_file(&out_path).ok(); // 清理无效的加密文件
        return Err(anyhow!("Encrypted file is corrupted: {}", out_path.display()));
    }

    // 分离 xnonce、加密类型标记、密文和哈希
    let (xnonce_bytes_verify, rest) = encrypted_data.split_at(24);
    let (enc_type_marker_verify, rest) = rest.split_at(4);
    let (ct_verify, stored_hash_bytes) = rest.split_at(rest.len() - 32);
    
    // 检查加密类型标记
    if enc_type_marker_verify != [0u8; 4] {
        fs::remove_file(&out_path).ok(); // 清理无效的加密文件
        return Err(anyhow!("Invalid encryption type marker in encrypted file: {}", out_path.display()));
    }
    
    // 验证时使用相同的子密钥派生方法
    let mut subkey_verify = derive_subkey_simple(master_key.as_slice().try_into().unwrap(), xnonce_bytes_verify)?;
    let cipher_verify = XChaCha20Poly1305::new(Key::from_slice(&subkey_verify));
    
    let xnonce_verify = XNonce::from_slice(xnonce_bytes_verify);
    let mut pt_verify = cipher_verify
        .decrypt(xnonce_verify, ct_verify)
        .map_err(|_| {
            // 安全擦除敏感数据
            subkey_verify.zeroize();
            fs::remove_file(&out_path).ok(); // 清理无效的加密文件
            anyhow!("Encryption verification failed for {}", out_path.display())
        })?;

    // 验证解密后的数据哈希是否匹配
    let mut hasher_verify = Sha256::new();
    hasher_verify.update(&pt_verify);
    let decrypted_hash = hasher_verify.finalize();
    
    if decrypted_hash.as_slice() != stored_hash_bytes {
        // 安全擦除敏感数据
        subkey_verify.zeroize();
        pt_verify.zeroize();
        fs::remove_file(&out_path).ok(); // 清理无效的加密文件
        return Err(anyhow!("Integrity check failed for encrypted file: {}", out_path.display()));
    }

    // 安全擦除剩余敏感数据
    subkey_verify.zeroize();
    pt_verify.zeroize();

    // 只有加密文件验证成功后才删除源文件 
    // 2025.12.11 remove_file 是原子操作，不会出现“原文件删一半失败”的情况。
    // 失败时文件保持完整，成功时整个目录项被移除。
    if let Err(e) = fs::remove_file(path) {
        // 如果删除原文件失败，清理已创建的加密文件
        fs::remove_file(&out_path).ok();
        return Err(e).with_context(|| format!("Failed to remove original file: {}", path.display()));
    }

    println!("Encrypted (original removed, integrity verified): {}", path.display());
    Ok(0)
}

/// 使用密码短语加密密钥（改进版）
pub fn encrypt_key_with_passphrase(key: &[u8; 32], passphrase: &str) -> Result<Vec<u8>> {
    // 生成随机 salt
    let mut salt_bytes = [0u8; SALT_LENGTH];
    if let Err(e) = OsRng.try_fill_bytes(&mut salt_bytes) {
        return Err(e).context("Failed to generate random salt for key encryption");
    }
    
    // 使用 Argon2id 派生密钥加密密钥
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, None)
            .map_err(|_e| anyhow!("Failed to create Argon2 params for key encryption"))?,
    );
    
    // 派生密钥 - 使用 hash_password_into 直接写入可变数组
    let mut key_encryption_key_bytes = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), &salt_bytes, &mut key_encryption_key_bytes)
        .map_err(|_e| anyhow!("Failed to derive key for key encryption"))?;
    
    // 使用 XChaCha20Poly1305 加密密钥
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key_encryption_key_bytes));
    
    // 随机 xnonce
    let mut xnonce_bytes = [0u8; 24];
    if let Err(e) = OsRng.try_fill_bytes(&mut xnonce_bytes) {
        // 安全擦除敏感数据
        salt_bytes.zeroize();
        key_encryption_key_bytes.zeroize();
        return Err(e).context("Failed to generate random nonce for key encryption");
    }
    let xnonce = XNonce::from_slice(&xnonce_bytes);
    
    // 加密密钥
    let encrypted_key = match cipher.encrypt(xnonce, key.as_ref()) {
        Ok(encrypted) => encrypted,
        Err(_) => {
            // 安全擦除敏感数据
            salt_bytes.zeroize();
            xnonce_bytes.zeroize();
            key_encryption_key_bytes.zeroize();
            return Err(anyhow!("Failed to encrypt key with passphrase"));
        }
    };
    
    // 输出格式: [salt (SALT_LENGTH bytes) || xnonce (24 bytes) || encrypted_key]
    let mut output = Vec::with_capacity(SALT_LENGTH + 24 + encrypted_key.len());
    output.extend_from_slice(&salt_bytes);
    output.extend_from_slice(&xnonce_bytes);
    output.extend_from_slice(&encrypted_key);
    
    // 安全擦除敏感数据的内存
    salt_bytes.zeroize();
    xnonce_bytes.zeroize();
    key_encryption_key_bytes.zeroize();
    
    Ok(output)
}


pub fn process_encrypt_dir(dir: &Path, master_key: &Key, key_path_opt: Option<&Path>, exe_path: &Path) -> Result<i32> {
    // 收集所有需要处理的文件
    let mut files_to_process = Vec::new();
    let mut skipped_empty_count = 0;
    
    // 规范化 exe_path
    let canon_exe_path = fs::canonicalize(exe_path)
        .with_context(|| format!("Failed to canonicalize exe_path: {}", exe_path.display()))?;

    // 规范化 key_path_opt（如果存在）
    let canon_key_path_opt= match key_path_opt {
        Some(kp) => {
            let canon = fs::canonicalize(kp)
                .with_context(|| format!("Failed to canonicalize key_path: {}", kp.display()))?;
            Some(canon)
        }
        None => None,
    };

    for entry in WalkBuilder::new(dir)
        .add_custom_ignore_filename(".kitignore")
        .git_ignore(false)
        .follow_links(false)
        .filter_entry(|e: &ignore_DirEntry| ignore_filter_entry(e))
        .build()
    {
        // 检查中断标志
        if crate::cli::is_interrupted() {
            println!("Interrupt signal received, stopping file collection");
            return Ok(1);
        }
        
        let entry = entry?;
        let path = entry.path();

        if entry.file_type().unwrap().is_file() {
            // 先判断是文件再规范化
            let canon_path = fs::canonicalize(path)
                .with_context(|| format!("Failed to canonicalize path: {}", path.display()))?;
            // Skip conditions 
            if canon_is_self(&canon_path, &canon_exe_path)? || canon_is_key_file(&canon_path, canon_key_path_opt.as_deref())? || is_encrypted_file(path) {
                continue;
            }
            let size = entry.metadata()?.len();
            
            // 跳过空文件
            if size == 0 {
                skipped_empty_count += 1;
                continue;
            }
            
            // 2025.12.11 注意不能输入规范化的path，否则软链接会在实际目录下生成加密文件
            // 对于软链接，is_file()会返回false，直接跳过，除非WalkBuilder指定输入为软链接
            files_to_process.push((path.to_path_buf(), size));
        }
    }
    
    println!("Found {} files to process, {} empty files skipped", files_to_process.len(), skipped_empty_count);
    
    if files_to_process.is_empty() {
        println!("No files to encrypt.");
        return Ok(0);
    }
    
    // 使用 rayon 并行处理文件
    let results: Vec<Result<i32>> = files_to_process
        .par_iter()
        .map(|(path, size)| {
            // 检查中断标志，如果已中断则跳过此文件
            if crate::cli::is_interrupted() {
                println!("Skipping {} due to interrupt signal", path.display());
                return Ok(1);
            }
            
            // 根据文件大小选择加密方式
            let result = if *size <= STREAMING_THRESHOLD {
                // ≤10MB：使用内存加密（并行处理）
                encrypt_file(path, master_key)
            } else {
                // >10MB：使用流式加密（串行处理，但可以与其他文件并行）
                encrypt_file_streaming(path, master_key)
            };
            
            match &result {
                Ok(code) => {
                    match code {
                        // 0 => (), // 成功加密，不打印
                        // 1 => println!("Skipped {} due to interrupt", path.display()),
                        // 2 => println!("Skipped {} (file open exception)", path.display()),
                        // 3 => println!("Skipped {} (target exists)", path.display()),
                        _ => (),
                    }
                }
                Err(e) => {
                    eprintln!("Error encrypting {}: {}", path.display(), e);
                }
            }
            result
        })
        .collect();
    
    // 统计结果
    let mut success_count = 0;
    let mut skipped_interrupt_count = 0;
    let mut skipped_open_exception_count = 0;
    let mut skipped_target_exists_count = 0;
    let mut error_count = 0;
    
    for result in &results {
        match result {
            Ok(code) => match code {
                0 => success_count += 1,
                1 => skipped_interrupt_count += 1,
                2 => skipped_open_exception_count += 1,
                3 => skipped_target_exists_count += 1,
                _ => error_count += 1,
            },
            Err(_) => error_count += 1,
        }
    }
    
    println!("Encryption summary:");
    println!("  Found {} files to encrypt", files_to_process.len());
    println!("  Successfully encrypted: {} files", success_count);
    println!("  Skipped (interrupted): {} files", skipped_interrupt_count);
    println!("  Skipped (file open exception): {} files", skipped_open_exception_count);
    println!("  Skipped (target exists): {} files", skipped_target_exists_count);
    println!("  Failed: {} files", error_count);
    println!("  Empty files skipped: {} files", skipped_empty_count);
    
    // 如果存在目标文件已存在的警告，打印额外提示
    if skipped_target_exists_count > 0 {
        println!("Warning: {} Target encrypted file already exists, you need to fix it", skipped_target_exists_count);
    }
    
    // // 如果有错误，返回第一个错误
    // for result in results {
    //     if let Err(e) = result {
    //         return Err(e);
    //     }
    // }
    
    Ok(0)
}

/// 流式加密大文件（使用 XChaCha20Poly1305）
pub fn encrypt_file_streaming(path: &Path, master_key: &Key) -> Result<i32> {
    use std::io::{BufReader, BufWriter, Write, Read};
    
    // 检查文件是否可访问
    if let Err(_e) = fs::OpenOptions::new().read(true).write(true).open(path) {
        eprintln!("Warning: File {} cannot be opened (file open exception).", path.display());
        return Ok(2); // 返回特殊代码表示文件打开异常
    }

    // 创建输出文件路径
    let mut out_path = PathBuf::from(path);
    if let Some(orig_ext) = path.extension() {
        let mut s = orig_ext.to_os_string();
        s.push(format!(".{}", ENC_SUFFIX));
        out_path.set_extension(s);
    } else {
        out_path.set_extension(ENC_SUFFIX);
    };

    // 检查加密目标文件是否已经存在，存在则跳过
    if out_path.exists() {
        eprintln!("Warning: Target encrypted file {} already exists, you need to fix it", out_path.display());
        return Ok(3); // 返回代码3表示目标文件已存在而跳过
    }

    // 打开源文件
    let source_file = File::open(path)
        .with_context(|| format!("Failed to open file for streaming encryption: {}", path.display()))?;
    let mut reader = BufReader::new(source_file);
      
    // 创建输出文件
    let out_file = File::create(&out_path)
        .with_context(|| format!("Failed to create encrypted file: {}", out_path.display()))?;
    let mut writer = BufWriter::new(out_file);
    
    // 生成 24 字节的扩展 nonce
    let mut xnonce_bytes = [0u8; 24];
    if let Err(e) = OsRng.try_fill_bytes(&mut xnonce_bytes) {
        // 清理已创建的加密文件
        fs::remove_file(&out_path).ok();
        return Err(e).context("Failed to generate random nonce for streaming encryption");
    }
    
    // 使用主密钥和nonce作为盐派生子密钥
    let mut subkey = derive_subkey_simple(master_key.as_slice().try_into().unwrap(), &xnonce_bytes)?;
    
    // 使用 XChaCha20Poly1305 进行流式加密
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&subkey));
    
    // 先写入 nonce
    if let Err(e) = writer.write_all(&xnonce_bytes) {
        // 安全擦除敏感数据
        xnonce_bytes.zeroize();
        subkey.zeroize();
        // 清理已创建的加密文件
        fs::remove_file(&out_path).ok();
        return Err(e).with_context(|| format!("Failed to write nonce to encrypted file: {}", out_path.display()));
    }
    
    // 缓冲区大小：1MB
    let mut buffer = vec![0u8; STREAMING_CHUNK_SIZE];
    let mut hasher = Sha256::new();
    
    // 块计数器，用于生成唯一的 nonce
    let mut block_counter: u64 = 0;
    
    // 流式读取、计算哈希、加密、写入
    loop {
        // 检查中断标志
        if crate::cli::is_interrupted() {
            println!("Interrupt signal received, stopping encryption of {}", path.display());
            // 安全擦除敏感数据
            buffer.zeroize();
            xnonce_bytes.zeroize();
            subkey.zeroize();
            // 清理已创建的加密文件
            fs::remove_file(&out_path).ok();
            return Ok(1); // 返回成功，表示已停止处理
        }
        
        let bytes_read = match reader.read(&mut buffer) {
            Ok(bytes) => bytes,
            Err(e) => {
                // 安全擦除敏感数据
                buffer.zeroize();
                xnonce_bytes.zeroize();
                subkey.zeroize();
                // 清理已创建的加密文件
                fs::remove_file(&out_path).ok();
                return Err(e).with_context(|| format!("Failed to read from source file: {}", path.display()));
            }
        };
        
        if bytes_read == 0 {
            break;
        }
        
        // 更新哈希
        hasher.update(&buffer[..bytes_read]);
        
        // 为每个块生成唯一的 nonce：使用主 nonce + 块计数器拼接
        // XNonce 是 24 字节，我们使用前 16 字节作为主 nonce，后 8 字节作为块计数器
        let mut block_nonce_bytes = [0u8; 24];
        
        // 复制主 nonce 的前 16 字节
        block_nonce_bytes[..16].copy_from_slice(&xnonce_bytes[..16]);
        
        // 后 8 字节使用块计数器的 LE 编码
        let counter_bytes = block_counter.to_le_bytes();
        block_nonce_bytes[16..].copy_from_slice(&counter_bytes);
        
        let block_nonce = XNonce::from_slice(&block_nonce_bytes);
        
        // 加密当前块
        let ct = cipher.encrypt(block_nonce, &buffer[..bytes_read])
            .map_err(|_| {
                // 安全擦除敏感数据
                buffer.zeroize();
                xnonce_bytes.zeroize();
                subkey.zeroize();
                // 清理已创建的加密文件
                fs::remove_file(&out_path).ok();
                anyhow!("Encryption failed for block {} in file: {}", block_counter, path.display())
            })?;
        
        // 写入加密块大小（4字节）和加密块数据
        let ct_len = ct.len() as u32;
        if let Err(e) = writer.write_all(&ct_len.to_le_bytes()) {
            // 安全擦除敏感数据
            buffer.zeroize();
            xnonce_bytes.zeroize();
            subkey.zeroize();
            // 清理已创建的加密文件
            fs::remove_file(&out_path).ok();
            return Err(e).with_context(|| format!("Failed to write block size to file: {}", out_path.display()));
        }
        
        if let Err(e) = writer.write_all(&ct) {
            // 安全擦除敏感数据
            buffer.zeroize();
            xnonce_bytes.zeroize();
            subkey.zeroize();
            // 清理已创建的加密文件
            fs::remove_file(&out_path).ok();
            return Err(e).with_context(|| format!("Failed to write encrypted block to file: {}", out_path.display()));
        }
        
        block_counter += 1;
    }
    
    // 计算最终哈希
    let original_hash = hasher.finalize();
    
    // 写入结束标记：4字节0表示下一个块大小为0
    let end_marker: u32 = 0;
    if let Err(e) = writer.write_all(&end_marker.to_le_bytes()) {
        // 安全擦除敏感数据
        buffer.zeroize();
        xnonce_bytes.zeroize();
        subkey.zeroize();
        // 清理已创建的加密文件
        fs::remove_file(&out_path).ok();
        return Err(e).with_context(|| format!("Failed to write end marker to encrypted file: {}", out_path.display()));
    }
    
    // 写入哈希
    if let Err(e) = writer.write_all(&original_hash) {
        // 安全擦除敏感数据
        buffer.zeroize();
        xnonce_bytes.zeroize();
        subkey.zeroize();
        // 清理已创建的加密文件
        fs::remove_file(&out_path).ok();
        return Err(e).with_context(|| format!("Failed to write hash to encrypted file: {}", out_path.display()));
    }
    
    // 确保所有数据都写入磁盘
    if let Err(e) = writer.flush() {
        // 安全擦除敏感数据
        buffer.zeroize();
        xnonce_bytes.zeroize();
        subkey.zeroize();
        // 清理已创建的加密文件
        fs::remove_file(&out_path).ok();
        return Err(e).with_context(|| format!("Failed to flush encrypted file: {}", out_path.display()));
    }
    
    // 安全擦除敏感数据
    buffer.zeroize();
    xnonce_bytes.zeroize();
    subkey.zeroize();
    
    // 验证加密文件
    if let Err(e) = verify_file_not_empty(&out_path) {
        fs::remove_file(&out_path).ok();
        return Err(e);
    }
    
    // 流式验证加密文件
    let verify_file = match File::open(&out_path) {
        Ok(file) => file,
        Err(e) => {
            fs::remove_file(&out_path).ok();
            return Err(e).with_context(|| format!("Failed to open encrypted file for verification: {}", out_path.display()));
        }
    };
    let mut verify_reader = BufReader::new(verify_file);
    
    // 读取 nonce (24字节)
    let mut xnonce_bytes_verify = [0u8; 24];
    if let Err(e) = verify_reader.read_exact(&mut xnonce_bytes_verify) {
        // 安全擦除敏感数据
        xnonce_bytes_verify.zeroize();
        fs::remove_file(&out_path).ok();
        return Err(e).with_context(|| format!("Failed to read nonce from encrypted file: {}", out_path.display()));
    }
    
    // 验证时使用相同的子密钥派生方法
    let mut subkey_verify = derive_subkey_simple(master_key.as_slice().try_into().unwrap(), &xnonce_bytes_verify)?;
    let cipher_verify = XChaCha20Poly1305::new(Key::from_slice(&subkey_verify));
    
    let mut verify_block_counter: u64 = 0;
    let mut verify_hasher = Sha256::new();
    
    // 流式读取并验证每个加密块
    loop {
        // 检查中断标志
        if crate::cli::is_interrupted() {
            println!("Interrupt signal received, stopping verification of {}", out_path.display());
            // 安全擦除敏感数据
            subkey_verify.zeroize();
            // 清理已创建的加密文件
            fs::remove_file(&out_path).ok();
            return Ok(1); // 返回成功，表示已停止处理
        }
        
        // 读取块大小 (4字节)
        let mut block_size_bytes = [0u8; 4];
        if let Err(e) = verify_reader.read_exact(&mut block_size_bytes) {
            // 安全擦除敏感数据
            block_size_bytes.zeroize();
            subkey_verify.zeroize();
            fs::remove_file(&out_path).ok();
            return Err(e).with_context(|| format!("Failed to read block size from encrypted file: {}", out_path.display()));
        }
        
        let block_size = u32::from_le_bytes(block_size_bytes);
        
        // 如果块大小为0，表示文件结束
        if block_size == 0 {
            break;
        }
        
        let block_size = block_size as usize;
        
        // 读取加密块
        let mut encrypted_block = vec![0u8; block_size];
        if let Err(e) = verify_reader.read_exact(&mut encrypted_block) {
            // 安全擦除敏感数据
            encrypted_block.zeroize();
            subkey_verify.zeroize();
            fs::remove_file(&out_path).ok();
            return Err(e).with_context(|| format!("Failed to read encrypted block {} from file: {}", verify_block_counter, out_path.display()));
        }
        
        // 为当前块生成 nonce
        let mut block_nonce_bytes = [0u8; 24];
        
        // 复制主 nonce 的前 16 字节
        block_nonce_bytes[..16].copy_from_slice(&xnonce_bytes_verify[..16]);
        
        // 后 8 字节使用块计数器的 LE 编码
        let counter_bytes = verify_block_counter.to_le_bytes();
        block_nonce_bytes[16..].copy_from_slice(&counter_bytes);
        
        let block_nonce = XNonce::from_slice(&block_nonce_bytes);
        
        // 解密当前块
        let mut decrypted_block = cipher_verify.decrypt(block_nonce, encrypted_block.as_slice())
            .map_err(|_| {
                // 安全擦除敏感数据
                encrypted_block.zeroize();
                subkey_verify.zeroize();
                fs::remove_file(&out_path).ok();
                anyhow!("Encryption verification failed for block {}: {}", verify_block_counter, out_path.display())
            })?;
        
        // 更新验证哈希
        verify_hasher.update(&decrypted_block);

        // 安全擦除敏感数据 (注意subkey_verify, xnonce_bytes_verify下一轮要用, 不能清)
        encrypted_block.zeroize();
        block_nonce_bytes.zeroize();
        decrypted_block.zeroize();

        verify_block_counter += 1;
    }
    
    // 读取并验证哈希 (32字节)
    let mut stored_hash = [0u8; 32];
    if let Err(e) = verify_reader.read_exact(&mut stored_hash) {
        // 安全擦除敏感数据
        stored_hash.zeroize();
        subkey_verify.zeroize();
        fs::remove_file(&out_path).ok();
        return Err(e).with_context(|| format!("Failed to read hash from encrypted file: {}", out_path.display()));
    }
    
    let computed_hash = verify_hasher.finalize();
    
    if computed_hash.as_slice() != stored_hash {
        // 安全擦除敏感数据
        stored_hash.zeroize();
        subkey_verify.zeroize();
        fs::remove_file(&out_path).ok();
        return Err(anyhow!("Integrity check failed for encrypted file: {}", out_path.display()));
    }
    
    // 安全擦除验证子密钥
    subkey_verify.zeroize();
    
    // 只有加密文件验证成功后才删除源文件
    if let Err(e) = fs::remove_file(path) {
        // 如果删除原文件失败，清理已创建的加密文件
        fs::remove_file(&out_path).ok();
        return Err(e).with_context(|| format!("Failed to remove original file: {}", path.display()));
    }
    
    println!("Encrypted (streaming, original removed, integrity verified): {}", path.display());
    Ok(0)
}

