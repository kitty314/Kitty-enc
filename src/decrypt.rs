use anyhow::{Context, Result, anyhow};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
// use walkdir::WalkDir;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path};
use sha2::{Sha256, Digest};
use argon2::{self, Argon2};
use zeroize::Zeroize;
use rayon::prelude::*;  // 添加 rayon 并行处理
use ignore::WalkBuilder;
use ignore::DirEntry as ignore_DirEntry;

use crate::*;

pub fn decrypt_file(path: &Path, master_key: &Key) -> Result<i32> {
    // 检查中断标志
    if crate::cli::is_interrupted() {
        println!("Interrupt signal received, skipping decryption of {}", path.display());
        return Ok(1);
    }
    
    // 检查加密文件是否可访问
    if let Err(_e) = fs::OpenOptions::new().read(true).write(true).open(path) {
        eprintln!("Warning: Encrypted file {} cannot be opened (file open exception).", path.display());
        return Ok(2); // 返回特殊代码表示文件打开异常
    }

    // 获取文件名
    let file_name = match path.file_name().and_then(|n| n.to_str()) {
        Some(name) => name,
        None => {
            return Err(anyhow!("Cannot get file name for {}", path.display()));
        }
    };
    
    // 检查是否以 .kitty_enc 结尾
    if !file_name.ends_with(&format!(".{}", ENC_SUFFIX)) {
        return Err(anyhow!("Encrypted file does not end with .{}: {}", ENC_SUFFIX, path.display()));
    }
    
    // 删除 .kitty_enc 后缀得到源文件名
    let out_name = &file_name[..file_name.len() - format!(".{}", ENC_SUFFIX).len()];
    let parent = path.parent().unwrap_or(Path::new("."));
    let out_path = parent.join(out_name);

    // 检查解密后的文件是否已经存在，存在则跳过
    if out_path.exists() {
        eprintln!("Warning: Target file {} already exists, you need to fix it", out_path.display());
        return Ok(3); // 返回代码3表示目标文件已存在而跳过
    }

    //开始读取加密文件
    let mut data = Vec::new();
    if let Err(e) = File::open(path)
        .with_context(|| format!("Failed to open file for decryption: {}", path.display()))
        .and_then(|mut file| file.read_to_end(&mut data)
        .with_context(|| format!("Failed to read encrypted file: {}", path.display())))
    {
        // 安全擦除可能已读取的部分数据
        data.zeroize();
        return Err(e);
    };

    if data.len() < 24 + 4 + 32 {
        // 安全擦除敏感数据
        data.zeroize();
        return Err(anyhow!("Invalid encrypted file (too short): {}", path.display()));
    }

    // 分离 xnonce、加密类型标记、密文和存储的哈希
    let (xnonce_bytes, rest) = data.split_at(24);
    let (enc_type_marker, rest) = rest.split_at(4);
    let (ct, stored_hash_bytes) = rest.split_at(rest.len() - 32);
    
    // 检查加密类型标记：应该是4字节0表示普通加密
    if enc_type_marker != [0u8; 4] {
        // 安全擦除敏感数据
        data.zeroize();
        return Err(anyhow!("Invalid encryption type marker in file: {}", path.display()));
    }
    
    let xnonce = XNonce::from_slice(xnonce_bytes);
    
    // 使用主密钥和nonce作为盐派生子密钥
    let mut subkey = derive_subkey_simple(master_key.as_slice().try_into().unwrap(), xnonce_bytes)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&subkey));
    
    let mut pt = match cipher.decrypt(xnonce, ct) {
        Ok(pt) => pt,
        Err(_) => {
            // 安全擦除敏感数据
            data.zeroize();
            subkey.zeroize();
            return Err(anyhow!("Decryption failed for {} (bad key or corrupted file)", path.display()));
        }
    };

    // 先写入解密文件
    if let Err(e) = fs::write(&out_path, &pt)
        .with_context(|| format!("Failed to write decrypted file: {}", out_path.display()))
    {
        // 安全擦除敏感数据
        data.zeroize();
        subkey.zeroize();
        pt.zeroize();
        // 清理可能已经创建的文件
        fs::remove_file(&out_path).ok();
        return Err(e);
    };

    // 文件写入成功后，立即清理解密时使用的内存
    // data.zeroize(); 其实 data 是密文, 应该不需要太严格
    subkey.zeroize();
    pt.zeroize();

    // 验证解密文件是否写入成功
    if let Err(e) = verify_file_not_empty(&out_path) {
        fs::remove_file(&out_path).ok(); // 清理无效的解密文件
        return Err(e);
    };

    // 验证解密文件的内容
    let decrypted_data = match read_file_for_verification(&out_path) {
        Ok(data) => data,
        Err(e) => {
            fs::remove_file(&out_path).ok(); // 清理无效的解密文件
            return Err(e);
        }
    };
    
    let mut hasher_verify = Sha256::new();
    hasher_verify.update(&decrypted_data);
    let final_hash = hasher_verify.finalize();
    
    if final_hash.as_slice() != stored_hash_bytes {
        fs::remove_file(&out_path).ok(); // 清理无效的解密文件
        return Err(anyhow!("Final integrity check failed for decrypted file: {}", path.display()));
    }

    // 只有解密文件验证成功后才删除加密文件
    if let Err(e) = fs::remove_file(path) {
        // 如果删除加密文件失败，清理已创建的解密文件
        fs::remove_file(&out_path).ok();
        return Err(e).with_context(|| format!("Failed to remove encrypted file: {}", path.display()));
    }

    println!("Decrypted (encrypted file removed, integrity verified): {}", path.display());
    Ok(0)
}

/// 使用密码短语解密密钥（改进版）
pub fn decrypt_key_with_passphrase(encrypted_data: &[u8], passphrase: &str) -> Result<[u8; 32]> {
    if encrypted_data.len() < SALT_LENGTH + 24 {
        return Err(anyhow!("Invalid encrypted key data (too short)"));
    }
    
    // 分离 salt、xnonce 和加密的密钥
    let (salt_bytes, rest) = encrypted_data.split_at(SALT_LENGTH);
    let (xnonce_bytes, encrypted_key) = rest.split_at(24);
    
    // 使用 Argon2id 派生密钥解密密钥
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, None)
            .map_err(|e| anyhow!("Failed to create Argon2 params: {:?}", e))?,
    );
    
    // 派生密钥 - 使用 hash_password_into 直接写入可变数组
    let mut key_encryption_key_bytes = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt_bytes, &mut key_encryption_key_bytes)
        .map_err(|e| anyhow!("Failed to derive key: {:?}", e))?;
    
    // 使用 XChaCha20Poly1305 解密密钥
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key_encryption_key_bytes));
    let xnonce = XNonce::from_slice(xnonce_bytes);
    
    // 解密密钥
    let mut decrypted_key = match cipher.decrypt(xnonce, encrypted_key) {
        Ok(decrypted) => decrypted,
        Err(_) => {
            // 安全擦除派生密钥的内存
            key_encryption_key_bytes.zeroize();
            return Err(anyhow!("Failed to decrypt key with passphrase"));
        }
    };
    
    if decrypted_key.len() != 32 {
        // 安全擦除派生密钥的内存
        key_encryption_key_bytes.zeroize();
        decrypted_key.zeroize();
        return Err(anyhow!("Decrypted key has wrong length: {} bytes", decrypted_key.len()));
    }
    
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&decrypted_key);
    
    // 安全擦除派生密钥和解密后的密钥数据的内存
    key_encryption_key_bytes.zeroize();
    decrypted_key.zeroize();
    
    Ok(key_bytes)
}


pub fn process_decrypt_dir(dir: &Path, master_key: &Key, exe_path: &Path, key_path_opt: Option<&Path>) -> Result<i32> {
    // 收集所有需要处理的文件
    let mut files_to_process = Vec::new();

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
        let canon_path = fs::canonicalize(path)
            .with_context(|| format!("Failed to canonicalize path: {}", path.display()))?;

        if entry.file_type().unwrap().is_file() {
            // Skip self and key file
            if canon_is_self(&canon_path, &canon_exe_path)? || canon_is_key_file(&canon_path, canon_key_path_opt.as_deref())? {
                continue;
            }
            if is_encrypted_file(path) {
                files_to_process.push(path.to_path_buf());
            }
        }
    }
    
    println!("Found {} encrypted files to decrypt", files_to_process.len());
    
    if files_to_process.is_empty() {
        println!("No encrypted files to decrypt.");
        return Ok(0);
    }
        
    // 使用 rayon 并行处理文件
    let results: Vec<Result<i32>> = files_to_process
        .par_iter()
        .map(|path| {
            // 检查中断标志，如果已中断则跳过此文件
            if crate::cli::is_interrupted() {
                println!("Skipping {} due to interrupt signal", path.display());
                return Ok(1);
            }

            // 先检查目标文件是否存在
            if check_whether_src_file_exist(path)? {
                eprintln!("Warning: Target file {} already exists, you need to fix it", path.display());
                return Ok(3);
            } 
            
            // 根据文件格式选择解密方式
            let result = match is_streaming_encrypted_file(path) {
                Ok(is_streaming) => {
                    if is_streaming {
                        // 流式加密文件
                        decrypt_file_streaming(path, master_key)
                    } else {
                        // 普通加密文件
                        decrypt_file(path, master_key)
                    }
                }
                Err(e) => Err(e),
            };
            
            match &result {
                Ok(code) => {
                    match code {
                        // 0 => (), // 成功解密，不打印
                        // 1 => println!("Skipped {} due to interrupt", path.display()),
                        // 2 => println!("Skipped {} (file open exception)", path.display()),
                        // 3 => println!("Skipped {} (target exists)", path.display()),
                        _ => (),
                    }
                }
                Err(e) => {
                    eprintln!("Error decrypting {}: {}", path.display(), e);
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
    
    println!("Decryption summary:");
    println!("  Found {} encrypted files to decrypt", files_to_process.len());
    println!("  Successfully decrypted: {} files", success_count);
    println!("  Skipped (interrupted): {} files", skipped_interrupt_count);
    println!("  Skipped (file open exception): {} files", skipped_open_exception_count);
    println!("  Skipped (target exists): {} files", skipped_target_exists_count);
    println!("  Failed: {} files", error_count);
    
    // 如果存在目标文件已存在的警告，打印额外提示
    if skipped_target_exists_count > 0 {
        println!("Warning: {} Target file already exists, you need to fix it", skipped_target_exists_count);
    }
    
    // // 如果有错误，返回第一个错误
    // for result in results {
    //     if let Err(e) = result {
    //         return Err(e);
    //     }
    // }
    
    Ok(0)
}

/// 流式解密大文件（使用 XChaCha20Poly1305）
pub fn decrypt_file_streaming(path: &Path, master_key: &Key) -> Result<i32> {
    use std::io::{BufReader, BufWriter, Write, Read};
    
    // 检查加密文件是否可访问
    if let Err(_e) = fs::OpenOptions::new().read(true).write(true).open(path) {
        eprintln!("Warning: Encrypted file {} cannot be opened (file open exception).", path.display());
        return Ok(2); // 返回特殊代码表示文件打开异常
    }

    // 获取文件名
    let file_name = match path.file_name().and_then(|n| n.to_str()) {
        Some(name) => name,
        None => {
            return Err(anyhow!("Cannot get file name for {}", path.display()));
        }
    };
    
    // 检查是否以 .kitty_enc 结尾
    if !file_name.ends_with(&format!(".{}", ENC_SUFFIX)) {
        return Err(anyhow!("Encrypted file does not end with .{}: {}", ENC_SUFFIX, path.display()));
    }
    
    // 删除 .kitty_enc 后缀得到源文件名
    let out_name = &file_name[..file_name.len() - format!(".{}", ENC_SUFFIX).len()];
    let parent = path.parent().unwrap_or(Path::new("."));
    let out_path = parent.join(out_name);
    
    // 检查解密后的文件是否已经存在，存在则跳过
    if out_path.exists() {
        eprintln!("Warning: Target file {} already exists, you need to fix it", out_path.display());
        return Ok(3); // 返回代码3表示目标文件已存在而跳过
    }

    // 打开加密文件
    let encrypted_file = File::open(path)
        .with_context(|| format!("Failed to open file for streaming decryption: {}", path.display()))?;
    let mut reader = BufReader::new(encrypted_file);
    
    // 读取前24字节作为主 XNonce
    let mut xnonce_bytes = [0u8; 24];
    if let Err(e) = reader.read_exact(&mut xnonce_bytes)
        .with_context(|| format!("Failed to read xnonce from encrypted file: {}", path.display()))
    {
        // 安全擦除敏感数据
        xnonce_bytes.zeroize();
        return Err(e);
    };
    
    // 创建输出文件
    let out_file = File::create(&out_path)
        .with_context(|| format!("Failed to create decrypted file: {}", out_path.display()))?;
    let mut writer = BufWriter::new(out_file);
    
    // 使用主密钥和nonce作为盐派生子密钥
    let mut subkey = derive_subkey_simple(master_key.as_slice().try_into().unwrap(), &xnonce_bytes)?;
    
    // 使用 XChaCha20Poly1305 进行流式解密
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&subkey));
    
    let mut block_counter: u64 = 0;
    
    // 流式读取、解密、写入（不计算哈希）
    loop {
        // 检查中断标志
        if crate::cli::is_interrupted() {
            println!("Interrupt signal received, stopping decryption of {}", path.display());
            // 安全擦除敏感数据
            xnonce_bytes.zeroize();
            subkey.zeroize();
            // 清理已创建的解密文件
            fs::remove_file(&out_path).ok();
            return Ok(1); // 返回成功，表示已停止处理
        }
        
        // 读取块大小 (4字节)
        let mut block_size_bytes = [0u8; 4];
        if let Err(e) = reader.read_exact(&mut block_size_bytes)
            .with_context(|| format!("Failed to read block size from encrypted file: {}", path.display()))
        {
            // 安全擦除敏感数据
            block_size_bytes.zeroize();
            xnonce_bytes.zeroize();
            subkey.zeroize();
            // 清理可能已经创建的解密文件
            fs::remove_file(&out_path).ok();
            return Err(e);
        }
        
        let block_size = u32::from_le_bytes(block_size_bytes);
        
        // 安全擦除块大小字节
        block_size_bytes.zeroize();
        
        // 如果块大小为0，表示文件结束
        if block_size == 0 {
            break;
        } else if block_size > (STREAMING_CHUNK_SIZE + 16) as u32 {
            // 块大小理论最大值STREAMING_CHUNK_SIZE + 16
            fs::remove_file(&out_path).ok();
            return Err(anyhow!("密文大小不合理"));
        }
        
        let block_size = block_size as usize;
        
        // 读取加密块
        let mut encrypted_block = vec![0u8; block_size];
        if let Err(e) = reader.read_exact(&mut encrypted_block)
            .with_context(|| format!("Failed to read encrypted block {} from file: {}", block_counter, path.display()))
        {
            // 安全擦除敏感数据
            encrypted_block.zeroize();
            xnonce_bytes.zeroize();
            subkey.zeroize();
            // 清理可能已经创建的解密文件
            fs::remove_file(&out_path).ok();
            return Err(e);
        }
        
        // 为当前块生成 nonce：使用主 nonce + 块计数器拼接
        let mut block_nonce_bytes = [0u8; 24];
        
        // 复制主 nonce 的前 16 字节
        block_nonce_bytes[..16].copy_from_slice(&xnonce_bytes[..16]);
        
        // 后 8 字节使用块计数器的 LE 编码
        let counter_bytes = block_counter.to_le_bytes();
        block_nonce_bytes[16..].copy_from_slice(&counter_bytes);
        
        let block_nonce = XNonce::from_slice(&block_nonce_bytes);
        
        // 解密当前块
        let mut decrypted_block = cipher.decrypt(block_nonce, encrypted_block.as_slice())
            .map_err(|_| {
                // 安全擦除敏感数据
                encrypted_block.zeroize();
                block_nonce_bytes.zeroize();
                xnonce_bytes.zeroize();
                subkey.zeroize();
                // 清理无效的解密文件
                fs::remove_file(&out_path).ok();
                anyhow!("Decryption failed for block {} in file: {}", block_counter, path.display())
            })?;
        
        // 写入解密块
        if let Err(e) = writer.write_all(&decrypted_block)
            .with_context(|| format!("Failed to write decrypted block to file: {}", out_path.display()))
        {
            // 安全擦除敏感数据
            encrypted_block.zeroize();
            block_nonce_bytes.zeroize();
            decrypted_block.zeroize();
            xnonce_bytes.zeroize();
            subkey.zeroize();
            // 清理无效的解密文件
            fs::remove_file(&out_path).ok();
            return Err(e);
        }
        
        // 安全擦除敏感数据 (注意subkey, xnonce_bytes下一轮要用, 不能清)
        encrypted_block.zeroize();
        block_nonce_bytes.zeroize();
        decrypted_block.zeroize();

        block_counter += 1;
    }
    
    // 读取存储的哈希 (32字节)
    let mut stored_hash = [0u8; 32];
    if let Err(e) = reader.read_exact(&mut stored_hash)
        .with_context(|| format!("Failed to read hash from encrypted file: {}", path.display()))
    {
        // 安全擦除敏感数据
        stored_hash.zeroize();
        xnonce_bytes.zeroize();
        subkey.zeroize();
        // 清理可能已经创建的解密文件
        fs::remove_file(&out_path).ok();
        return Err(e);
    };
    
    // 确保所有数据都写入磁盘
    if let Err(e) = writer.flush()
        .with_context(|| format!("Failed to flush decrypted file: {}", out_path.display()))
    {
        // 安全擦除敏感数据
        stored_hash.zeroize();
        xnonce_bytes.zeroize();
        subkey.zeroize();
        // 清理无效的解密文件
        fs::remove_file(&out_path).ok();
        return Err(e);
    };
    
    // 安全擦除敏感数据
    xnonce_bytes.zeroize();
    subkey.zeroize();
    
    // 验证解密文件
    if let Err(e) = verify_file_not_empty(&out_path) {
        // 安全擦除敏感数据
        stored_hash.zeroize();
        xnonce_bytes.zeroize();
        fs::remove_file(&out_path).ok();
        return Err(e);
    }
    
    // 从文件分块读取计算哈希
    let mut hasher = Sha256::new();
    let mut file_for_hash = match File::open(&out_path)
        .with_context(|| format!("Failed to open decrypted file for hash verification: {}", out_path.display()))
    {
        Ok(file) => file,
        Err(e) => {
            // 安全擦除敏感数据
            stored_hash.zeroize();
            xnonce_bytes.zeroize();
            // 清理可能已经创建的解密文件
            fs::remove_file(&out_path).ok();
            return Err(e);
        }
    };
    
    let mut buffer = vec![0u8; 65536]; // 64KB 缓冲区
    loop {
        // 检查中断标志
        if crate::cli::is_interrupted() {
            println!("Interrupt signal received, stopping hash verification of {}", out_path.display());
            // 安全擦除敏感数据
            buffer.zeroize();
            stored_hash.zeroize();
            xnonce_bytes.zeroize();
            // 清理已创建的解密文件
            fs::remove_file(&out_path).ok();
            return Ok(1); // 返回成功，表示已停止处理
        }
        
        let bytes_read = match file_for_hash.read(&mut buffer)
            .with_context(|| format!("Failed to read decrypted file for hash verification: {}", out_path.display()))
        {
            Ok(bytes) => bytes,
            Err(e) => {
                // 安全擦除敏感数据
                buffer.zeroize();
                stored_hash.zeroize();
                xnonce_bytes.zeroize();
                // 清理可能已经创建的解密文件
                fs::remove_file(&out_path).ok();
                return Err(e);
            }
        };
        
        if bytes_read == 0 {
            break;
        }
        
        hasher.update(&buffer[..bytes_read]);
    }
    
    // 安全擦除缓冲区
    buffer.zeroize();
    
    // 计算解密数据的哈希
    let computed_hash = hasher.finalize();
    
    // 验证哈希
    if computed_hash.as_slice() != stored_hash {
        // 安全擦除敏感数据
        stored_hash.zeroize();
        xnonce_bytes.zeroize();
        fs::remove_file(&out_path).ok(); // 清理无效的解密文件
        return Err(anyhow!("Integrity check failed for decrypted file: {}", path.display()));
    }
    
    // 安全擦除存储的哈希
    stored_hash.zeroize();
    
    // 只有解密文件验证成功后才删除加密文件
    if let Err(e) = fs::remove_file(path) {
        // 如果删除加密文件失败，清理已创建的解密文件
        fs::remove_file(&out_path).ok();
        return Err(e).with_context(|| format!("Failed to remove encrypted file: {}", path.display()));
    }
    
    println!("Decrypted (streaming, encrypted file removed, integrity verified): {}", path.display());
    Ok(0)
}

fn check_whether_src_file_exist(enc_path: &Path) -> Result<bool>{
    // 获取文件名
    let file_name = match enc_path.file_name().and_then(|n| n.to_str()) {
        Some(name) => name,
        None => {
            return Err(anyhow!("Cannot get file name for {}", enc_path.display()));
        }
    };
    
    // 检查是否以 .kitty_enc 结尾
    if !file_name.ends_with(&format!(".{}", ENC_SUFFIX)) {
        return Err(anyhow!("Encrypted file does not end with .{}: {}", ENC_SUFFIX, enc_path.display()));
    }
    
    // 删除 .kitty_enc 后缀得到源文件名
    let out_name = &file_name[..file_name.len() - format!(".{}", ENC_SUFFIX).len()];
    let parent = enc_path.parent().unwrap_or(Path::new("."));
    let out_path = parent.join(out_name);

    // 检查解密后的文件是否已经存在，存在则跳过
    if out_path.exists() {
        return Ok(true); // 返回代码3表示目标文件已存在而跳过
    }
    return Ok(false);
}