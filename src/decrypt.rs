use anyhow::{Context, Result, anyhow};
// use walkdir::WalkDir;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use crate::MySha256 as Sha256;
use zeroize::Zeroizing;
use rayon::prelude::*;  // 添加 rayon 并行处理
use ignore::WalkBuilder;
use ignore::DirEntry as ignore_DirEntry;

use crate::*;

pub fn process_decrypt_dir(dir: &Path, master_key: &[u8;32], exe_path: &Path, key_path_opt: Option<&Path>) -> Result<i32> {
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

    my_println!("Starting file collection...");
    
    for entry in WalkBuilder::new(dir)
        .add_custom_ignore_filename(".kitignore")
        .git_ignore(false)
        .follow_links(false)
        .filter_entry(|e: &ignore_DirEntry| ignore_filter_entry(e))
        .build()
    {
        // 检查中断标志
        if crate::cli::is_interrupted() {
            my_println!("Interrupt signal received, stopping file collection");
            return Ok(1);
        }
        
        let entry = entry?;
        let path = entry.path();

        if entry.file_type().unwrap().is_file() {
            // 先判断是文件再规范化
            let canon_path = fs::canonicalize(path)
                .with_context(|| format!("Failed to canonicalize path: {}", path.display()))?;
            // Skip self and key file
            if canon_is_self(&canon_path, &canon_exe_path)? || canon_is_key_file(&canon_path, canon_key_path_opt.as_deref())? {
                continue;
            }
            if is_encrypted_file(path) {
                files_to_process.push(path.to_path_buf());
            }
        }
    }
    
    my_println!("Found {} encrypted files to decrypt", files_to_process.len());
    
    if files_to_process.is_empty() {
        my_println!("No encrypted files to decrypt.");
        return Ok(0);
    }
        
    // 使用 rayon 并行处理文件
    let results: Vec<Result<i32>> = files_to_process
        .par_iter()
        .map(|path| {
            // 检查中断标志，如果已中断则跳过此文件
            if crate::cli::is_interrupted() {
                my_println!("Skipping {} due to interrupt signal", path.display());
                return Ok(1);
            }

            // 先检查目标文件是否存在
            match check_whether_src_file_exist(path) {
                Ok((true,out_path)) => {
                    my_eprintln!("Warning: Target file {} already exists, you need to fix it", out_path.display());
                    return Ok(3);
                } 
                Ok((false,_)) => {}
                Err(e) => {
                    my_eprintln!("Error: {}", e);
                    return Err(e);
                }
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
                        // 1 => my_println!("Skipped {} due to interrupt", path.display()),
                        // 2 => my_println!("Skipped {} (file open exception)", path.display()),
                        // 3 => my_println!("Skipped {} (target exists)", path.display()),
                        _ => (),
                    }
                }
                Err(e) => {
                    my_eprintln!("Error decrypting {}: {}", path.display(), e);
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
    
    my_println!("Decryption summary:");
    my_println!("  Found {} encrypted files to decrypt", files_to_process.len());
    my_println!("  Successfully decrypted: {} files", success_count);
    my_println!("  Skipped (interrupted): {} files", skipped_interrupt_count);
    my_println!("  Skipped (file open exception): {} files", skipped_open_exception_count);
    my_println!("  Skipped (target exists): {} files", skipped_target_exists_count);
    my_println!("  Failed: {} files", error_count);
    
    // 如果存在目标文件已存在的警告，打印额外提示
    if skipped_target_exists_count > 0 {
        my_println!("Warning: {} Target file already exists, you need to fix it", skipped_target_exists_count);
    }
    
    // // 如果有错误，返回第一个错误
    // for result in results {
    //     if let Err(e) = result {
    //         return Err(e);
    //     }
    // }
    
    Ok(0)
}

fn decrypt_file(path: &Path, master_key: &[u8;32]) -> Result<i32> {
    // 检查中断标志
    if crate::cli::is_interrupted() {
        my_println!("Interrupt signal received, skipping decryption of {}", path.display());
        return Ok(1);
    }
    
    // 检查加密文件是否可访问
    if let Err(_e) = fs::OpenOptions::new().read(true).write(true).open(path) {
        my_eprintln!("Warning: Encrypted file {} cannot be opened (file open exception).", path.display());
        return Ok(2); // 返回特殊代码表示文件打开异常
    }
    
    // 检查是否以 .kitty_enc 结尾
    if let Some(orig_ext) = path.extension() {
        if orig_ext == ENC_SUFFIX{
            // pass
        } else {
            return Err(anyhow!("Encrypted file does not end with .{}: {}", ENC_SUFFIX, path.display()));
        }
    } else {
            return Err(anyhow!("Cannot get file extension: {}", path.display()));
    };

    let mut out_path = PathBuf::from(path);
    out_path.set_extension("");
    
    // 检查解密后的文件是否已经存在，存在则跳过
    if out_path.try_exists()? {
        my_eprintln!("Warning: Target file {} already exists, you need to fix it", out_path.display());
        return Ok(3); // 返回代码3表示目标文件已存在而跳过
    }

    //开始读取加密文件
    let mut data: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
    let mut file = File::open(path)
        .with_context(|| format!("Failed to open file for decryption: {}", path.display()))?;
    file.try_lock_shared()
        .with_context(|| format!("Failed to lock file for decryption: {}", path.display()))?;
    file.read_to_end(&mut data)
        .with_context(|| format!("Failed to read encrypted file: {}", path.display()))?;
    file.unlock()
        .with_context(|| format!("Failed to unlock encrypted file: {}", path.display()))?;

    // 检查文件长度：至少需要48字节all_xnonce + 4字节标记 + 48字节加密哈希
    if data.len() < 48 + 4 + 48 {
        return Err(anyhow!("Invalid encrypted file (too short): {}", path.display()));
    }

    // 分离 all_xnonce、加密类型标记、密文和存储的加密哈希
    let (all_xnonce_bytes, rest) = data.split_at(48);
    let (enc_type_marker, rest) = rest.split_at(4);
    let (ct, stored_encrypted_hash_bytes) = rest.split_at(rest.len() - 48);
    
    // 检查加密类型标记：应该是4字节0表示普通加密
    if enc_type_marker != [0u8; 4] {
        return Err(anyhow!("Invalid encryption type marker in file: {}", path.display()));
    }
    
    // 拆分all_xnonce为文件nonce和哈希nonce
    let (file_xnonce_bytes, hash_xnonce_bytes) = all_xnonce_bytes.split_at(24);
    let file_xnonce = MyXnonce::try_from_slice(file_xnonce_bytes)?;
    
    // 使用主密钥和all_xnonce作为盐派生子密钥（与加密保持一致）
    let subkey: Zeroizing<[u8; 32]> = derive_subkey_simple(master_key, all_xnonce_bytes)?;
    let cipher = MyCipher::new(subkey.as_ref())?;
    
    let pt: Zeroizing<Vec<u8>> = match cipher.decrypt(&file_xnonce, ct) {
        Ok(pt) => pt,
        Err(_) => {
            return Err(anyhow!("Decryption failed for {} (bad key or corrupted file)", path.display()));
        }
    };

    // 解密存储的哈希
    let decrypted_stored_hash: Zeroizing<[u8; 32]> = decrypt_file_hash(stored_encrypted_hash_bytes, &subkey, hash_xnonce_bytes)?;

    // 先写入解密文件
    let mut out_file = File::create_new(&out_path)
        .with_context(|| format!("Failed to create decrypted file: {}", out_path.display()))?;

    // 写入数据，逐段写入，避免中间 Vec
    if let Err(e) = (|| -> Result<()> {
        out_file.try_lock()
            .with_context(|| format!("Failed to lock decrypted file: {}", out_path.display()))?;
        out_file.write_all(&pt)
            .with_context(|| format!("Failed to write decrypted file: {}", out_path.display()))?;
        out_file.flush()
            .with_context(|| "Failed to flush buffer")?;
        out_file.unlock()
            .with_context(|| format!("Failed to unlock decrypted file: {}", out_path.display()))?;
        Ok(())
    })() {
        // 写入失败时清理文件
        std::fs::remove_file(out_path).ok();
        return Err(e);
    }

    match decrypt_file_verify(&out_path, decrypted_stored_hash){
        Ok(0) => {}
        other => {
            fs::remove_file(&out_path).ok();
            return other;
        }

    }
    // 只有解密文件验证成功后才删除加密文件
    if let Err(e) = fs::remove_file(path) {
        // 如果删除加密文件失败，清理已创建的解密文件
        fs::remove_file(&out_path).ok();
        return Err(e).with_context(|| format!("Failed to remove encrypted file: {}", path.display()));
    }

    my_println!("Decrypted (encrypted file removed, integrity verified): {}", path.display());
    Ok(0)
}

fn decrypt_file_verify(out_path: &Path, decrypted_stored_hash_bytes: Zeroizing<[u8; 32]>) -> Result<i32>{
    // 验证解密文件是否写入成功
    if let Err(e) = verify_file_not_empty(&out_path) {
        return Err(e);
    };

    // 验证解密文件的内容
    let decrypted_data: Zeroizing<Vec<u8>> = match read_file_for_verification(&out_path) {
        Ok(data) => data,
        Err(e) => {
            return Err(e);
        }
    };
    
    let mut hasher_verify = Sha256::new(None,32)?;
    hasher_verify.update(&decrypted_data);
    let mut final_hash:Zeroizing<[u8;32]> = Zeroizing::new([0u8;32]);
    hasher_verify.finalize_into(final_hash.as_mut())?;
    
    if final_hash != decrypted_stored_hash_bytes {
        return Err(anyhow!("Final integrity check failed for decrypted file: {}", out_path.display()));
    }
    Ok(0)
}

/// 流式解密大文件（使用 XChaCha20Poly1305）
fn decrypt_file_streaming(path: &Path, master_key: &[u8;32]) -> Result<i32> {  
    // 检查中断标志
    if crate::cli::is_interrupted() {
        my_println!("Interrupt signal received, skipping decryption of {}", path.display());
        return Ok(1);
    }
    
    // 检查加密文件是否可访问
    if let Err(_e) = fs::OpenOptions::new().read(true).write(true).open(path) {
        my_eprintln!("Warning: Encrypted file {} cannot be opened (file open exception).", path.display());
        return Ok(2); // 返回特殊代码表示文件打开异常
    }

    // 检查是否以 .kitty_enc 结尾
    if let Some(orig_ext) = path.extension() {
        if orig_ext == ENC_SUFFIX{
            // pass
        } else {
            return Err(anyhow!("Encrypted file does not end with .{}: {}", ENC_SUFFIX, path.display()));
        }
    } else {
            return Err(anyhow!("Cannot get file extension: {}", path.display()));
    };

    let mut out_path = PathBuf::from(path);
    out_path.set_extension("");

    // 检查解密后的文件是否已经存在，存在则跳过
    if out_path.try_exists()? {
        my_eprintln!("Warning: Target file {} already exists, you need to fix it", out_path.display());
        return Ok(3); // 返回代码3表示目标文件已存在而跳过
    }

    // 打开加密文件
    let mut encrypted_file = File::open(path)
        .with_context(|| format!("Failed to open file for streaming decryption: {}", path.display()))?;
    encrypted_file.try_lock_shared()
        .with_context(|| format!("Failed to lock file for streaming decryption: {}", path.display()))?;

    // 读取前48字节作为 all_xnonce（24字节文件nonce + 24字节哈希nonce）
    let mut all_xnonce_bytes = [0u8; 48];
    if let Err(e) = encrypted_file.read_exact(&mut all_xnonce_bytes) {
        return Err(e).with_context(|| format!("Failed to read all_xnonce from encrypted file: {}", path.display()));
    };
    
    // 拆分all_xnonce为文件nonce和哈希nonce
    let (file_xnonce_bytes, hash_xnonce_bytes) = all_xnonce_bytes.split_at(24);
    
    // 使用主密钥和all_xnonce作为盐派生子密钥（与加密保持一致）
    let subkey: Zeroizing<[u8; 32]> = derive_subkey_simple(master_key, &all_xnonce_bytes)?;
    
    // 使用 XChaCha20Poly1305 进行流式解密
    let cipher = MyCipher::new(subkey.as_ref())?;
    
    let mut block_counter: u64 = 0;

    // 创建输出文件
    let mut out_file = File::create_new(&out_path)
        .with_context(|| format!("Failed to create decrypted file: {}", out_path.display()))?;
    if let Err(e) = out_file.try_lock(){
        fs::remove_file(&out_path).ok();
        return Err(e).with_context(|| format!("Failed to lock decrypted file: {}", out_path.display()))
    }

    // 流式读取、解密、写入并计算哈希
    let loop_result= (||-> Result<i32> {
        loop {
            // 检查中断标志
            if crate::cli::is_interrupted() {
                my_println!("Interrupt signal received, stopping decryption of {}", path.display());
                return Ok(1); // 返回成功，表示已停止处理
            }
            
            // 读取块大小 (4字节)
            let mut block_size_bytes = [0u8; 4];
            if let Err(e) = encrypted_file.read_exact(&mut block_size_bytes) {
                return Err(e).with_context(|| format!("Failed to read block size from encrypted file: {}", path.display()));
            }
            
            let block_size = u32::from_le_bytes(block_size_bytes);
            
            // 如果块大小为0，表示文件结束
            if block_size == 0 {
                break;
            } else if block_size > (STREAMING_CHUNK_SIZE + 16) as u32 {
                return Err(anyhow!("密文大小不合理"));
            }
            
            let block_size = block_size as usize;
            
            // 读取加密块
            let mut encrypted_block: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0u8; block_size]);
            if let Err(e) = encrypted_file.read_exact(&mut encrypted_block) {
                return Err(e).with_context(|| format!("Failed to read encrypted block {} from file: {}", block_counter, path.display()));
            }
            
            // 为每个块生成唯一的 nonce
            let block_nonce_bytes: [u8; 24] = get_block_nonce_bytes(file_xnonce_bytes, block_counter)?;
            let block_nonce = MyXnonce::try_from_slice(&block_nonce_bytes)?;
            
            // 解密当前块
            let decrypted_block: Zeroizing<Vec<u8>> = cipher.decrypt(&block_nonce, encrypted_block.as_ref())
                .map_err(|_| {
                    anyhow!("Decryption failed for block {} in file: {}", block_counter, path.display())
                })?;
            
            // 写入解密块
            if let Err(e) = out_file.write_all(&decrypted_block) {
                return Err(e).with_context(|| format!("Failed to write decrypted block to file: {}", out_path.display()));
            }
            
            block_counter += 1;
        }
        Ok(0)
    })();
    match loop_result {
        Ok(0) => {}
        other => {
            fs::remove_file(&out_path).ok();
            return other;
        }   
    };
    
    // 确保所有数据都写入磁盘
    if let Err(e) = out_file.flush() {
        // 清理无效的解密文件
        fs::remove_file(&out_path).ok();
        return Err(e).with_context(|| format!("Failed to flush decrypted file: {}", out_path.display()));
    };
    if let Err(e) = out_file.unlock(){
        fs::remove_file(&out_path).ok();
        return Err(e).with_context(|| format!("Failed to unlock decrypted file: {}", out_path.display()));
    }

    // 读取存储的加密哈希 (48字节)
    let mut stored_encrypted_hash: Zeroizing<[u8; 48]> = Zeroizing::new([0u8; 48]);
    if let Err(e) = encrypted_file.read_exact(stored_encrypted_hash.as_mut()) {
        // 清理可能已经创建的解密文件
        fs::remove_file(&out_path).ok();
        return Err(e).with_context(|| format!("Failed to read hash from encrypted file: {}", path.display()));
    };
    if let Err(e) = encrypted_file.unlock(){
        fs::remove_file(&out_path).ok();
        return Err(e).with_context(|| format!("Failed to unlock encrypted file: {}", path.display()));
    }
    
    // 解密存储的哈希
    let decrypted_stored_hash: Zeroizing<[u8; 32]> = decrypt_file_hash(stored_encrypted_hash.as_ref(), &subkey, hash_xnonce_bytes)
        .map_err(|e|{fs::remove_file(&out_path).ok();e})?;
    
    // 调用验证函数进行验证
    match decrypt_file_streaming_verify(&out_path, decrypted_stored_hash) {
        Ok(0) => {}
        other => {
            fs::remove_file(&out_path).ok();
            return other;
        }
    };
    
    // 只有解密文件验证成功后才删除加密文件
    if let Err(e) = fs::remove_file(path) {
        // 如果删除加密文件失败，清理已创建的解密文件
        fs::remove_file(&out_path).ok();
        return Err(e).with_context(|| format!("Failed to remove encrypted file: {}", path.display()));
    }
    
    my_println!("Decrypted (streaming, encrypted file removed, integrity verified): {}", path.display());
    Ok(0)
}

/// 流式解密验证函数
fn decrypt_file_streaming_verify(out_path: &Path, decrypted_stored_hash_bytes: Zeroizing<[u8; 32]>) -> Result<i32> {
    // 验证加密文件
    if let Err(e) = verify_file_not_empty(&out_path) {
        return Err(e);
    }
    
    // 流式验证加密文件
    let mut verify_file = match File::open(&out_path) {
        Ok(file) => file,
        Err(e) => {
            return Err(e).with_context(|| format!("Failed to open decrypted file for verification: {}", out_path.display()));
        }
    };
    verify_file.try_lock_shared()
        .with_context(|| format!("Failed to lock decrypted file for verification: {}", out_path.display()))?;

    let mut verify_hasher = Sha256::new(None,32)?;
    
    let mut buffer: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0u8; 65536]); // 64KB 缓冲区
    loop {
        // 检查中断标志
        if crate::cli::is_interrupted() {
            my_println!("Interrupt signal received, stopping hash verification of {}", out_path.display());
            return Ok(1); // 返回成功，表示已停止处理
        }
        
        let bytes_read = match verify_file.read(&mut buffer)
            .with_context(|| format!("Failed to read decrypted file for hash verification: {}", out_path.display()))
        {
            Ok(bytes) => bytes,
            Err(e) => {return Err(e);}
        };
        
        if bytes_read == 0 {
            break;
        }
        
        verify_hasher.update(&buffer[..bytes_read]);
    }
    verify_file.unlock()
        .with_context(|| format!("Failed to unlock decrypted file during verification: {}", out_path.display()))?;
    
    
    // 计算解密数据的哈希
    let mut computed_hash:Zeroizing<[u8;32]> = Zeroizing::new([0u8;32]);
    verify_hasher.finalize_into(computed_hash.as_mut())?;
    
    // 验证哈希
    if computed_hash != decrypted_stored_hash_bytes {
        return Err(anyhow!("Integrity check failed for decrypted file: {}", out_path.display()));
    }
    
    Ok(0)
}

fn check_whether_src_file_exist(enc_path: &Path) -> Result<(bool,PathBuf)> {
    // 检查是否以 .kitty_enc 结尾
    if let Some(orig_ext) = enc_path.extension() {
        if orig_ext == ENC_SUFFIX{
            // pass
        } else {
            return Err(anyhow!("Encrypted file does not end with .{}: {}", ENC_SUFFIX, enc_path.display()));
        }
    } else {
            return Err(anyhow!("Cannot get file extension: {}", enc_path.display()));
    };

    let mut out_path = PathBuf::from(enc_path);
    out_path.set_extension("");

    // 检查解密后的文件是否已经存在，存在则跳过
    if out_path.try_exists()? {
        return Ok((true,out_path)); // 返回代码3表示目标文件已存在而跳过
    }
    return Ok((false,out_path));
}