use anyhow::{Context, Result, anyhow};
use std::{fs::{self, File}, io::{Read, Seek, SeekFrom}};
use std::path::{Path, PathBuf};
use crate::MySha256 as Sha256;
use ignore::WalkBuilder;
use ignore::DirEntry as ignore_DirEntry;
use zeroize::Zeroizing;
use rayon::prelude::*;  // 添加 rayon 并行处理

use crate::*;

/// 处理修复目录
pub fn process_fix_dir(dir: &Path, master_key: &[u8;32], exe_path: &Path, key_path_opt: Option<&Path>) -> Result<i32> {
    my_println!("Starting file collection...");
    // 收集加密文件并查找重复的文件对
    let (duplicate_pairs, interrupted) = collect_files_for_fix(dir, exe_path, key_path_opt)?;
    
    // 如果被中断，直接退出
    if interrupted {
        my_println!("Fix operation interrupted by user");
        return Ok(1);
    }

    my_println!("Found {} duplicate file pairs to fix", duplicate_pairs.len());  
    
    if duplicate_pairs.is_empty() {
        my_println!("No duplicate files found, nothing to fix.");
        return Ok(0);
    }
    

    // 使用 rayon 并行处理文件对
    let results: Vec<Result<FixResult>> = duplicate_pairs
        .par_iter()
        .map(|(src_path, enc_path)| {
            // 检查中断标志，如果已中断则跳过此文件对
            if crate::cli::is_interrupted() {
                my_println!("Skipping duplicate pair due to interrupt signal");
                return Ok(FixResult::Interrupt);
            }

            let result = verify_and_fix_pair(src_path, enc_path, master_key);
            
            match &result {
                Ok(fix_result) => {
                    match fix_result {
                        FixResult::DeletedEncrypted => {
                            my_println!("Fixing duplicate pair: \n  Source: {}, \n  Encrypted: {} \n  -> Deleted encrypted file (encrypted file is incomplete)", src_path.display(), enc_path.display());
                        }
                        FixResult::DeletedSource => {
                            my_println!("Fixing duplicate pair: \n  Source: {}, \n  Encrypted: {} \n  -> Deleted source file (source file is incomplete)", src_path.display(), enc_path.display());
                        }
                        FixResult::Interrupt => {
                            my_println!("Fixing duplicate pair: \n  Source: {}, \n  Encrypted: {} \n  -> Interrupted, stopping fix operation", src_path.display(), enc_path.display());
                        }
                        FixResult::ManualRequired{reason} => {
                            my_println!("Fixing duplicate pair: \n  Source: {}, \n  Encrypted: {} \n  -> {reason} Manual intervention required, skipping", src_path.display(), enc_path.display());
                        }
                    }
                }
                Err(e) => {
                    my_eprintln!("Fixing duplicate pair: \n  Source: {}, \n  Encrypted: {} \n  -> Error fixing pair: {}", src_path.display(), enc_path.display(), e);
                }
            }
            
            result
        })
        .collect();
    
    // 统计结果
    let mut auto_processed_count = 0;
    let mut deleted_encrypted_count = 0;
    let mut deleted_source_count = 0;
    let mut error_count = 0;
    let mut manual_required_count = 0;
    let mut skipped_interrupt_count = 0;
    let mut manual_pairs = Vec::new();
    
    for (i, result) in results.iter().enumerate() {
        match result {
            Ok(fix_result) => {
                match fix_result {
                    FixResult::DeletedEncrypted => {
                        deleted_encrypted_count += 1;
                        auto_processed_count += 1;
                    }
                    FixResult::DeletedSource => {
                        deleted_source_count += 1;
                        auto_processed_count += 1;
                    }
                    FixResult::Interrupt => {
                        skipped_interrupt_count += 1;
                    }
                    FixResult::ManualRequired{reason: _} => {
                        manual_required_count += 1;
                        if i < duplicate_pairs.len() {
                            manual_pairs.push((duplicate_pairs[i].0.clone(), duplicate_pairs[i].1.clone()));
                        }
                    }
                }
            }
            Err(_) => {
                error_count += 1;
            }
        }
    }
    
    my_println!("Fix summary:");
    my_println!("  Found {} duplicate file pairs", duplicate_pairs.len());
    my_println!("  Successfully processed {} pairs", auto_processed_count);
    my_println!("  {} pairs failed", error_count);
    my_println!("  {} pairs require manual intervention", manual_required_count);
    my_println!("  {} pairs skipped (interrupted)", skipped_interrupt_count);
    my_println!("  {} pairs not processed", duplicate_pairs.len()-auto_processed_count-error_count-manual_required_count-skipped_interrupt_count);
    my_println!("  Deleted {} encrypted files automatically", deleted_encrypted_count);
    my_println!("  Deleted {} source files automatically", deleted_source_count);

    // 打印需要手动处理的文件对
    if !manual_pairs.is_empty() {
        my_println!("\nFiles requiring manual intervention:");
        for (i, (src_path, enc_path)) in manual_pairs.iter().enumerate() {
            my_println!("  {}.\tSource: {}\n\tEncrypted: {}\n", 
                i + 1, 
                src_path.display(), 
                enc_path.display());
        }
    }

    Ok(0)
}

/// 收集加密文件并查找重复的文件对
/// 返回元组：(重复文件对列表, 是否被中断)
fn collect_files_for_fix(dir: &Path, exe_path: &Path, key_path_opt: Option<&Path>) -> Result<(Vec<(PathBuf, PathBuf)>, bool)> {
    let mut pairs = Vec::new();
    let mut interrupted = false;

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
            my_println!("Interrupt signal received, stopping file collection");
            interrupted = true;
            break;
        }
        
        let entry = entry?;
        let path = entry.path();

        if entry.file_type().unwrap().is_file() {
            // 先判断是文件再规范化
            let canon_path = fs::canonicalize(path)
                .with_context(|| format!("Failed to canonicalize path: {}", path.display()))?;
            // 跳过自身和密钥文件
            if canon_is_self(&canon_path, &canon_exe_path)? || canon_is_key_file(&canon_path, canon_key_path_opt.as_deref())? {
                continue;
            }
            
            // let size = entry.metadata()?.len(); // 2025.12.6 因为只处理加密文件，不跳过空文件
            
            // 跳过空文件
            // if size == 0 {
            //     continue;
            // }
            
            // 只处理加密文件
            if is_encrypted_file(path) {
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

                let mut src_path = PathBuf::from(path);
                src_path.set_extension("");
                
                // 检查源文件是否已经存在
                if src_path.exists() {
                    pairs.push((src_path, path.to_path_buf()));
                }
            }
        }
    }
    
    Ok((pairs, interrupted))
}

/// 修复结果枚举
#[derive(Debug)]
/// 文件修复结果
enum FixResult {
    /// 删除了加密文件
    DeletedEncrypted,
    /// 删除了源文件
    DeletedSource,
    /// 收到中断信号
    Interrupt,
    /// 需要手动处理
    ManualRequired{reason:String},
}

/// 验证并修复文件对
fn verify_and_fix_pair(src_path: &Path, enc_path: &Path, master_key: &[u8;32]) -> Result<FixResult> {
    // 首先验证加密文件完整性
    let verify_encrypted_file_code: i32 = verify_encrypted_file(src_path,enc_path , master_key)?;
    if verify_encrypted_file_code == 1 {
        return Ok(FixResult::Interrupt);
    }
    if verify_encrypted_file_code == 2 {
        return Ok(FixResult::ManualRequired{reason:"加密文件无法打开".to_string()});
    }
    if verify_encrypted_file_code == 99 {
        // 加密文件不完整，删除加密文件
        fs::remove_file(enc_path)
        .with_context(|| format!("Failed to delete incomplete encrypted file {}", enc_path.display()))?;
        return Ok(FixResult::DeletedEncrypted);
    }
    if verify_encrypted_file_code == 98{
        // 加密文件不确定, 简单验证源文件
        let verify_decrypted_file_simple_code = verify_decrypted_file_simple(src_path)?;
        if verify_decrypted_file_simple_code == 1 {
            return Ok(FixResult::Interrupt);
        }
        if verify_decrypted_file_simple_code == 2 {
            return Ok(FixResult::ManualRequired{reason:"源文件无法打开".to_string()});
        }
        if verify_decrypted_file_simple_code == 99{
            // 源文件不完整，删除源文件
            fs::remove_file(src_path)
            .with_context(|| format!("Failed to delete incomplete source file {}", src_path.display()))?;
            return Ok(FixResult::DeletedSource);
        }
        // 其他交给用户
        return Ok(FixResult::ManualRequired{reason:"加密文件无法确定完整性".to_string()});
    }
    if verify_encrypted_file_code == 0{
        // 加密文件完整，检查源文件完整性
        let verify_decrypted_file_code = verify_decrypted_file(src_path, enc_path, master_key)?;
        if verify_decrypted_file_code == 1 {
            return Ok(FixResult::Interrupt);
        }
        if verify_decrypted_file_code == 2 {
            return Ok(FixResult::ManualRequired{reason:"源文件或加密文件无法打开".to_string()});
        }
        if verify_decrypted_file_code == 99||verify_decrypted_file_code == 98 {
            // 源文件不完整，删除源文件
            fs::remove_file(src_path)
            .with_context(|| format!("Failed to delete incomplete source file {}", src_path.display()))?;
            return Ok(FixResult::DeletedSource);
        }
        if verify_decrypted_file_code == 0{
            // 两个都完整，交给用户
            return Ok(FixResult::ManualRequired{reason:"两个文件均完整".to_string()});
        }
    }
    Err(anyhow!("不应该运行到这里！！！！！"))
}

/// 验证加密文件完整性
fn verify_encrypted_file(src_path: &Path, enc_path: &Path, master_key: &[u8;32]) -> Result<i32> {    
    // 检查文件是否过小
    let metadata = fs::metadata(enc_path)?;
    if metadata.len() < 48 + 4 + 48 {
        return Ok(99);
    }
    let src_metadata =fs::metadata(src_path)?;
    if metadata.len() <= src_metadata.len() {
        return Ok(99);
    }

    // 根据文件格式选择验证方式
    let result: Result<i32> = if is_streaming_encrypted_file(enc_path)? {
        // 流式验证文件
        verify_streaming_encrypted_file(enc_path, master_key)
    } else {
        // 普通验证文件
        verify_regular_encrypted_file(enc_path, master_key)
    };
    match result {
        Ok(code) => {
            match code {
                0 => Ok(0), 
                1 => Ok(1),
                2 => Ok(2),
                98 => Ok(98),
                99 => Ok(99),
                _ => Err(anyhow!("Error verifying {}: unknown code", enc_path.display())),
            }
        }
        Err(e) => {
            // my_eprintln!("Error verifying {}: {}", enc_path.display(), e);
            Err(e)
        }
    }
}

/// 验证普通加密文件（只解密验证，不写入文件）
fn verify_regular_encrypted_file(path: &Path, master_key: &[u8;32]) -> Result<i32> {
    // 检查中断标志
    if crate::cli::is_interrupted() {
        my_println!("Interrupt signal received, skipping verification of {}", path.display());
        return Ok(1);
    }
    
    // 检查加密文件是否可访问
    if let Err(_e) = fs::OpenOptions::new().read(true).write(true).open(path) {
        my_eprintln!("Warning: Encrypted file {} cannot be opened (file open exception).", path.display());
        return Ok(2); // 返回特殊代码表示文件打开异常
    }

    //开始读取加密文件
    let mut data: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
    File::open(path)
        .with_context(|| format!("Failed to open file for decryption: {}", path.display()))
        .and_then(|mut file| file.read_to_end(&mut data)
        .with_context(|| format!("Failed to read encrypted file: {}", path.display())))?;

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
    
    // 使用主密钥和nonce作为盐派生子密钥
    let subkey: Zeroizing<[u8; 32]> = derive_subkey_simple(master_key, all_xnonce_bytes)?;
    let cipher = MyCipher::new(subkey.as_ref())?;
    
    let pt: Zeroizing<Vec<u8>> = match cipher.decrypt(&file_xnonce, ct) {
        Ok(pt) => pt,
        Err(_) => {
            return Ok(98);
        }
    };

    // 验证解密后的数据哈希是否匹配
    let mut hasher_verify = Sha256::new(None,32)?;
    hasher_verify.update(&pt);
    let mut decrypted_hash:Zeroizing<[u8;32]> = Zeroizing::new([0u8;32]);
    hasher_verify.finalize_into(decrypted_hash.as_mut())?;
    
    // 解密存储的哈希
    let decrypted_stored_hash: Zeroizing<[u8; 32]> = match decrypt_file_hash(stored_encrypted_hash_bytes, &subkey, hash_xnonce_bytes) {
        Ok(hash) => hash,
        Err(_) => {return Ok(98);}
    };


    if decrypted_hash != decrypted_stored_hash {
        return Ok(98);// 不能绝对确定加密文件不完整，有可能是密钥输入有误或计算错误
    }

    Ok(0)
}

/// 验证流式加密文件
fn verify_streaming_encrypted_file(path: &Path, master_key: &[u8;32]) -> Result<i32> {
    // 检查加密文件是否可访问
    if let Err(_e) = fs::OpenOptions::new().read(true).write(true).open(path) {
        my_eprintln!("Warning: Encrypted file {} cannot be opened (file open exception).", path.display());
        return Ok(2); // 返回特殊代码表示文件打开异常
    }

    // 打开加密文件
    let mut encrypted_file = File::open(path)
        .with_context(|| format!("Failed to open file for streaming decryption: {}", path.display()))?;
    
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
    let mut verify_hasher = Sha256::new(None,32)?;

    // 流式读取、解密、写入（不计算哈希）
    loop {
        // 检查中断标志
        if crate::cli::is_interrupted() {
            my_println!("Interrupt signal received, stopping verification of {}", path.display());
            return Ok(1); // 返回成功，表示已停止处理
        }
        
        // 读取块大小 (4字节)
        let mut block_size_bytes = [0u8; 4];
        if let Err(e) = encrypted_file.read_exact(&mut block_size_bytes)
            // .with_context(|| format!("Failed to read block size from encrypted file: {}", path.display()))
        {
            match e.kind() {
                std::io::ErrorKind::UnexpectedEof => {return Ok(99);}
                _ => {return Err(anyhow!("Failed to read block size from encrypted file: {}", path.display()));}           
            }
        }
        
        let block_size = u32::from_le_bytes(block_size_bytes);
        
        // 如果块大小为0，表示文件结束
        if block_size == 0 {
            break;
        } else if block_size > (STREAMING_CHUNK_SIZE + 16) as u32 {
            //密文大小不合理 // 2025.12.17 还是98吧
            return Ok(98);
        }
        
        let block_size = block_size as usize;
        
        // 读取加密块
        let mut encrypted_block: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0u8; block_size]);
        if let Err(e) = encrypted_file.read_exact(&mut encrypted_block)
            // .with_context(|| format!("Failed to read encrypted block {} from file: {}", block_counter, path.display()))
        {
            match e.kind() {
                std::io::ErrorKind::UnexpectedEof => {return Ok(99);}
                _ => {return Err(anyhow!("Failed to read encrypted block {} from file: {}", block_counter, path.display()));}           
            }
        }
        
        // 为当前块生成 nonce
        let block_nonce_bytes: [u8; 24] = get_block_nonce_bytes(file_xnonce_bytes, block_counter)?;
        let block_nonce = MyXnonce::try_from_slice(&block_nonce_bytes)?;
        
        // 解密当前块
        let decrypted_block: Zeroizing<Vec<u8>> = match cipher.decrypt(&block_nonce, encrypted_block.as_ref()) {
            Ok(block) => block,
            Err(_) => {
                return Ok(98);// 不能绝对确定加密文件不完整，有可能是密钥输入有误或计算错误
            }
        };

        // 更新验证哈希
        verify_hasher.update(&decrypted_block);

        block_counter += 1;
    }
    
    // 读取存储的哈希 (48字节)
    let mut stored_encrypted_hash_bytes: Zeroizing<[u8; 48]> = Zeroizing::new([0u8; 48]);
    if let Err(e) = encrypted_file.read_exact(stored_encrypted_hash_bytes.as_mut())
        // .with_context(|| format!("Failed to read hash from encrypted file: {}", path.display()))
    {
        match e.kind() {
            std::io::ErrorKind::UnexpectedEof => {return Ok(99);}
            _ => {return Err(anyhow!("Failed to read hash from encrypted file: {}", path.display()));}           
        }
    };
    
    let mut computed_hash:Zeroizing<[u8;32]> = Zeroizing::new([0u8;32]);
    verify_hasher.finalize_into(computed_hash.as_mut())?;
    
    // 解密存储的哈希
    let decrypted_stored_hash: Zeroizing<[u8; 32]> = match decrypt_file_hash(stored_encrypted_hash_bytes.as_ref(), &subkey, hash_xnonce_bytes) {
        Ok(hash) => hash,
        Err(_) => {return Ok(98);}
    };
    

    if computed_hash != decrypted_stored_hash {
        return Ok(98);// 不能绝对确定加密文件不完整，有可能是密钥输入有误或计算错误
    }
    
    Ok(0)
}

/// 验证解密文件完整性
fn verify_decrypted_file(dec_path: &Path, enc_path: &Path, master_key: &[u8;32]) -> Result<i32> {
    // 检查中断标志
    if crate::cli::is_interrupted() {
        my_println!("Interrupt signal received, skipping verification of {}", dec_path.display());
        return Ok(1);
    }
    
    // 检查解密文件是否可访问
    if let Err(_e) = fs::OpenOptions::new().read(true).write(true).open(dec_path) {
        my_eprintln!("Warning: Decrypted file {} cannot be opened (file open exception).", dec_path.display());
        return Ok(2); // 返回特殊代码表示文件打开异常
    }
   
    // 检查文件是否为空
    let metadata = fs::metadata(dec_path)?;
    if metadata.len() == 0 {
        return Ok(99);
    }

    // 检查加密文件是否可访问
    if let Err(_e) = fs::OpenOptions::new().read(true).write(true).open(enc_path) {
        my_eprintln!("Warning: Encrypted file {} cannot be opened (file open exception).", enc_path.display());
        return Ok(2); // 返回特殊代码表示文件打开异常
    }

    // 加密文件完整性已验证，直接返回err, 而不是98
    let decrypted_stored_src_hash_bytes = get_decrypted_src_hash_bytes_from_enc_file(enc_path, master_key)
        .with_context(|| format!("Failed to get src_hash_bytes from enc_file: {}", enc_path.display()))?;

    // 从文件分块读取计算哈希
    let mut hasher = Sha256::new(None,32)?;
    let mut file_for_hash = match File::open(dec_path)
        .with_context(|| format!("Failed to open decrypted file for hash verification: {}", dec_path.display()))
    {
        Ok(file) => file,
        Err(e) => {
            return Err(e);
        }
    };
    
    let mut buffer: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0u8; 65536]); // 64KB 缓冲区
    loop {
        // 检查中断标志
        if crate::cli::is_interrupted() {
            my_println!("Interrupt signal received, stopping hash verification of {}", dec_path.display());
            return Ok(1); // 返回成功，表示已停止处理
        }
        
        let bytes_read = match file_for_hash.read(&mut buffer)
            .with_context(|| format!("Failed to read decrypted file for hash verification: {}", dec_path.display()))
        {
            Ok(bytes) => bytes,
            Err(e) => {
                return Err(e);
            }
        };
        
        if bytes_read == 0 {
            break;
        }
        
        hasher.update(&buffer[..bytes_read]);
    }
    
    
    // 计算解密数据的哈希
    let mut computed_hash:Zeroizing<[u8;32]> = Zeroizing::new([0u8;32]);
    hasher.finalize_into(computed_hash.as_mut())?;
    
    // 验证哈希
    if computed_hash != decrypted_stored_src_hash_bytes {
        return Ok(98);// 有可能是计算错误，注意只有加密文件验证正确时才有效，否则stored_src_hash_bytes没有意义
    }

    Ok(0)
}

fn get_decrypted_src_hash_bytes_from_enc_file(enc_path: &Path, master_key: &[u8;32]) -> Result<Zeroizing<[u8;32]>> {
    let mut file = File::open(enc_path)?;
    
    // 读取前48字节作为 all_xnonce（24字节文件nonce + 24字节哈希nonce）
    let mut all_xnonce_bytes = [0u8; 48];
    if let Err(e) = file.read_exact(&mut all_xnonce_bytes) {
        return Err(e).with_context(|| format!("Failed to read all_xnonce from encrypted file: {}", enc_path.display()));
    };
    
    // 拆分all_xnonce为文件nonce和哈希nonce
    let (_, hash_xnonce_bytes) = all_xnonce_bytes.split_at(24);

    // 使用主密钥和all_xnonce作为盐派生子密钥（与加密保持一致）
    let subkey: Zeroizing<[u8; 32]> = derive_subkey_simple(master_key, &all_xnonce_bytes)?;

    // 移动到文件末尾前 48 字节
    file.seek(SeekFrom::End(-48))?;

    let mut encrypted_hash_bytes: Zeroizing<[u8; 48]> = Zeroizing::new([0u8; 48]);
    file.read_exact(encrypted_hash_bytes.as_mut())?;
    
    // 解密存储的哈希
    let decrypted_stored_hash: Zeroizing<[u8; 32]> = decrypt_file_hash(encrypted_hash_bytes.as_ref(), &subkey, hash_xnonce_bytes)?;

    Ok(decrypted_stored_hash)
}

/// 验证解密文件完整性, 简易版
fn verify_decrypted_file_simple(dec_path: &Path) -> Result<i32> {
    // 检查中断标志
    if crate::cli::is_interrupted() {
        my_println!("Interrupt signal received, skipping verification of {}", dec_path.display());
        return Ok(1);
    }
    
    // 检查解密文件是否可访问
    if let Err(_e) = fs::OpenOptions::new().read(true).write(true).open(dec_path) {
        my_eprintln!("Warning: Decrypted file {} cannot be opened (file open exception).", dec_path.display());
        return Ok(2); // 返回特殊代码表示文件打开异常
    }
   
    // 检查文件是否为空
    let metadata = fs::metadata(dec_path)?;
    if metadata.len() == 0 {
        return Ok(99);
    }

    Ok(0)
}
