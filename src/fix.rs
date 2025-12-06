use anyhow::{Context, Result, anyhow};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce, aead::{KeyInit, Aead}};
use std::{fs::{self, File}, io::Read};
use std::path::{Path, PathBuf};
use sha2::{Sha256, Digest};
use ignore::WalkBuilder;
use ignore::DirEntry as ignore_DirEntry;
use zeroize::Zeroize;

use crate::*;

/// 处理修复目录
pub fn process_fix_dir(dir: &Path, master_key: &Key, exe_path: &Path, key_path_opt: Option<&Path>) -> Result<i32> {
    // 收集加密文件并查找重复的文件对
    let (duplicate_pairs, interrupted) = collect_files_for_fix(dir, exe_path, key_path_opt)?;
    
    // 如果被中断，直接退出
    if interrupted {
        println!("Fix operation interrupted by user");
        return Ok(1);
    }

    println!("Found {} duplicate file pairs to fix", duplicate_pairs.len());  
    
    if duplicate_pairs.is_empty() {
        println!("No duplicate files found, nothing to fix.");
        return Ok(0);
    }
    

    // 对所有重复文件对进行验证和修复
    let mut processed_count = 0;
    let mut deleted_encrypted_count = 0;
    let mut deleted_source_count = 0;
    let mut error_count = 0;
    let mut manual_required_count = 0;
    let mut manual_pairs = Vec::new();
    
    for (src_path, enc_path) in duplicate_pairs {
        // 检查中断标志
        if crate::cli::is_interrupted() {
            println!("Interrupt signal received, skipping duplicate pair fix.");
            return Ok(1);
        }

        println!("Fixing duplicate pair:");
        println!("  Source file: {}", src_path.display());
        println!("  Encrypted file: {}", enc_path.display());
        
        match verify_and_fix_pair(&src_path, &enc_path, master_key) {
            Ok(result) => {
                match result {
                    FixResult::DeletedEncrypted => {
                        println!("  -> Deleted encrypted file (encrypted file is incomplete)");
                        deleted_encrypted_count += 1;
                        processed_count += 1;
                    }
                    FixResult::DeletedSource => {
                        println!("  -> Deleted source file (source file is incomplete)");
                        deleted_source_count += 1;
                        processed_count += 1;
                    }
                    FixResult::Interrupt => {
                        println!("  -> Interrupted, stopping fix operation");
                        return Ok(1);
                    }
                    FixResult::ManualRequired{reason} => {
                        println!("  -> {reason} Manual intervention required, skipping");
                        manual_required_count += 1;
                        manual_pairs.push((src_path.clone(), enc_path.clone()));
                    }
                }
            }
            Err(e) => {
                eprintln!("  -> Error fixing pair: {}", e);
                error_count += 1;
            }
        }
    }
    
    println!("Fix summary:");
    println!("  Successfully processed: {} pairs", processed_count);
    println!("  Failed: {} pairs", error_count);
    println!("  Deleted encrypted files: {}", deleted_encrypted_count);
    println!("  Deleted source files: {}", deleted_source_count);
    println!("  Manual intervention required: {} pairs", manual_required_count);

    // 打印需要手动处理的文件对
    if !manual_pairs.is_empty() {
        println!("\nFiles requiring manual intervention:");
        for (i, (src_path, enc_path)) in manual_pairs.iter().enumerate() {
            println!("  {}. Source: {}, Encrypted: {}", 
                i + 1, 
                src_path.display(), 
                enc_path.display());
        }
    }

    Ok(0)
}

/// 收集加密文件并查找重复的文件对
/// 返回元组：(重复文件对列表, 是否被中断)
fn collect_files_for_fix(
    dir: &Path,
    exe_path: &Path,
    key_path_opt: Option<&Path>,
) -> Result<(Vec<(PathBuf, PathBuf)>, bool)> {
    let mut pairs = Vec::new();
    let mut interrupted = false;
    
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
            interrupted = true;
            break;
        }
        
        let entry = entry?;
        let path = entry.path();

        if entry.file_type().unwrap().is_file() {
            // 跳过自身和密钥文件
            if is_self(path, exe_path) || is_key_file(path, key_path_opt) {
                continue;
            }
            
            // let size = entry.metadata()?.len(); // 2025.12.6 因为只处理加密文件，不跳过空文件
            
            // 跳过空文件
            // if size == 0 {
            //     continue;
            // }
            
            // 只处理加密文件
            if is_encrypted_file(path) {
                // 获取文件名
                let file_name = match path.file_name() {
                    Some(name) => name.to_string_lossy().to_string(),
                    None => {
                        return Err(anyhow!("Cannot get file name for {}", path.display()));
                    }
                };
                
                // 检查是否以 .kitty_enc 结尾
                if !file_name.ends_with(&format!(".{}", ENC_SUFFIX)) {
                    return Err(anyhow!("Encrypted file does not end with .{}: {}", ENC_SUFFIX, path.display()));
                }
                
                // 删除 .kitty_enc 后缀得到源文件名
                let src_file_name = &file_name[..file_name.len() - format!(".{}", ENC_SUFFIX).len()];
                let parent = path.parent().unwrap_or(Path::new("."));
                let src_path = parent.join(src_file_name);
                
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
fn verify_and_fix_pair(src_path: &Path, enc_path: &Path, master_key: &Key) -> Result<FixResult> {
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
        let verify_decrypted_file_code = verify_decrypted_file(src_path, enc_path)?;
        if verify_decrypted_file_code == 1 {
            return Ok(FixResult::Interrupt);
        }
        if verify_decrypted_file_code == 2 {
            return Ok(FixResult::ManualRequired{reason:"源文件无法打开".to_string()});
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
fn verify_encrypted_file(src_path: &Path, enc_path: &Path, master_key: &Key) -> Result<i32> {    
    // 检查文件是否过小
    let metadata = fs::metadata(enc_path)?;
    if metadata.len() < 24 + 4 + 32 {
        return Ok(99);
    }
    let src_metadata =fs::metadata(src_path)?;
    if metadata.len() < src_metadata.len() {
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
            eprintln!("Error verifying {}: {}", enc_path.display(), e);
            Err(e)
        }
    }
}

/// 验证普通加密文件（只解密验证，不写入文件）
fn verify_regular_encrypted_file(path: &Path, master_key: &Key) -> Result<i32> {
    // 检查中断标志
    if crate::cli::is_interrupted() {
        println!("Interrupt signal received, skipping verification of {}", path.display());
        return Ok(1);
    }
    
    // 检查加密文件是否可访问
    if let Err(_e) = fs::OpenOptions::new().read(true).write(true).open(path) {
        eprintln!("Warning: Encrypted file {} cannot be opened (file open exception).", path.display());
        return Ok(2); // 返回特殊代码表示文件打开异常
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
            return Ok(98);// 不能绝对确定加密文件不完整，有可能是密钥输入有误或计算错误
        }
    };

    // 验证解密后的数据哈希是否匹配
    let mut hasher_verify = Sha256::new();
    hasher_verify.update(&pt);
    let decrypted_hash = hasher_verify.finalize();
    
    if decrypted_hash.as_slice() != stored_hash_bytes {
        // 安全擦除敏感数据
        subkey.zeroize();
        pt.zeroize();
        return Ok(98);// 不能绝对确定加密文件不完整，有可能是密钥输入有误或计算错误
    }

    // data.zeroize(); 其实 data 是密文, 应该不需要太严格
    subkey.zeroize();
    pt.zeroize();

    Ok(0)
}


/// 验证流式加密文件
fn verify_streaming_encrypted_file(path: &Path, master_key: &Key) -> Result<i32> {
    use std::io::{BufReader, Read};
    
    // 检查加密文件是否可访问
    if let Err(_e) = fs::OpenOptions::new().read(true).write(true).open(path) {
        eprintln!("Warning: Encrypted file {} cannot be opened (file open exception).", path.display());
        return Ok(2); // 返回特殊代码表示文件打开异常
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
        
    // 使用主密钥和nonce作为盐派生子密钥
    let mut subkey = derive_subkey_simple(master_key.as_slice().try_into().unwrap(), &xnonce_bytes)?;
    
    // 使用 XChaCha20Poly1305 进行流式解密
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&subkey));
    
    let mut block_counter: u64 = 0;
    let mut verify_hasher = Sha256::new();

    // 流式读取、解密、写入（不计算哈希）
    loop {
        // 检查中断标志
        if crate::cli::is_interrupted() {
            println!("Interrupt signal received, stopping verification of {}", path.display());
            // 安全擦除敏感数据
            xnonce_bytes.zeroize();
            subkey.zeroize();
            return Ok(1); // 返回成功，表示已停止处理
        }
        
        // 读取块大小 (4字节)
        let mut block_size_bytes = [0u8; 4];
        if let Err(e) = reader.read_exact(&mut block_size_bytes)
            // .with_context(|| format!("Failed to read block size from encrypted file: {}", path.display()))
        {
            // 安全擦除敏感数据
            block_size_bytes.zeroize();
            xnonce_bytes.zeroize();
            subkey.zeroize();
            match e.kind() {
                std::io::ErrorKind::UnexpectedEof => {return Ok(99);}
                _ => {return Err(anyhow!("Failed to read block size from encrypted file: {}", path.display()));}           
            }
        }
        
        let block_size = u32::from_le_bytes(block_size_bytes);
        
        // 安全擦除块大小字节
        block_size_bytes.zeroize();
        
        // 如果块大小为0，表示文件结束
        if block_size == 0 {
            break;
        } else if block_size > (STREAMING_CHUNK_SIZE + 16) as u32 {
            //密文大小不合理
            return Ok(99);
        }
        
        let block_size = block_size as usize;
        
        // 读取加密块
        let mut encrypted_block = vec![0u8; block_size];
        if let Err(e) = reader.read_exact(&mut encrypted_block)
            // .with_context(|| format!("Failed to read encrypted block {} from file: {}", block_counter, path.display()))
        {
            // 安全擦除敏感数据
            encrypted_block.zeroize();
            xnonce_bytes.zeroize();
            subkey.zeroize();
            match e.kind() {
                std::io::ErrorKind::UnexpectedEof => {return Ok(99);}
                _ => {return Err(anyhow!("Failed to read encrypted block {} from file: {}", block_counter, path.display()));}           
            }
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
        let mut decrypted_block = match cipher.decrypt(block_nonce, encrypted_block.as_slice()) {
            Ok(block) => block,
            Err(_) => {
                // 安全擦除敏感数据
                encrypted_block.zeroize();
                block_nonce_bytes.zeroize();
                xnonce_bytes.zeroize();
                subkey.zeroize();

                return Ok(98);// 不能绝对确定加密文件不完整，有可能是密钥输入有误或计算错误
            }
        };

        // 更新验证哈希
        verify_hasher.update(&decrypted_block);

        // 安全擦除敏感数据 (注意subkey, xnonce_bytes下一轮要用, 不能清)
        encrypted_block.zeroize();
        block_nonce_bytes.zeroize();
        decrypted_block.zeroize();

        block_counter += 1;
    }
    
    // 读取存储的哈希 (32字节)
    let mut stored_hash = [0u8; 32];
    if let Err(e) = reader.read_exact(&mut stored_hash)
        // .with_context(|| format!("Failed to read hash from encrypted file: {}", path.display()))
    {
        // 安全擦除敏感数据
        stored_hash.zeroize();
        xnonce_bytes.zeroize();
        subkey.zeroize();
        match e.kind() {
            std::io::ErrorKind::UnexpectedEof => {return Ok(99);}
            _ => {return Err(anyhow!("Failed to read hash from encrypted file: {}", path.display()));}           
        }
    };
    
    // 安全擦除敏感数据
    xnonce_bytes.zeroize();
    subkey.zeroize();

    let computed_hash = verify_hasher.finalize();
    
    if computed_hash.as_slice() != stored_hash {
        // 安全擦除敏感数据
        stored_hash.zeroize();
        return Ok(98);// 不能绝对确定加密文件不完整，有可能是密钥输入有误或计算错误
    }

    // 安全擦除存储的哈希
    stored_hash.zeroize();
    
    Ok(0)
}

/// 验证解密文件完整性
fn verify_decrypted_file(dec_path: &Path, enc_path: &Path) -> Result<i32> {
    // 检查中断标志
    if crate::cli::is_interrupted() {
        println!("Interrupt signal received, skipping verification of {}", dec_path.display());
        return Ok(1);
    }
    
    // 检查解密文件是否可访问
    if let Err(_e) = fs::OpenOptions::new().read(true).write(true).open(dec_path) {
        eprintln!("Warning: Decrypted file {} cannot be opened (file open exception).", dec_path.display());
        return Ok(2); // 返回特殊代码表示文件打开异常
    }
   
    // 检查文件是否为空
    let metadata = fs::metadata(dec_path)?;
    if metadata.len() == 0 {
        return Ok(99);
    }

    // 检查加密文件是否可访问
    if let Err(_e) = fs::OpenOptions::new().read(true).write(true).open(enc_path) {
        eprintln!("Warning: Encrypted file {} cannot be opened (file open exception).", enc_path.display());
        return Ok(2); // 返回特殊代码表示文件打开异常
    }

    let mut stored_src_hash_bytes = get_src_hash_bytes_from_enc_file(enc_path)
        .with_context(|| format!("Failed to get src_hash_bytes from enc_file: {}", enc_path.display()))?;

    // 从文件分块读取计算哈希
    let mut hasher = Sha256::new();
    let mut file_for_hash = match File::open(dec_path)
        .with_context(|| format!("Failed to open decrypted file for hash verification: {}", dec_path.display()))
    {
        Ok(file) => file,
        Err(e) => {
            // 安全擦除敏感数据
            stored_src_hash_bytes.zeroize();
            return Err(e);
        }
    };
    
    let mut buffer = vec![0u8; 65536]; // 64KB 缓冲区
    loop {
        // 检查中断标志
        if crate::cli::is_interrupted() {
            println!("Interrupt signal received, stopping hash verification of {}", dec_path.display());
            // 安全擦除敏感数据
            buffer.zeroize();
            stored_src_hash_bytes.zeroize();
            return Ok(1); // 返回成功，表示已停止处理
        }
        
        let bytes_read = match file_for_hash.read(&mut buffer)
            .with_context(|| format!("Failed to read decrypted file for hash verification: {}", dec_path.display()))
        {
            Ok(bytes) => bytes,
            Err(e) => {
                // 安全擦除敏感数据
                buffer.zeroize();
                stored_src_hash_bytes.zeroize();
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
    if computed_hash.as_slice() != stored_src_hash_bytes {
        // 安全擦除敏感数据
        stored_src_hash_bytes.zeroize();
        return Ok(98);// 有可能是计算错误，注意只有加密文件验证正确时才有效，否则stored_src_hash_bytes没有意义
    }
    
    // 安全擦除存储的哈希
    stored_src_hash_bytes.zeroize();

    Ok(0)
}


fn get_src_hash_bytes_from_enc_file(enc_path: &Path) -> Result<[u8;32]> {
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom};

    let mut file = File::open(enc_path)?;

    // 移动到文件末尾前 32 字节
    file.seek(SeekFrom::End(-32))?;

    let mut hash_bytes = [0u8; 32];
    file.read_exact(&mut hash_bytes)?;

    Ok(hash_bytes)

}

/// 验证解密文件完整性, 简易版
fn verify_decrypted_file_simple(dec_path: &Path) -> Result<i32> {
    // 检查中断标志
    if crate::cli::is_interrupted() {
        println!("Interrupt signal received, skipping verification of {}", dec_path.display());
        return Ok(1);
    }
    
    // 检查解密文件是否可访问
    if let Err(_e) = fs::OpenOptions::new().read(true).write(true).open(dec_path) {
        eprintln!("Warning: Decrypted file {} cannot be opened (file open exception).", dec_path.display());
        return Ok(2); // 返回特殊代码表示文件打开异常
    }
   
    // 检查文件是否为空
    let metadata = fs::metadata(dec_path)?;
    if metadata.len() == 0 {
        return Ok(99);
    }

    Ok(0)
}
