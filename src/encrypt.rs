use anyhow::{Context, Result, anyhow};
use rand::rngs::OsRng;
use rand::TryRngCore;
use std::fs::{self, File};
use std::io::{Write, Read};
use std::path::{Path, PathBuf};
use std::sync::mpsc::Receiver;
use crate::MySha256 as Sha256;
use zeroize::Zeroizing;
use rayon::prelude::*;  // 添加 rayon 并行处理
use ignore::WalkBuilder;
use ignore::DirEntry as ignore_DirEntry;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}, mpsc};
use std::thread;

use crate::*;

pub fn process_encrypt_dir(dir: &Path, master_key: &[u8;32], key_path_opt: Option<&Path>, exe_path: &Path) -> Result<i32> {
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
            // 指定输入为软链接时，似乎entry的对象为实际文件（is_file为true），path依然为软链接
            files_to_process.push((path.to_path_buf(), size));
        }
    }
    
    my_println!("Found {} files to process, {} empty files skipped", files_to_process.len(), skipped_empty_count);
    
    if files_to_process.is_empty() {
        my_println!("No files to encrypt.");
        return Ok(0);
    }
    
    // 使用 rayon 并行处理文件
    let results: Vec<Result<i32>> = files_to_process
        .par_iter()
        .map(|(path, size)| {
            // 检查中断标志，如果已中断则跳过此文件
            if crate::cli::is_interrupted() {
                my_println!("Skipping {} due to interrupt signal", path.display());
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
                        // 1 => my_println!("Skipped {} due to interrupt", path.display()),
                        // 2 => my_println!("Skipped {} (file open exception)", path.display()),
                        // 3 => my_println!("Skipped {} (target exists)", path.display()),
                        _ => (),
                    }
                }
                Err(e) => {
                    my_eprintln!("Error encrypting {}: {}", path.display(), e);
                }
            }
            result
        })
        .collect(); // 2026.1.5 完成一个任务就收集一次，如果一个任务panic, 主线程收集后会直接panic
    
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
    
    my_println!("Encryption summary:");
    my_println!("  Found {} files to encrypt", files_to_process.len());
    my_println!("  Successfully encrypted: {} files", success_count);
    my_println!("  Skipped (interrupted): {} files", skipped_interrupt_count);
    my_println!("  Skipped (file open exception): {} files", skipped_open_exception_count);
    my_println!("  Skipped (target exists): {} files", skipped_target_exists_count);
    my_println!("  Failed: {} files", error_count);
    my_println!("  Empty files skipped: {} files", skipped_empty_count);
    
    // 如果存在目标文件已存在的警告，打印额外提示
    if skipped_target_exists_count > 0 {
        my_println!("Warning: {} Target encrypted file already exists, you need to fix it", skipped_target_exists_count);
    }
    
    // // 如果有错误，返回第一个错误
    // for result in results {
    //     if let Err(e) = result {
    //         return Err(e);
    //     }
    // }
    
    Ok(0)
}

fn encrypt_file(path: &Path, master_key: &[u8;32]) -> Result<i32> {
    // 检查中断标志
    if crate::cli::is_interrupted() {
        my_println!("Interrupt signal received, skipping encryption of {}", path.display());
        return Ok(1);
    }
    
    // 检查文件是否可访问
    if let Err(_e) = fs::OpenOptions::new().read(true).write(true).open(path) {
        my_eprintln!("Warning: File {} cannot be opened (file open exception).", path.display());
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
    if out_path.try_exists()? {
        my_eprintln!("Warning: Target encrypted file {} already exists, you need to fix it", out_path.display());
        return Ok(3); // 返回代码3表示目标文件已存在而跳过
    }

    // Random XNonce per file (48 bytes)
    let mut all_xnonce_bytes = [0u8; 48];
    if let Err(e) = OsRng.try_fill_bytes(&mut all_xnonce_bytes) {
        return Err(e).context("Failed to generate random nonce for file encryption");
    }
    let (file_xnonce_bytes, hash_xnonce_bytes) = all_xnonce_bytes.split_at(24);
    let file_xnonce = MyXnonce::try_from_slice(file_xnonce_bytes)?;
    
    // 使用主密钥和all_nonce作为盐派生子密钥 
    let subkey: Zeroizing<[u8; 32]> = match derive_subkey_simple(master_key, &all_xnonce_bytes) {
        Ok(subkey) => subkey, // 保护数据
        Err(e) => {
            return Err(e);
        }
    };

    // 启动hash子线程
    let stop_flag: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
    let hash_calculation_subthread = {
        let stop_flag_2 = stop_flag.clone();
        let path = path.to_owned();
        thread::spawn(||{hash_calculation_subthread_fn(path, stop_flag_2)})
    };

    // 读取源文件
    let mut data: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());// 保护数据
    if let Err(e) = (|| -> Result<()> {
        let mut file = File::open(path)
            .with_context(|| format!("Failed to open file for encryption: {}", path.display()))?;
        file.try_lock_shared()
            .with_context(|| format!("Failed to lock file for encryption: {}", path.display()))?;
        file.read_to_end(&mut data)
            .with_context(|| format!("Failed to read file: {}", path.display()))?;
        file.unlock()
            .with_context(|| format!("Failed to unlock file: {}", path.display()))?;
        Ok(())
    })() {
        stop_flag.store(true, Ordering::SeqCst);
        return Err(e);
    };

    // 2025.12.25 根据chacha20poly1305 = "0.10.1"的文档，cipher在drop时实现内部清零
    let cipher = MyCipher::new(subkey.as_ref())
        .map_err(|e|{stop_flag.store(true, Ordering::SeqCst);e})?;
    
    let ct: Zeroizing<Vec<u8>> = match cipher.encrypt(&file_xnonce, data.as_ref()) {
        Ok(ct) => ct,
        Err(_) => {
            stop_flag.store(true, Ordering::SeqCst);
            return Err(anyhow!("Encryption failed for {}", path.display()));
        }
    };

    // 获取源文件hash, 如果子线程panic，直接panic
    let original_hash: Zeroizing<[u8; 32]> = match hash_calculation_subthread.join().unwrap(){
        Ok(original_hash) => original_hash,
        Err(e) => {
            return Err(anyhow!("Hash_Calculation_SubThread_Err: {e}"));
        }
    };
    // 加密hash
    let encrypted_original_hash: Zeroizing<Vec<u8>> = match encrypt_file_hash(&original_hash, &subkey, hash_xnonce_bytes) {
        Ok(encrypted_original_hash) => encrypted_original_hash,
        Err(e) => {
            return Err(e);
        }
    };

    // Output: [xnonce (48 bytes) || 4 bytes 0 (普通加密标记) || ciphertext || encrypted_original_hash(48 bytes)]
    let mut out_file = File::create_new(&out_path)
        .with_context(|| format!("Failed to create encrypted file: {}", out_path.display()))?;

    // 写入数据，逐段写入，避免中间 Vec
    if let Err(e) = (|| -> Result<()> {
        out_file.try_lock()
            .with_context(|| format!("Failed to lock encrypted file: {}", out_path.display()))?;
        out_file.write_all(&all_xnonce_bytes)
            .with_context(|| "Failed to write nonce")?;
        out_file.write_all(&[0u8; 4])
            .with_context(|| "Failed to write encryption marker")?;
        out_file.write_all(&ct)
            .with_context(|| "Failed to write ciphertext")?;
        out_file.write_all(&encrypted_original_hash)
            .with_context(|| "Failed to write encrypted hash")?;
        out_file.flush()
            .with_context(|| "Failed to flush buffer")?;
        out_file.unlock()
            .with_context(|| format!("Failed to unlock encrypted file: {}", out_path.display()))?;
        Ok(())
    })() {
        // 写入失败时清理文件
        std::fs::remove_file(out_path).ok();
        return Err(e);
    }

    match encrypt_file_verify(&out_path, master_key){
        Ok(0) => {}
        other => {
            fs::remove_file(&out_path).ok();
            return other;
        }
    };

    // 只有加密文件验证成功后才删除源文件 
    // 2025.12.11 remove_file 是原子操作，不会出现“原文件删一半失败”的情况。
    // 失败时文件保持完整，成功时整个目录项被移除。
    if let Err(e) = fs::remove_file(path) {
        // 如果删除原文件失败，清理已创建的加密文件
        fs::remove_file(&out_path).ok();
        return Err(e).with_context(|| format!("Failed to remove original file: {}", path.display()));
    }

    my_println!("Encrypted (original removed, integrity verified): {}", path.display());
    Ok(0)
}

fn encrypt_file_verify(out_path: &Path, master_key: &[u8;32]) -> Result<i32> {
    // 检查中断标志
    if crate::cli::is_interrupted() {
        my_println!("Interrupt signal received, skipping verification of {}", out_path.display());
        return Ok(1);
    }
    
    // 验证加密文件是否写入成功
    if let Err(e) = verify_file_not_empty(&out_path) {
        return Err(e);
    };

    // 验证加密文件可以正确解密
    let encrypted_data: Zeroizing<Vec<u8>> = match read_file_for_verification(&out_path) {
        Ok(data) => data,// 保护数据
        Err(e) => {
            return Err(e);
        }
    };

    if encrypted_data.len() < 48 + 4 + 48 {
        return Err(anyhow!("Encrypted file is corrupted: {}", out_path.display()));
    }

    // 分离 xnonce、加密类型标记、密文和哈希
    let (all_xnonce_bytes_verify, rest) = encrypted_data.split_at(48);
    let (enc_type_marker_verify, rest) = rest.split_at(4);
    let (ct_verify, stored_encrypted_hash_bytes) = rest.split_at(rest.len() - 48);
    
    // 检查加密类型标记
    if enc_type_marker_verify != [0u8; 4] {
        return Err(anyhow!("Invalid encryption type marker in encrypted file: {}", out_path.display()));
    }
    
    let (file_xnonce_bytes_verify, hash_xnonce_bytes_verify) = all_xnonce_bytes_verify.split_at(24);
    let file_xnonce_verify = MyXnonce::try_from_slice(file_xnonce_bytes_verify)?;

    // 验证时使用相同的子密钥派生方法
    let subkey_verify: Zeroizing<[u8; 32]> = derive_subkey_simple(master_key, all_xnonce_bytes_verify)?;// 保护数据
    let cipher_verify = MyCipher::new(subkey_verify.as_ref())?;
    // 保护数据
    let pt_verify: Zeroizing<Vec<u8>> = cipher_verify
        .decrypt(&file_xnonce_verify, ct_verify)
        .map_err(|_| {
            anyhow!("Encryption verification failed for {}", out_path.display())
        })?;

    // 验证解密后的数据哈希是否匹配
    let mut hasher_verify = Sha256::new(None,32)?;
    hasher_verify.update(&pt_verify);
    // 保护数据
    let mut hash_need_verify:Zeroizing<[u8;32]> = Zeroizing::new([0u8;32]);
    hasher_verify.finalize_into(hash_need_verify.as_mut())?;
    
    // 解密hash // 保护数据
    let decrypted_stored_hash_bytes: Zeroizing<[u8; 32]> = decrypt_file_hash(stored_encrypted_hash_bytes, &subkey_verify, hash_xnonce_bytes_verify)?;

    if hash_need_verify != decrypted_stored_hash_bytes {
        return Err(anyhow!("Integrity check failed for encrypted file: {}", out_path.display()));
    }

    Ok(0)
}
    
/// 流式加密大文件（使用 XChaCha20Poly1305）
fn encrypt_file_streaming(path: &Path, master_key: &[u8;32]) -> Result<i32> {
    // 检查文件是否可访问
    if let Err(_e) = fs::OpenOptions::new().read(true).write(true).open(path) {
        my_eprintln!("Warning: File {} cannot be opened (file open exception).", path.display());
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
    if out_path.try_exists()? {
        my_eprintln!("Warning: Target encrypted file {} already exists, you need to fix it", out_path.display());
        return Ok(3); // 返回代码3表示目标文件已存在而跳过
    }

    // 打开源文件
    let mut source_file = File::open(path)
        .with_context(|| format!("Failed to open file for streaming encryption: {}", path.display()))?;
    source_file.try_lock_shared()
        .with_context(|| format!("Failed to lock file for streaming encryption: {}", path.display()))?;

    // 生成 48 字节的扩展 nonce
    let mut all_xnonce_bytes = [0u8; 48];
    if let Err(e) = OsRng.try_fill_bytes(&mut all_xnonce_bytes) {
        return Err(e).context("Failed to generate random nonce for streaming encryption");
    }
    // 拆分nonce
    let (file_xnonce_bytes, hash_xnonce_bytes) = all_xnonce_bytes.split_at(24);
    
    // 使用主密钥和all_nonce作为盐派生子密钥
    let subkey: Zeroizing<[u8; 32]> = derive_subkey_simple(master_key, &all_xnonce_bytes)?;
    
    // 使用 XChaCha20Poly1305 进行流式加密
    let cipher = MyCipher::new(subkey.as_ref())?;
        
    // 缓冲区大小：1MB
    let mut buffer: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0u8; STREAMING_CHUNK_SIZE]);
 
    // 块计数器，用于生成唯一的 nonce
    let mut block_counter: u64 = 0;

    // 创建输出文件
    let mut out_file = File::create_new(&out_path)
        .with_context(|| format!("Failed to create encrypted file: {}", out_path.display()))?;
    if let Err(e) = out_file.try_lock() {
        fs::remove_file(&out_path).ok();
        return Err(e).with_context(|| format!("Failed to lock encrypted file: {}", out_path.display()))
    }

    // 先写入 nonce
    if let Err(e) = out_file.write_all(&all_xnonce_bytes) {
        fs::remove_file(&out_path).ok();
        return Err(e).with_context(|| format!("Failed to write nonce to encrypted file: {}", out_path.display()));
    }

    // 启动hash子线程
    let stop_flag: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
    let subthread_err_flag: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
    let hash_calculation_subthread = {
        let stop_flag_2 = stop_flag.clone();
        let subthread_err_flag_2 = subthread_err_flag.clone();
        let path = path.to_owned();
        thread::spawn(move||{
            match hash_calculation_subthread_fn(path, stop_flag_2){
                Ok(hash) => Ok(hash),
                Err(e) => {
                    subthread_err_flag_2.store(true, Ordering::SeqCst);
                    // my_eprintln!("Hash_Calculation_SubThread_Err: {e}");
                    return Err(anyhow!("Hash_Calculation_SubThread_Err: {e}"));
                }
            }
        })
    };

    // 流式读取、计算哈希、加密、写入
    let loop_result = (||-> Result<i32> {
        loop {
            // 检查中断标志
            if crate::cli::is_interrupted() {
                my_println!("Interrupt signal received, stopping encryption of {}", path.display());
                return Ok(1); // 返回成功，表示已停止处理
            }
            // 检查子线程是否出错
            if subthread_err_flag.load(Ordering::SeqCst) {
                return Ok(9);
            }
            let bytes_read = match source_file.read(&mut buffer) {
                Ok(bytes) => bytes,
                Err(e) => {
                    return Err(e).with_context(|| format!("Failed to read from source file: {}", path.display()));
                }
            };
            
            if bytes_read == 0 {
                break;
            }
                     
            // 为每个块生成唯一的 nonce
            let block_nonce_bytes: [u8; 24] = get_block_nonce_bytes(file_xnonce_bytes, block_counter)?;
            let block_nonce = MyXnonce::try_from_slice(&block_nonce_bytes)?;
            
            // 加密当前块
            let ct: Zeroizing<Vec<u8>> = cipher.encrypt(&block_nonce, &buffer[..bytes_read])
                .map_err(|_| {
                    anyhow!("Encryption failed for block {} in file: {}", block_counter, path.display())
                })?;
            
            // 写入加密块大小（4字节）和加密块数据
            let ct_len = ct.len() as u32;
            if let Err(e) = out_file.write_all(&ct_len.to_le_bytes()) {
                return Err(e).with_context(|| format!("Failed to write block size to file: {}", out_path.display()));
            }
            
            if let Err(e) = out_file.write_all(&ct) {
                return Err(e).with_context(|| format!("Failed to write encrypted block to file: {}", out_path.display()));
            }
            
            block_counter += 1;
        }
        Ok(0)
    })();
    match loop_result {
        Ok(0) => {}
        Ok(9) => {
            fs::remove_file(&out_path).ok();
            match hash_calculation_subthread.join().unwrap(){
                Err(e) => {return Err(e);}
                Ok(_) => {return Err(anyhow!("Hash_Calculation_SubThread_Err_Flag has been set but result is not error"));}
            }
        }
        other => {
            stop_flag.store(true, Ordering::SeqCst);
            fs::remove_file(&out_path).ok();
            return other;
        }   
    };

    // 解锁源文件
    if let Err(e) = source_file.unlock() {
        stop_flag.store(true, Ordering::SeqCst);
        fs::remove_file(&out_path).ok();
        return Err(e).with_context(|| format!("Failed to unlock source file: {}", path.display()))
    }
    
    // 写入结束标记：4字节0表示下一个块大小为0
    let end_marker: u32 = 0;
    if let Err(e) = out_file.write_all(&end_marker.to_le_bytes()) {
        stop_flag.store(true, Ordering::SeqCst);
        // 清理已创建的加密文件
        fs::remove_file(&out_path).ok();
        return Err(e).with_context(|| format!("Failed to write end marker to encrypted file: {}", out_path.display()));
    }

    // 获取源文件hash, 如果子线程panic，直接panic
    let original_hash: Zeroizing<[u8; 32]> = match hash_calculation_subthread.join().unwrap(){
        Ok(original_hash) => original_hash,
        Err(e) => {
            fs::remove_file(&out_path).ok();
            return Err(e);
        }
    };
    
    // 加密hash
    let encrypted_original_hash: Zeroizing<Vec<u8>> = encrypt_file_hash(&original_hash, &subkey, hash_xnonce_bytes)
        .map_err(|e|{fs::remove_file(&out_path).ok();e})?;
    
    // 写入哈希
    if let Err(e) = out_file.write_all(encrypted_original_hash.as_ref()) {
        // 清理已创建的加密文件
        fs::remove_file(&out_path).ok();
        return Err(e).with_context(|| format!("Failed to write hash to encrypted file: {}", out_path.display()));
    }
    
    // 确保所有数据都写入磁盘
    if let Err(e) = out_file.flush() {
        // 清理已创建的加密文件
        fs::remove_file(&out_path).ok();
        return Err(e).with_context(|| format!("Failed to flush encrypted file: {}", out_path.display()));
    }
    // 解锁加密文件
    if let Err(e) = out_file.unlock() {
        fs::remove_file(&out_path).ok();
        return Err(e).with_context(|| format!("Failed to unlock encrypted file: {}", out_path.display()))
    }

    match encrypt_file_streaming_verify(&out_path, master_key){
            Ok(0) => {}
            other => {
                fs::remove_file(&out_path).ok();
                return other;
            }
        };
    
    // 只有加密文件验证成功后才删除源文件
    if let Err(e) = fs::remove_file(path) {
        // 如果删除原文件失败，清理已创建的加密文件
        fs::remove_file(&out_path).ok();
        return Err(e).with_context(|| format!("Failed to remove original file: {}", path.display()));
    }
    
    my_println!("Encrypted (streaming, original removed, integrity verified): {}", path.display());
    Ok(0)
}

fn encrypt_file_streaming_verify(out_path: &Path, master_key: &[u8;32]) -> Result<i32> {
    // 验证加密文件
    if let Err(e) = verify_file_not_empty(&out_path) {
        return Err(e);
    }
    
    // 流式验证加密文件
    let mut verify_file = match File::open(&out_path) {
        Ok(file) => file,
        Err(e) => {
            return Err(e).with_context(|| format!("Failed to open encrypted file for verification: {}", out_path.display()));
        }
    };
    verify_file.try_lock_shared()
        .with_context(|| format!("Failed to lock encrypted file for verification: {}", out_path.display()))?;

    // 读取 nonce (48字节)
    let mut all_xnonce_bytes_verify = [0u8; 48];
    if let Err(e) = verify_file.read_exact(&mut all_xnonce_bytes_verify) {
        return Err(e).with_context(|| format!("Failed to read nonce from encrypted file: {}", out_path.display()));
    }
    // 拆分nonce
    let (file_xnonce_bytes_verify, hash_xnonce_bytes_verify) = all_xnonce_bytes_verify.split_at(24);

    // 验证时使用相同的子密钥派生方法
    let subkey_verify: Zeroizing<[u8; 32]> = derive_subkey_simple(master_key, &all_xnonce_bytes_verify)?;
    let cipher_verify = MyCipher::new(subkey_verify.as_ref())?;
    
    let mut verify_block_counter: u64 = 0;

    // 哈希验证子线程   
    let (tx, rx) = mpsc::channel::<Zeroizing<Vec<u8>>>();
    let stop_flag: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
    let subthread_err_flag: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));  
    let hash_verify_subthread = {
        let rx_2 = rx;
        let stop_flag_2 = stop_flag.clone();
        let subthread_err_flag_2 = subthread_err_flag.clone();
        let out_path = out_path.to_owned();
        thread::spawn(move||{
            match hash_verify_subthread_fn(rx_2, stop_flag_2, out_path){
                Ok(hash) => Ok(hash),
                Err(e) => {
                    subthread_err_flag_2.store(true, Ordering::SeqCst);
                    return Err(anyhow!("Hash_Verify_SubThread_Err: {e}"));
                }
            }
        })
    };

    // 流式读取并验证每个加密块
    let loop_result = (|| -> Result<i32> {
        loop {
            // 检查中断标志
            if crate::cli::is_interrupted() {
                my_println!("Interrupt signal received, stopping verification of {}", out_path.display());
                return Ok(1); // 返回成功，表示已停止处理
            }
            // 检查子线程是否出错
            if subthread_err_flag.load(Ordering::SeqCst) {
                return Ok(9);
            }

            // 读取块大小 (4字节)
            let mut block_size_bytes = [0u8; 4];
            if let Err(e) = verify_file.read_exact(&mut block_size_bytes) {
                return Err(e).with_context(|| format!("Failed to read block size from encrypted file: {}", out_path.display()));
            }
            
            let block_size = u32::from_le_bytes(block_size_bytes);
            
            // 如果块大小为0，表示文件结束
            if block_size == 0 {
                break;
            }
            
            let block_size = block_size as usize;
            
            // 读取加密块
            let mut encrypted_block: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0u8; block_size]);
            if let Err(e) = verify_file.read_exact(&mut encrypted_block) {
                return Err(e).with_context(|| format!("Failed to read encrypted block {} from file: {}", verify_block_counter, out_path.display()));
            }
            
            // 为当前块生成 nonce
            // 为每个块生成唯一的 nonce
            let block_nonce_bytes: [u8; 24] = get_block_nonce_bytes(file_xnonce_bytes_verify, verify_block_counter)?;
            let block_nonce = MyXnonce::try_from_slice(&block_nonce_bytes)?;
            
            // 解密当前块
            let decrypted_block: Zeroizing<Vec<u8>> = cipher_verify.decrypt(&block_nonce, encrypted_block.as_ref())
                .map_err(|_| {
                    anyhow!("Encryption verification failed for block {}: {}", verify_block_counter, out_path.display())
                })?;
            
            // 更新验证哈希
            tx.send(decrypted_block)
                .context(format!("Send decrypted block {} to hash verify subthread failed: {}", verify_block_counter, out_path.display()))?;

            verify_block_counter += 1;
        }
        Ok(0)
    })();
    drop(tx);
    match loop_result {
        Ok(0) => {}
        Ok(9) => {
            match hash_verify_subthread.join().unwrap(){
                Err(e) => {return Err(e);}
                Ok(_) => {return Err(anyhow!("Hash_Verify_SubThread_Err_Flag has been set but result is not error"));}
            }
        }       
        other => {
            stop_flag.store(true, Ordering::SeqCst);
            return other;
        }   
    };
   
    // 读取并验证哈希 (48字节)
    let mut stored_encrypted_hash: Zeroizing<[u8; 48]> = Zeroizing::new([0u8; 48]);
    if let Err(e) = verify_file.read_exact(stored_encrypted_hash.as_mut()) {
        stop_flag.store(true, Ordering::SeqCst);
        return Err(e).with_context(|| format!("Failed to read hash from encrypted file: {}", out_path.display()));
    }
    if let Err(e) = verify_file.unlock() {
        stop_flag.store(true, Ordering::SeqCst);
        return Err(e).with_context(|| format!("Failed to unlock encrypted file during verification: {}", out_path.display()));
    }
    let computed_hash: Zeroizing<[u8; 32]> = hash_verify_subthread.join().unwrap()?;
 
    let decrypted_stored_hash_bytes: Zeroizing<[u8; 32]> = decrypt_file_hash(stored_encrypted_hash.as_ref(), &subkey_verify, hash_xnonce_bytes_verify)?;
    
    if computed_hash != decrypted_stored_hash_bytes {
        return Err(anyhow!("Integrity check failed for encrypted file: {}", out_path.display()));
    }
    Ok(0)
}

/// 读取并计算源文件哈希
fn hash_calculation_subthread_fn(src_path: PathBuf, stop_flag: Arc<AtomicBool>) -> Result<Zeroizing<[u8; 32]>> {    
    let mut src_file = match File::open(&src_path) {
        Ok(file) => file,
        Err(e) => {
            return Err(e).with_context(|| format!("Failed to open source file for hash calculation: {}", src_path.display()));
        }
    };
    src_file.try_lock_shared()
        .with_context(|| format!("Failed to lock source file for hash calculation: {}", src_path.display()))?;

    let mut hasher = Sha256::new(None,32)?;
    
    let mut buffer: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0u8; 65536]); // 64KB 缓冲区
    loop {
        // 检查中断标志
        if stop_flag.load(Ordering::SeqCst) {
            my_println!("Hash_Calculation_SubThread: Stop signal received, stopping hash calculation of {}", src_path.display());
            return Err(anyhow!("Stop signal received, stopping hash calculation of {}", src_path.display()));
        }
        
        let bytes_read = match src_file.read(&mut buffer)
            .with_context(|| format!("Failed to read source file for hash calculation: {}", src_path.display()))
        {
            Ok(bytes) => bytes,
            Err(e) => {return Err(e);}
        };
        
        if bytes_read == 0 {
            break;
        }
        
        hasher.update(&buffer[..bytes_read]);
    }
    src_file.unlock()
        .with_context(|| format!("Failed to unlock source file during hash calculation: {}", src_path.display()))?;
    
    
    // 计算哈希
    let mut computed_hash:Zeroizing<[u8;32]> = Zeroizing::new([0u8;32]);
    hasher.finalize_into(computed_hash.as_mut())?;
        
    Ok(computed_hash)
}

fn hash_verify_subthread_fn(rx: Receiver<Zeroizing<Vec<u8>>>, stop_flag: Arc<AtomicBool>, out_path: PathBuf)-> Result<Zeroizing<[u8;32]>>{
    let mut verify_hasher = Sha256::new(None,32)?; 
    for msg in rx {
        if stop_flag.load(Ordering::SeqCst) {
            my_println!("Hash_Verify_SubThread: Stop signal received, stopping hash verification of {}", out_path.display());
            return Err(anyhow!("Stop signal received, stopping hash verification of {}", out_path.display()));
        }
        verify_hasher.update(&msg);
    }
    if stop_flag.load(Ordering::SeqCst) {
        my_println!("Hash_Verify_SubThread: Stop signal received, stopping hash verification of {}", out_path.display());
        return Err(anyhow!("Stop signal received, stopping hash verification of {}", out_path.display()));
    }
    let mut computed_hash:Zeroizing<[u8;32]> = Zeroizing::new([0u8;32]);
    verify_hasher.finalize_into(computed_hash.as_mut())?;
    Ok(computed_hash)
}