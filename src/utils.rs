use anyhow::{anyhow, Context, Result};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use ignore::DirEntry as ignore_DirEntry;
use zeroize::Zeroizing;

use crate::*;

/// 规范化路径，移除 . 和 .. 组件
pub fn normalize_path(path: &Path, run_dir: &Path) -> PathBuf {
    // 使用更简洁的方式规范化路径
    let mut normalized = PathBuf::new();
    
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {
                // 忽略当前目录 .
            }
            std::path::Component::ParentDir => {
                // 处理上级目录 ..
                normalized.pop();
            }
            _ => {
                normalized.push(component);
            }
        }
    }
    
    if normalized.as_os_str().is_empty() {
        run_dir.to_path_buf()// 统一绝对路径不可能执行到这里，还是兜底
    } else {
        normalized
    }
}

#[cfg(any())]
fn filter_entry(e: &DirEntry) -> bool {
    // 跳过 . 开头的文件和文件夹
    let name = e.file_name().to_string_lossy();
    // 过滤以点开头的目录（如 .git, .vscode 等）
    if name.starts_with('.') {
        return false;
    }
    true
}

pub fn ignore_filter_entry(e: &ignore_DirEntry) -> bool {
    // 跳过 . 开头的文件和文件夹
    let name = e.file_name().to_string_lossy();
    // 过滤以点开头的目录（如 .git, .vscode 等）
    if name.starts_with('.') {
        return false;
    }
    true
}

#[cfg(any())]
fn is_self(path: &Path, exe_path: &Path) -> Result<bool> {
    let p = fs::canonicalize(path)
        .with_context(|| format!("Failed to canonicalize path: {}", path.display()))?;

    let e = fs::canonicalize(exe_path)
        .with_context(|| format!("Failed to canonicalize exe_path: {}", exe_path.display()))?;

    Ok(p == e)
}

#[cfg(any())]
fn is_key_file(path: &Path, key_path_opt: Option<&Path>) -> Result<bool> {
    // 首先检查是否是 .kitty_key 文件
    if let Some(ext) = path.extension() {
        if ext == DEFAULT_KEY_SUFFIX {
            return Ok(true);
        }
    }

    // 然后检查是否是指定的密钥文件（规范化路径匹配）
    if let Some(kp) = key_path_opt {
        let p = fs::canonicalize(path)
            .with_context(|| format!("Failed to canonicalize path: {}", path.display()))?;
        let k = fs::canonicalize(kp)
            .with_context(|| format!("Failed to canonicalize key_path: {}", kp.display()))?;
        return Ok(p == k);
    }

    Ok(false)
}

pub fn is_encrypted_file(path: &Path) -> bool {
    // 使用 to_string_lossy() 处理所有可能的文件名
    // 2025.12.21 .在几乎所有编码中字节都是一致的,这个判断方法可行
    path.file_name()
        .map(|n| n.to_string_lossy())
        .map_or(false, |name| name.ends_with(&format!(".{}", ENC_SUFFIX)))
}

pub fn canon_is_self(canon_path: &Path, canon_exe_path: &Path) -> Result<bool> {
    Ok(canon_path == canon_exe_path)
}

pub fn canon_is_key_file(canon_path: &Path, canon_key_path_opt: Option<&Path>) -> Result<bool> {
    // 首先检查是否是 .kitty_key 文件
    if let Some(ext) = canon_path.extension() {
        if ext == DEFAULT_KEY_SUFFIX {
            return Ok(true);
        }
    }

    // 然后检查是否是指定的密钥文件（规范化路径匹配）
    if let Some(canon_kp) = canon_key_path_opt {
        return Ok(canon_kp == canon_path);
    }

    Ok(false)
}

/// 验证文件不为空
pub fn verify_file_not_empty(path: &Path) -> Result<()> {
    let size = fs::metadata(path)
        .with_context(|| format!("Failed to verify file: {}", path.display()))?
        .len();
    
    if size == 0 {
        return Err(anyhow!("File is empty: {}", path.display()));
    }
    Ok(())
}

/// 读取文件用于验证
pub fn read_file_for_verification(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let mut data = Zeroizing::new(Vec::new());
    let mut file = File::open(path)
        .with_context(|| format!("Failed to open file for verification: {}", path.display()))?;
    file.try_lock_shared()
        .with_context(|| format!("Failed to lock file for verification: {}", path.display()))?;
    file.read_to_end(&mut data)
        .with_context(|| format!("Failed to read file for verification: {}", path.display()))?;
    file.unlock()
        .with_context(|| format!("Failed to unlock file during verification: {}", path.display()))?;
    Ok(data)
}

/// 判断文件是否是流式加密格式
pub fn is_streaming_encrypted_file(path: &Path) -> Result<bool> {
    let mut file = File::open(path)
        .with_context(|| format!("Failed to open file: {}", path.display()))?;
    file.try_lock_shared()
        .with_context(|| format!("Failed to lock file: {}", path.display()))?;

    // 读取前52字节：48字节nonce + 4字节加密类型标记
    let mut header = [0u8; 52];
    
    let result = match file.read_exact(&mut header) {
        Ok(_) => {
            // 分离nonce和加密类型标记
            let (_, enc_type_marker) = header.split_at(48); 
            // 如果加密类型标记是4字节0，则是普通加密
            // 否则是流式加密（流式加密在24字节nonce之后是块大小，不会是4字节0）
            Ok(enc_type_marker != [0u8; 4])
        }
        Err(_) => {
            // 读取失败，说明文件可能太短
            Err(anyhow!("Unable to determine whether the file is in streaming encrypted format."))
        }
    };

    file.unlock()
        .with_context(|| format!("Failed to unlock file: {}", path.display()))?;
    result
}

/// 通过把主nonce末8字节和计数器相加得到块nonce
/// 统一LE编码处理, 溢出还原为0
pub fn get_block_nonce_bytes(file_xnonce_bytes: &[u8], block_counter: u64) -> Result<[u8;24]>{
    if file_xnonce_bytes.len() != 24{
        return Err(anyhow!("计算块nonce失败, 输入的主nonce长度不符"));
    }
    let mut file_xnonce_bytes_8 = [0u8;8];
    file_xnonce_bytes_8.copy_from_slice(&file_xnonce_bytes[16..]);
    let final_counter = u64::from_le_bytes(file_xnonce_bytes_8).wrapping_add(block_counter);
    let final_counter_bytes: [u8; 8] = final_counter.to_le_bytes();
    // 复制主 nonce 的前 16 字节
    let mut block_nonce_bytes = [0u8; 24];
    block_nonce_bytes[..16].copy_from_slice(&file_xnonce_bytes[..16]);
    
    // 后 8 字节使用计数器的 LE 编码
    block_nonce_bytes[16..].copy_from_slice(&final_counter_bytes);
    Ok(block_nonce_bytes)
}