use anyhow::{anyhow, Context, Result};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use walkdir::DirEntry;
use ignore::DirEntry as ignore_DirEntry;

/// 规范化路径，移除 . 和 .. 组件
pub fn normalize_path(path: &Path) -> PathBuf {
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
        PathBuf::from(".")
    } else {
        normalized
    }
}

pub fn filter_entry(e: &DirEntry) -> bool {
    // 跳过 . 开头的文件和文件夹
    match e.file_name().to_str() {
        Some(name) => {
            // 过滤以点开头的目录（如 .git, .vscode 等）
            if name.starts_with('.') {
                return false;
            }
        }
        None => {
            // 如果文件名无法转换为字符串，可能是编码问题
            // 我们选择不过滤它，继续处理
        }
    }
    true
}

pub fn ignore_filter_entry(e: &ignore_DirEntry) -> bool {
    // 跳过 . 开头的文件和文件夹
    match e.file_name().to_str() {
        Some(name) => {
            // 过滤以点开头的目录（如 .git, .vscode 等）
            if name.starts_with('.') {
                return false;
            }
        }
        None => {
            // 如果文件名无法转换为字符串，可能是编码问题
            // 我们选择不过滤它，继续处理
        }
    }
    true
}

pub fn is_self(path: &Path, exe_path: &Path) -> Result<bool> {
    let p = fs::canonicalize(path)
        .with_context(|| format!("Failed to canonicalize path: {}", path.display()))?;

    let e = fs::canonicalize(exe_path)
        .with_context(|| format!("Failed to canonicalize exe_path: {}", exe_path.display()))?;

    Ok(p == e)
}

pub fn is_key_file(path: &Path, key_path_opt: Option<&Path>) -> Result<bool> {
    // 首先检查是否是 .kitty_key 文件
    if let Some(ext) = path.extension() {
        if ext == "kitty_key" {
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
    path.file_name()
        .map(|n| n.to_string_lossy())
        .map_or(false, |name| name.ends_with(".kitty_enc"))
}

pub fn canon_is_self(canon_path: &Path, canon_exe_path: &Path) -> Result<bool> {
    Ok(canon_path == canon_exe_path)
}

pub fn canon_is_key_file(canon_path: &Path, canon_key_path_opt: Option<&Path>) -> Result<bool> {
    // 首先检查是否是 .kitty_key 文件
    if let Some(ext) = canon_path.extension() {
        if ext == "kitty_key" {
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
pub fn read_file_for_verification(path: &Path) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    File::open(path)
        .with_context(|| format!("Failed to open file for verification: {}", path.display()))?
        .read_to_end(&mut data)
        .with_context(|| format!("Failed to read file: {}", path.display()))?;
    Ok(data)
}

/// 判断文件是否是流式加密格式
pub fn is_streaming_encrypted_file(path: &Path) -> Result<bool> {
    use std::io::Read;
    
    // 打开文件
    let mut file = File::open(path)
        .with_context(|| format!("Failed to open file: {}", path.display()))?;
    
    // 读取前28字节：24字节nonce + 4字节加密类型标记
    let mut header = [0u8; 28];
    
    match file.read_exact(&mut header) {
        Ok(_) => {
            // 分离nonce和加密类型标记
            let (_, enc_type_marker) = header.split_at(24);
            
            // 如果加密类型标记是4字节0，则是普通加密
            // 否则是流式加密（流式加密在24字节nonce之后是块大小，不会是4字节0）
            Ok(enc_type_marker != [0u8; 4])
        }
        Err(_) => {
            // 读取失败，说明文件可能太短
            Err(anyhow!("Unable to determine whether the file is in streaming encrypted format."))
        }
    }
}
