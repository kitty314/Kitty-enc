// #![allow(unused)]
use std::{fs::{self, File}, io::{self, Read, Seek, Write}, path::PathBuf};
use anyhow::{Context, Result, anyhow};
use rayon::prelude::*;

use crate::*;

pub fn base_encode_file(path: &PathBuf, base256mode_code: u32) -> Result<()> {
    // 创建输出文件路径
    let mut out_path = PathBuf::from(path);
    if let Some(orig_ext) = path.extension() {
        let mut s = orig_ext.to_os_string();
        s.push(format!(".{}", BASE_ENCODE_FILE_SUFFIX));
        out_path.set_extension(s);
    } else {
        out_path.set_extension(BASE_ENCODE_FILE_SUFFIX);
    };

    // 检查目标文件是否已经存在，存在则跳过
    if out_path.try_exists()? {
        return Err(anyhow!("Warning: Target file {} already exists", out_path.display()));
    }
    // 打开源文件
    let mut source_file = File::open(path)
        .with_context(|| format!("Failed to open file for base256 encoding: {}", path.display()))?;
    source_file.try_lock_shared()
        .with_context(|| format!("Failed to lock file for base256 encoding: {}", path.display()))?;

    // 检查文件大小
    let metadata = source_file.metadata()
        .with_context(|| format!("Failed to get metadata: {}", path.display()))?;
    if metadata.len() > BASE_MAX_SIZE {
        return Err(anyhow!("File too large (>1GB): {}", path.display()));
    }

    // 缓冲区大小：4MB
    let mut buffer: Vec<u8> = vec![0u8; BASE_BUFFER_SIZE];
    let encoder = MyBase256::new(base256mode_code);
    // 创建输出文件
    let mut out_file = File::create_new(&out_path)
        .with_context(|| format!("Failed to create file: {}", out_path.display()))?;
    if let Err(e) = out_file.try_lock() {
        fs::remove_file(&out_path).ok();
        return Err(e).with_context(|| format!("Failed to lock file: {}", out_path.display()))
    }
    my_println!("开始编码: {}", path.display());
    // 流式读取、编码、写入
    let loop_result = (||-> Result<()> {
        loop {
            // 检查中断标志
            if crate::cli::is_interrupted() {
                return Err(anyhow!("Interrupt signal received, stopping encoding of {}", path.display()));
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

            // 切分成 512KB 块并行处理 
            let encoded_chunks: Vec<String> = buffer[..bytes_read] 
                .par_chunks(BASE_CHUNK_SIZE) 
                .map(|chunk| {
                    encoder.encode(chunk)
                }).collect(); 
            // 按顺序写入文件 
            for encoded in encoded_chunks { 
                out_file.write_all(encoded.as_bytes())?; 
            }
        }
        Ok(())
    })();
    match loop_result {
        Ok(()) => {}
        Err(e) => {
            fs::remove_file(&out_path).ok();
            return Err(e);
        }   
    };

    // 解锁源文件
    if let Err(e) = source_file.unlock() {
        fs::remove_file(&out_path).ok();
        return Err(e).with_context(|| format!("Failed to unlock source file: {}", path.display()))
    }
    // 确保所有数据都写入磁盘
    if let Err(e) = out_file.flush() {
        // 清理已创建的文件
        fs::remove_file(&out_path).ok();
        return Err(e).with_context(|| format!("Failed to flush file: {}", out_path.display()));
    }
    // 解锁文件
    if let Err(e) = out_file.unlock() {
        fs::remove_file(&out_path).ok();
        return Err(e).with_context(|| format!("Failed to unlock file: {}", out_path.display()))
    }
    my_println!("编码完成: {}", path.display());    
    Ok(())
}

pub fn base_decode_file(path: &PathBuf, base256mode_code: u32) -> Result<()>{
    // 检查是否以 .txt 结尾
    if let Some(orig_ext) = path.extension() {
        if orig_ext == BASE_ENCODE_FILE_SUFFIX{
            // pass
        } else {
            return Err(anyhow!("File does not end with .{}: {}", BASE_ENCODE_FILE_SUFFIX, path.display()));
        }
    } else {
            return Err(anyhow!("Cannot get file extension: {}", path.display()));
    };

    let mut out_path = PathBuf::from(path);
    out_path.set_extension("");

    // 检查解码后的文件是否已经存在，存在则跳过
    if out_path.try_exists()? {
        return Err(anyhow!("Warning: Target file {} already exists", out_path.display()));
    }

    // 打开文件
    let mut file = File::open(path)
        .with_context(|| format!("Failed to open file for base256 decoding: {}", path.display()))?;
    file.try_lock_shared()
        .with_context(|| format!("Failed to lock file for base256 decoding: {}", path.display()))?;
    
    // 创建输出文件
    let mut out_file = File::create_new(&out_path)
        .with_context(|| format!("Failed to create file: {}", out_path.display()))?;
    if let Err(e) = out_file.try_lock(){
        fs::remove_file(&out_path).ok();
        return Err(e).with_context(|| format!("Failed to lock file: {}", out_path.display()))
    }
    let encoder = MyBase256::new(base256mode_code);
    let mut encode_buf: Vec<u8> = Vec::with_capacity(BASE_BUFFER_SIZE * 3 + 4);
    my_println!("开始解码: {}", path.display());
    // 流式读取、解码、写入
    let loop_result= (||-> Result<()> {
        loop {
            // 检查中断标志
            if crate::cli::is_interrupted() {
                return Err(anyhow!("Interrupt signal received, stopping encoding of {}", path.display()));
            }

            encode_buf.resize(BASE_BUFFER_SIZE * 3, 0u8);
            let bytes_read = file.read(&mut encode_buf).with_context(||format!("Failed to read file: {}", path.display()))?;
            if bytes_read == 0 {
                break;
            }
            encode_buf.truncate(bytes_read); // 不会改变容量
            encode_buf = try_read_to_string_raw(&mut file, encode_buf)?;

            // 切分成块并行处理 
            let decoded_chunks: Vec<Result<Vec<u8>, anyhow::Error>> = 
                split_to_str_chunks_raw(&encode_buf, BASE_CHUNK_SIZE * 3)
                    .par_iter()
                    .map(|c|{
                        let s = str::from_utf8(c).with_context(||format!("转换为字符串失败"))?;
                        encoder.try_decode(s.trim())
                    }).collect();


            // 按顺序写入文件 
            for decoded in decoded_chunks { 
                out_file.write_all(&decoded?)?; 
            }
        }
        Ok(())
    })();
    match loop_result {
        Ok(()) => {}
        Err(e) => {
            fs::remove_file(&out_path).ok();
            return Err(e);
        }  
    };
    if let Err(e) = file.unlock(){
        fs::remove_file(&out_path).ok();
        return Err(e).with_context(|| format!("Failed to unlock file: {}", path.display()));
    }

    // 确保所有数据都写入磁盘
    if let Err(e) = out_file.flush() {
        fs::remove_file(&out_path).ok();
        return Err(e).with_context(|| format!("Failed to flush file: {}", out_path.display()));
    };
    if let Err(e) = out_file.unlock(){
        fs::remove_file(&out_path).ok();
        return Err(e).with_context(|| format!("Failed to unlock file: {}", out_path.display()));
    }
    my_println!("解码完成: {}", path.display());
    Ok(())
}

#[cfg(any())]
/// 尝试从文件读取至多4字节内容来补齐缓冲区，并转换为字符串，事实上最多只会填充3字节
fn try_read_to_string(file: &mut File, mut encode_buf: Vec<u8>) -> Result<String> {
    if encode_buf.is_empty() {
        return Err(anyhow!("不可能出现的错误: 尝试转换为字符串的缓冲区为空"));
    }
    // 最多尝试补齐 4 个字节
    let mut bytes = [0u8; 4];
    let n = file.read(&mut bytes)?;
    if n == 4 {
        for i in 0..n {
            if is_utf8_char_boundary(bytes[i]) {
                file.seek(io::SeekFrom::Current(-((n-i) as i64)))?;
                break;
            } 
            if i < n - 1 {
                encode_buf.push(bytes[i]);
            } else {
                return Err(anyhow!("尝试转换为字符串失败: 无法补齐合法字符"));
            }
        }
    } else {
        encode_buf.extend_from_slice(&bytes[..n]);
    }
    // 尝试转换为 String
    let s = String::from_utf8(encode_buf)?;
    Ok(s)
}

/// 尝试从文件读取至多4字节内容来补齐缓冲区，不转换为字符串，事实上最多只会填充3字节
fn try_read_to_string_raw(file: &mut File, mut encode_buf: Vec<u8>) -> Result<Vec<u8>> {
    if encode_buf.is_empty() {
        return Err(anyhow!("不可能出现的错误: 尝试转换为字符串的缓冲区为空"));
    }
    // 最多尝试补齐 4 个字节
    let mut bytes = [0u8; 4];
    let n = file.read(&mut bytes)?;
    if n == 4 {
        for i in 0..n {
            if is_utf8_char_boundary(bytes[i]) {
                file.seek(io::SeekFrom::Current(-((n-i) as i64)))?;
                break;
            } 
            if i < n - 1 {
                encode_buf.push(bytes[i]);
            } else {
                return Err(anyhow!("尝试转换为字符串失败: 无法补齐合法字符"));
            }
        }
    } else {
        encode_buf.extend_from_slice(&bytes[..n]);
    }
    Ok(encode_buf)
}

#[cfg(any())]
fn split_to_str_chunks(s: &str, chunk_size: usize) -> Vec<&str> {
    let mut chunks = Vec::with_capacity(BASE_BUFFER_SIZE/BASE_CHUNK_SIZE+1);
    let mut start = 0;

    while start < s.len() {
        // 先尝试直接跳 chunk_size 个字节
        let mut end = (start + chunk_size).min(s.len());

        // 调整到合法的 UTF-8 边界
        while end < s.len() && !s.is_char_boundary(end) {
            end += 1;
        }

        chunks.push(&s[start..end]);
        start = end;
    }
    chunks
}

fn split_to_str_chunks_raw(s: &[u8], chunk_size: usize) -> Vec<&[u8]> {
    let mut chunks = Vec::with_capacity(BASE_BUFFER_SIZE/BASE_CHUNK_SIZE+1);
    let mut start = 0;

    while start < s.len() {
        // 先尝试直接跳 chunk_size 个字节
        let mut end = (start + chunk_size).min(s.len());

        // 调整到合法的 UTF-8 边界
        while end < s.len() && !is_utf8_char_boundary(s[end]) {
            end += 1;
        }

        chunks.push(&s[start..end]);
        start = end;
    }
    chunks
}

fn is_utf8_char_boundary(byte: u8) -> bool {
    // This is bit magic equivalent to: b < 128 || b >= 192
    (byte as i8) >= -0x40
}

fn base_read_editor() -> Result<String> {
    my_println!("输入你要处理的消息，注意编码不是加密，输入内容不受保护");   
    loop{
        check_is_interrupted_to_err()?;
        let result= dialoguer::Editor::new()
            .extension(".tmp")
            .require_save(true)
            .trim_newlines(true)
            .edit("")
            .map_err(|e| anyhow::anyhow!("Failed to read message: {}", e))?
            .unwrap_or("".to_string());
        // 检查中断标志
        check_is_interrupted_to_err()?;
        if result.is_empty() {
            my_println!("Message cannot be empty. Please try again.");
            if ask_continue_or_not()? {continue;}
            else {return Err(anyhow!("User interrupted. Goodbye."));}
        }
        return Ok(result);
    }
}

fn base_read_terminal() -> Result<String> {
    my_println!("输入你要处理的消息，注意编码不是加密，输入内容不受保护");   
    loop{
        check_is_interrupted_to_err()?;
        let result: String = dialoguer::Input::new()
            .allow_empty(true)
            .with_prompt("输入消息(不能为空, 不能包含换行)")
            .interact()
            .map_err(|e| anyhow::anyhow!("Failed to read message: {}", e))?;
        // 检查中断标志
        check_is_interrupted_to_err()?;
        if result.is_empty() {
            my_println!("Message cannot be empty. Please try again.");
            continue;
        }
        return Ok(result);
    }
}

pub fn base_encode_interactive(base256mode_code: u32, use_editor: bool) -> Result<()> {
    let s = if use_editor{ base_read_editor()?} else {base_read_terminal()?};
    let encoder = MyBase256::new(base256mode_code);
    let encoded = encoder.encode(s.as_bytes());
    my_println!("编码结果:\n{}",encoded);
    Ok(())
}

pub fn base_decode_interactive(base256mode_code: u32, use_editor: bool) -> Result<()> {
    let s = if use_editor{ base_read_editor()?} else {base_read_terminal()?};
    let encoder = MyBase256::new(base256mode_code);
    let decoded = encoder.try_decode(s.trim())?;
    let decode_s = str::from_utf8(&decoded)
        .with_context(||format!("解码结果不是合法UTF-8字符串"))?;
    my_println!("解码结果:\n{}",decode_s);
    Ok(())
}