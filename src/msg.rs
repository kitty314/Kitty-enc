use std::{fs::File, io::Read, path::PathBuf};
use rand::{TryRngCore, rngs::OsRng};
use zeroize::{Zeroize, Zeroizing};
use anyhow::{Context, Result, anyhow};

use crate::*;

/// 交互式获取需要加密的消息
pub fn msg_read_enc_interactive() -> Result<Zeroizing<String>> {
    my_println!("输入你要加密的消息, 注意屏幕不会显示");
    my_println!("你只有一次机会, 如果输错请使用Ctrl + C退出");  
    loop{
        let result: Zeroizing<String> = msg_read_terminal_passwd("输入消息(不能为空, 不能包含换行)")?;
        if result.is_empty() {
            my_println!("Message cannot be empty. Please try again.");
            continue;
        }
        return Ok(result);
    }
}

/// 从文件读取需要加密的消息
pub fn msg_read_enc_from_file(path: &PathBuf) -> Result<Zeroizing<String>> {
    // 打开文件
    let mut file = File::open(path)
        .with_context(|| format!("Failed to open file: {}", path.display()))?;

    // 检查文件大小
    let metadata = file.metadata()
        .with_context(|| format!("Failed to get metadata: {}", path.display()))?;
    if metadata.len() > MSG_FILE_MAX_SIZE {
        return Err(anyhow!("File too large (>50KB): {}", path.display()));
    }

    // 尝试加锁
    file.try_lock_shared()
        .with_context(|| format!("Failed to lock file: {}", path.display()))?;

    let mut msg: Zeroizing<String> = Zeroizing::new(String::new());
    file.read_to_string(&mut msg)
        .with_context(|| format!("Failed to read file: {}", path.display()))?;

    // 解锁
    file.unlock()
        .with_context(|| format!("Failed to unlock file: {}", path.display()))?;

    // 校验内容
    if msg.trim().is_empty() {
        return Err(anyhow!("File content cannot be empty"));
    }

    Ok(msg)
}

/// 获取需要解密的消息
pub fn msg_read_dec_interactive(use_editor: bool) -> Result<Zeroizing<String>> {
    if use_editor {msg_read_dec_editor()} else {msg_read_dec_terminal()}
}

/// 生成随机 MASTER_KEY_LENGTH 字节密钥
pub fn msg_generate_random_key() -> Result<Zeroizing<[u8; MASTER_KEY_LENGTH]>> {
    let mut key: Zeroizing<[u8; MASTER_KEY_LENGTH]> = Zeroizing::new([0u8; MASTER_KEY_LENGTH]);
    if let Err(e) = OsRng.try_fill_bytes(key.as_mut()) {
        return Err(e).context("Failed to generate random key");
    }
    Ok(key)
}

/// 交互式读取Base64编码的密钥, 并转换为Zeroizing<[u8; MASTER_KEY_LENGTH]>
pub fn msg_load_key(base256mode_code: u32) -> Result<Zeroizing<[u8; MASTER_KEY_LENGTH]>> {
    // 提示用户输入
    let mut input: Zeroizing<String>;
    loop{
        input = msg_read_terminal_passwd("请输入密钥")?;
        if input.is_empty() {
            my_println!("Key cannot be empty. Please try again.");
            continue;
        }
        break;
    }

    // Base64 解码
    let decoded: Zeroizing<Vec<u8>> = Zeroizing::new(MyBase256::new(base256mode_code)
        .decode(input.trim()));
        // .map_err(|e| anyhow!("Base64解码失败: {}", e))?);

    // 检查长度是否为 MASTER_KEY_LENGTH 字节
    if decoded.len() != MASTER_KEY_LENGTH {
        return Err(anyhow!(
            "密钥长度错误: 解码后为 {} 字节, 需要 {} 字节",
            decoded.len(), MASTER_KEY_LENGTH
        ));
    }

    // 转换为 Zeroizing<[u8; MASTER_KEY_LENGTH]>
    let mut key: Zeroizing<[u8; MASTER_KEY_LENGTH]> = Zeroizing::new([0u8; MASTER_KEY_LENGTH]);
    key.copy_from_slice(&decoded);
    Ok(key)
}

/// 加密消息
pub fn msg_encrypt(msg: Zeroizing<String>, master_key: &[u8;MASTER_KEY_LENGTH], random_key: bool, base256mode_code: u32) -> Result<i32> {
    let mut xnonce_bytes = [0u8; 24];
    if let Err(e) = OsRng.try_fill_bytes(&mut xnonce_bytes) {
        return Err(e).context("Failed to generate random nonce for message encryption");
    }
    let xnonce = MyXnonce::try_from_slice(&xnonce_bytes)?;
    // 盐派生子密钥 
    let subkey: Zeroizing<[u8; 32]> = match derive_subkey_simple(master_key, &xnonce_bytes) {
        Ok(subkey) => subkey, // 保护数据
        Err(e) => {
            return Err(e);
        }
    };
    let cipher = MyCipher::new(subkey.as_ref())?;
    let mut ct: Zeroizing<Vec<u8>> = match cipher.encrypt(&xnonce, msg.as_ref()) {
        Ok(ct) => ct,
        Err(_) => {
            return Err(anyhow!("Encryption failed for message"));
        }
    };

    let mut ct_msg: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(xnonce_bytes.len()+ct.len()));
    ct_msg.extend_from_slice(&xnonce_bytes);
    ct_msg.append(ct.as_mut());

    let ct_msg_base64: Zeroizing<String> = Zeroizing::new(MyBase256::new(base256mode_code).encode(&ct_msg));
    my_println!("加密结果:\n{}\n", ct_msg_base64.as_str());

    if random_key {
        let key_base64: Zeroizing<String> = Zeroizing::new(MyBase256::new(base256mode_code).encode(master_key));
        my_println!("随机密钥:\n{}\n", key_base64.as_str());
    }
    Ok(0)
}

/// 解密消息
pub fn msg_decrypt(ct_msg_base64: Zeroizing<String>, master_key: &[u8; MASTER_KEY_LENGTH], base256mode_code: u32) -> Result<i32> {
    // Base64 解码
    let ct_msg: Zeroizing<Vec<u8>> = Zeroizing::new(MyBase256::new(base256mode_code)
        .decode(ct_msg_base64.trim()));
        // .map_err(|e| anyhow!("Base64解码失败: {}", e))?);

    if ct_msg.len() <= 24 {
        return Err(anyhow!("解密失败"));
    }

    // 拆分 nonce 和 ciphertext
    let (xnonce_bytes, ciphertext) = ct_msg.split_at(24);
    let xnonce = MyXnonce::try_from_slice(xnonce_bytes)?;

    // 派生子密钥
    let subkey: Zeroizing<[u8; 32]> =
        derive_subkey_simple(master_key, xnonce_bytes).context("子密钥派生失败")?;

    // 初始化 Cipher 并解密
    let cipher = MyCipher::new(subkey.as_ref()).context("Cipher 初始化失败")?;
    let plaintext_bytes: Zeroizing<Vec<u8>> =
        cipher.decrypt(&xnonce, ciphertext).context("解密失败")?;

    // 转换为 UTF-8 字符串
    let plaintext = str::from_utf8(&plaintext_bytes)
        .map_err(|_| anyhow!("解密结果不是有效的 UTF-8 字符串"))?;
    my_println!("解密结果:\n{}", plaintext);
    Ok(0)
}

/// 直接终端读取需要解密的消息
fn msg_read_dec_terminal() -> Result<Zeroizing<String>> {
    my_println!("输入你要解密的消息，注意输入内容不受保护");
    my_println!("一般复制粘贴即可, 如果输错可以用Ctrl + C退出");    
    loop{
        let result: Zeroizing<String> = msg_read_terminal_normal("输入消息(不能为空, 不能包含换行)")?;
        if result.is_empty() {
            my_println!("Message cannot be empty. Please try again.");
            continue;
        }
        return Ok(result);
    }
}

/// 使用编辑器获取需要解密的消息
fn msg_read_dec_editor() -> Result<Zeroizing<String>> {
    my_println!("输入你要解密的消息，注意输入内容不受保护");
    loop{
        let result: Zeroizing<String> = msg_read_editor()?;
        if result.is_empty() {
            my_println!("Message cannot be empty. Please try again.");
            if ask_continue_or_not()? {continue;}
            else {return Err(anyhow!("User interrupted. Goodbye."));}
        }
        return Ok(result);
    }
}

/// 直接终端读取信息(基础函数,密码模式)
fn msg_read_terminal_passwd(prompt:&str) -> Result<Zeroizing<String>> {
    // 检查中断标志，前后都应该有一次, 但是一般循环速度很快，前置的检查用户来不及中断
    check_is_interrupted_to_err()?;
    let result: Zeroizing<String> = Zeroizing::new(dialoguer::Password::new()
        .with_prompt(prompt)
        .allow_empty_password(true)
        .interact()
        .map_err(|e| anyhow::anyhow!("读取输入失败: {}", e))?);
    // 检查中断标志
    if crate::cli::is_interrupted() {
        let mut passwd: Zeroizing<String> = result;
        {
            my_println!("Cleaning up what you've typed...");
            passwd.zeroize();
        }
        my_println!("The program may report some errors, but don't worry.");
        return Err(anyhow!("User interrupted. Goodbye."));
    }
    Ok(result)
}

/// 使用编辑器读取信息(基础函数)
fn msg_read_editor() -> Result<Zeroizing<String>> {
    check_is_interrupted_to_err()?;
    let result: Zeroizing<String> = Zeroizing::new(dialoguer::Editor::new()
        .extension(".tmp")
        .require_save(true)
        .trim_newlines(true)
        .edit("")
        .map_err(|e| anyhow::anyhow!("读取输入失败: {}", e))?
        .unwrap_or("".to_string())
    );
    // 检查中断标志
    if crate::cli::is_interrupted() {
        let mut input: Zeroizing<String> = result;
        {
            my_println!("Cleaning up what you've typed...");
            input.zeroize();
        }
        my_println!("The program may report some errors, but don't worry.");
        return Err(anyhow!("User interrupted. Goodbye."));
    }
    Ok(result)
}

/// 直接终端读取信息(基础函数,普通模式)
fn msg_read_terminal_normal(prompt:&str) -> Result<Zeroizing<String>> {
    // 检查中断标志，前后都应该有一次, 但是一般循环速度很快，前置的检查用户来不及中断
    check_is_interrupted_to_err()?;
    let result: Zeroizing<String> = Zeroizing::new(dialoguer::Input::new()
        .with_prompt(prompt)
        .allow_empty(true)
        .interact()
        .map_err(|e| anyhow::anyhow!("读取输入失败: {}", e))?);
    // 检查中断标志
    if crate::cli::is_interrupted() {
        let mut passwd: Zeroizing<String> = result;
        {
            my_println!("Cleaning up what you've typed...");
            passwd.zeroize();
        }
        my_println!("The program may report some errors, but don't worry.");
        return Err(anyhow!("User interrupted. Goodbye."));
    }
    Ok(result)
}
