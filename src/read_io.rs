use anyhow::{anyhow, Result};
use zeroize::{Zeroize, Zeroizing};

use crate::*;

/// 安全地读取密码短语（交互式输入，不显示在屏幕上）
pub fn read_passphrase_interactive() -> Result<Zeroizing<String>> {
    // 第一次读取密码
    let mut passphrase: Zeroizing<String> = match read_password_utf8("Enter passphrase (input will be hidden)") {
        Ok(p) => p,
        Err(e) => {
            // 读取失败，没有密码需要清理
            return Err(e);
        }
    };
    
    // 如果第一次输入为空，给第二次确认机会
    if passphrase.is_empty() {
        match read_password_utf8("Empty passphrase entered. Press Enter again to confirm no passphrase, or enter a passphrase") {
            Ok(second_input) => {
                // 如果第二次输入非空，则使用第二次输入作为密码短语
                if !second_input.is_empty() {
                    passphrase = second_input;
                }
                // 如果第二次输入也为空，保持 passphrase 为空
            }
            Err(e) => {
                return Err(e);
            }
        }
    }
    
    // 如果密码非空，需要确认
    if !passphrase.is_empty() {
        // 确认密码短语
        let confirm: Zeroizing<String> = match read_password_utf8("Confirm passphrase") {
            Ok(c) => c,
            Err(e) => {
                return Err(e);
            }
        };
        
        if passphrase != confirm {
            return Err(anyhow::anyhow!("Passphrases do not match"));
        }
        
        // 返回主密码（调用者负责清理）
        return Ok(passphrase);
    }
    
    // 密码为空，直接返回（空字符串不需要特殊清理）
    Ok(passphrase)
}

/// 安全地读取密码短语一次（交互式输入，不显示在屏幕上）
pub fn read_passphrase_interactive_once() -> Result<Zeroizing<String>> {
    let passphrase: Zeroizing<String> = read_password_utf8("Enter passphrase (input will be hidden)")?;
    Ok(passphrase)
}

/// 安全地读取密码（交互式输入，不显示在屏幕上），一直读取直到输入非空
pub fn read_passwd_interactive() -> Result<Zeroizing<String>> {
    loop {
        // 读取密码
        let passwd: Zeroizing<String> = match read_password_utf8("Enter password (input will be hidden)") {
            Ok(p) => p,
            Err(e) => {
                // 读取失败，没有密码需要清理
                return Err(e);
            }
        };
        
        // 如果密码为空，提示并重新输入
        if passwd.is_empty() {
            my_println!("Password cannot be empty. Please try again.");
            continue;
        }
        
        // 确认密码
        let confirm: Zeroizing<String> = match read_password_utf8("Confirm password") {
            Ok(c) => c,
            Err(e) => {
                return Err(e);
            }
        };
        
        if passwd != confirm {
            return Err(anyhow::anyhow!("Passphrases do not match"));
            // my_println!("Passwords do not match. Please try again.");
            // continue;
        }
        
        // 返回密码（调用者负责清理）
        return Ok(passwd);
    }
}

/// 安全地读取密码一次（交互式输入，不显示在屏幕上）
pub fn read_passwd_interactive_once() -> Result<Zeroizing<String>> {
    loop {
        let passwd: Zeroizing<String> = read_password_utf8("Enter password (input will be hidden)")?;
        
        // 如果密码为空，提示并重新输入
        if passwd.is_empty() {
            my_println!("Password cannot be empty. Please try again.");
            continue;
        }
        
        return Ok(passwd);
    }
}

/// 读取密码并正确处理 UTF-8 编码（使用 dialoguer 库）
fn read_password_utf8(prompt:&str) -> Result<Zeroizing<String>> {
    let result: Zeroizing<String> = Zeroizing::new(dialoguer::Password::new()
        .with_prompt(prompt)
        .allow_empty_password(true)
        .interact()
        .map_err(|e| anyhow::anyhow!("Failed to read password: {}", e))?);
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

