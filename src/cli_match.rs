use anyhow::{Context, Result, anyhow};
use std::path::PathBuf;
use zeroize::Zeroizing;
use libsodium_rs::utils::{mlock, munlock};

use crate::*;

pub fn cli_match_main(cli: &Cli, exe_path: &PathBuf,run_dir: &PathBuf) -> Result<()> {   
    // Determine operation mode
    match (&cli.mode, &cli.src_dir, &cli.dec_dir, &cli.fix_dir, &cli.key_file, &cli.any_file, &cli.passwd) {
        // No subcommand, no -s/-d: auto encrypt current dir, generate key if none
        (None, None, None, None, key_opt, None, false) => {
            let (key_path,passphrase_opt) = get_or_create_key_path(&run_dir, key_opt, "current")?;
            let mut key: Zeroizing<[u8; 32]> = load_key(&key_path,passphrase_opt)?;
            mlock(key.as_mut()).context("锁定主密钥失败")?;
            process_encrypt_dir(&run_dir, &key, Some(&key_path), &exe_path)?;
            munlock(key.as_mut()).context("解锁主密钥失败")?;
            my_println!("Encryption completed for {}", run_dir.display());
            Ok(())
        }

        // Explicit encrypt: -s dir (key optional -> generate in cwd if missing)
        (Some(Mode::Encrypt { src_dir: Some(src_dir), key_file: key_opt }), None, None, None, None, None,false) 
        | (None, Some(src_dir), None, None, key_opt, None, false) => {
            let (key_path,passphrase_opt) = get_or_create_key_path(src_dir, key_opt, "source")?;
            let mut key: Zeroizing<[u8; 32]> = load_key(&key_path,passphrase_opt)?;
            mlock(key.as_mut()).context("锁定主密钥失败")?;
            process_encrypt_dir(src_dir, &key, Some(&key_path), &exe_path)?;
            munlock(key.as_mut()).context("解锁主密钥失败")?;
            my_println!("Encryption completed for {}", src_dir.display());
            Ok(())
        }

        // Explicit decrypt: -d dir (key optional -> search in decryption directory)
        (Some(Mode::Decrypt { dec_dir: Some(dec_dir), key_file: key_opt }), None, None, None, None, None,false) 
        | (None, None, Some(dec_dir), None, key_opt, None, false) => {
            let (key_path,passphrase_opt) = get_or_create_key_path(dec_dir, key_opt, "decryption")?;
            let mut key: Zeroizing<[u8; 32]> = load_key(&key_path,passphrase_opt)?;
            mlock(key.as_mut()).context("锁定主密钥失败")?;
            process_decrypt_dir(dec_dir, &key, &exe_path, Some(&key_path))?;
            munlock(key.as_mut()).context("解锁主密钥失败")?;
            my_println!("Decryption completed for {}", dec_dir.display());
            Ok(())
        }

        // Fix mode: -f dir (key optional -> search in fix directory)
        (None, None, None, Some(fix_dir), key_opt, None, false) => {
            let (key_path,passphrase_opt) = get_or_create_key_path(fix_dir, key_opt, "fix")?;
            let mut key: Zeroizing<[u8; 32]> = load_key(&key_path,passphrase_opt)?;
            mlock(key.as_mut()).context("锁定主密钥失败")?;
            process_fix_dir(fix_dir, &key, &exe_path, Some(&key_path))?;
            munlock(key.as_mut()).context("解锁主密钥失败")?;
            my_println!("Fix completed for {}", fix_dir.display());
            Ok(())
        }

        // 任意文件模式：加密当前目录
        (None, None, None, None, None, Some(any_file), &use_passwd) => {
            let need_confirm = use_passwd; // 加密时需要确认密码
            let mut key: Zeroizing<[u8; 32]> = derive_key_from_any_file(any_file, use_passwd, need_confirm)?;
            mlock(key.as_mut()).context("锁定主密钥失败")?;
            process_encrypt_dir(&run_dir, &key, Some(any_file), &exe_path)?;
            munlock(key.as_mut()).context("解锁主密钥失败")?;
            let mode_str = if use_passwd { "any-file mode with password" } else { "any-file mode, no password" };
            my_println!("Encryption completed for {} ({})", run_dir.display(), mode_str);
            Ok(())
        }

        // 任意文件模式：加密指定目录
        (None, Some(src_dir), None, None, None, Some(any_file), &use_passwd) => {
            let need_confirm = use_passwd; // 加密时需要确认密码
            let mut key: Zeroizing<[u8; 32]> = derive_key_from_any_file(any_file, use_passwd, need_confirm)?;
            mlock(key.as_mut()).context("锁定主密钥失败")?;
            process_encrypt_dir(src_dir, &key, Some(any_file), &exe_path)?;
            munlock(key.as_mut()).context("解锁主密钥失败")?;
            let mode_str = if use_passwd { "any-file mode with password" } else { "any-file mode, no password" };
            my_println!("Encryption completed for {} ({})", src_dir.display(), mode_str);
            Ok(())
        }

        // 任意文件模式：解密指定目录
        (None, None, Some(dec_dir), None, None, Some(any_file), &use_passwd) => {
            let need_confirm = false; // 解密时不需要确认密码
            let mut key: Zeroizing<[u8; 32]> = derive_key_from_any_file(any_file, use_passwd, need_confirm)?;
            mlock(key.as_mut()).context("锁定主密钥失败")?;
            process_decrypt_dir(dec_dir, &key, &exe_path, Some(any_file))?;
            munlock(key.as_mut()).context("解锁主密钥失败")?;
            let mode_str = if use_passwd { "any-file mode with password" } else { "any-file mode, no password" };
            my_println!("Decryption completed for {} ({})", dec_dir.display(), mode_str);
            Ok(())
        }

        // 任意文件模式：修复指定目录
        (None, None, None, Some(fix_dir), None, Some(any_file), &use_passwd) => {
            let need_confirm = false; // 修复时不需要确认密码
            let mut key: Zeroizing<[u8; 32]> = derive_key_from_any_file(any_file, use_passwd, need_confirm)?;
            mlock(key.as_mut()).context("锁定主密钥失败")?;
            process_fix_dir(fix_dir, &key, &exe_path, Some(any_file))?;
            munlock(key.as_mut()).context("解锁主密钥失败")?;
            let mode_str = if use_passwd { "any-file mode with password" } else { "any-file mode, no password" };
            my_println!("Fix completed for {} ({})", fix_dir.display(), mode_str);
            Ok(())
        }

        // 纯密码模式：加密当前目录
        (None, None, None, None, None, None, true) => {
            let passwd: Zeroizing<String> = read_passwd_interactive()?;
            let mut key: Zeroizing<[u8; 32]> = derive_key_from_password(passwd)?;
            mlock(key.as_mut()).context("锁定主密钥失败")?;
            process_encrypt_dir(&run_dir, &key, None, &exe_path)?;
            munlock(key.as_mut()).context("解锁主密钥失败")?;
            my_println!("Encryption completed for {} (password-only mode)", run_dir.display());
            Ok(())
        }

        // 纯密码模式：加密指定目录
        (None, Some(src_dir), None, None, None, None, true) => {
            let passwd: Zeroizing<String> = read_passwd_interactive()?;
            let mut key: Zeroizing<[u8; 32]> = derive_key_from_password(passwd)?;
            mlock(key.as_mut()).context("锁定主密钥失败")?;
            process_encrypt_dir(src_dir, &key, None, &exe_path)?;
            munlock(key.as_mut()).context("解锁主密钥失败")?;
            my_println!("Encryption completed for {} (password-only mode)", src_dir.display());
            Ok(())
        }

        // 纯密码模式：解密指定目录
        (None, None, Some(dec_dir), None, None, None, true) => {
            let passwd: Zeroizing<String> = read_passwd_interactive_once()?;
            let mut key: Zeroizing<[u8; 32]> = derive_key_from_password(passwd)?;
            mlock(key.as_mut()).context("锁定主密钥失败")?;
            process_decrypt_dir(dec_dir, &key, &exe_path, None)?;
            munlock(key.as_mut()).context("解锁主密钥失败")?;
            my_println!("Decryption completed for {} (password-only mode)", dec_dir.display());
            Ok(())
        }

        // 纯密码模式：修复指定目录
        (None, None, None, Some(fix_dir), None, None, true) => {
            let passwd: Zeroizing<String> = read_passwd_interactive_once()?;
            let mut key: Zeroizing<[u8; 32]> = derive_key_from_password(passwd)?;
            mlock(key.as_mut()).context("锁定主密钥失败")?;
            process_fix_dir(fix_dir, &key, &exe_path, None)?;
            munlock(key.as_mut()).context("解锁主密钥失败")?;
            my_println!("Fix completed for {} (password-only mode)", fix_dir.display());
            Ok(())
        }

        _ => {
            print_help();
            Ok(())
        }
    }
}

pub fn cli_match_msg(cli: &Cli) -> Result<()> {
    if let Some(Mode::Msg { src_dir, dec, key_file, any_file, passwd, base256mode_code}) = &cli.mode{
        my_println!("您正在使用消息加密模式，该模式不适合用于高度安全的加密传输消息，除非拥有极度安全的通道用于密钥传输，否则消息的安全性几乎等于密钥传输的安全性");
        my_println!("如果对于点对点加密传输有极高的安全性需求，你应该寻找支持非对称加密，密钥交换，随机数交换等功能的软件");
        let base256mode = match base256mode_code {
            0 => Base256Mode::YiSyllable,
            1 => Base256Mode::CjkIdeograph,
            2 => Base256Mode::MiscellaneousSymbols,
            _ => Base256Mode::YiSyllable,
        };

        match (src_dir, dec, key_file, any_file, passwd) {
            // 随机密钥模式
            (None, false, None, None, false) => {
                let pt_msg: Zeroizing<String> = msg_read_io()?;
                let key: Zeroizing<[u8; 32]> = msg_generate_random_key()?;
                msg_encrypt(pt_msg, &key, true, base256mode)?;
            }
            (Some(src_dir), false, None, None, false) => {
                let pt_msg: Zeroizing<String> = msg_read_file(src_dir)?;
                let key: Zeroizing<[u8; 32]> = msg_generate_random_key()?;
                msg_encrypt(pt_msg, &key, true, base256mode)?;
            }
            (None, true, None, None, false) => {
                let ct_msg: Zeroizing<String> = msg_read_dec()?;
                let key: Zeroizing<[u8; 32]> = msg_load_key(base256mode)?;
                msg_decrypt(ct_msg, &key, base256mode)?;
            }
            // 指定密钥模式
            (None, false, Some(key_file), None, false) => {
                let pt_msg: Zeroizing<String> = msg_read_io()?;
                let key: Zeroizing<[u8; 32]> = load_key(key_file,None)?;
                msg_encrypt(pt_msg, &key, false, base256mode)?;
            }
            (Some(src_dir), false, Some(key_file), None, false) => {
                let pt_msg: Zeroizing<String> = msg_read_file(src_dir)?;
                let key: Zeroizing<[u8; 32]> = load_key(key_file,None)?;
                msg_encrypt(pt_msg, &key, false, base256mode)?;
            }
            (None, true, Some(key_file), None, false) => {
                let ct_msg: Zeroizing<String> = msg_read_dec()?;
                let key: Zeroizing<[u8; 32]> = load_key(key_file,None)?;
                msg_decrypt(ct_msg, &key, base256mode)?;
            }
            // 任意密钥模式
            (None, false, None, Some(any_file), &use_passwd) => {
                let pt_msg: Zeroizing<String> = msg_read_io()?;
                let need_confirm = use_passwd; // 加密时需要确认密码
                let key: Zeroizing<[u8; 32]> = derive_key_from_any_file(any_file, use_passwd, need_confirm)?;
                msg_encrypt(pt_msg, &key, false, base256mode)?;
            }
            (Some(src_dir), false, None, Some(any_file), &use_passwd) => {
                let pt_msg: Zeroizing<String> = msg_read_file(src_dir)?;
                let need_confirm = use_passwd; // 加密时需要确认密码
                let key: Zeroizing<[u8; 32]> = derive_key_from_any_file(any_file, use_passwd, need_confirm)?;
                msg_encrypt(pt_msg, &key, false, base256mode)?;
            }
            (None, true, None, Some(any_file), &use_passwd) => {
                let ct_msg: Zeroizing<String> = msg_read_dec()?;
                let need_confirm = false;
                let key: Zeroizing<[u8; 32]> = derive_key_from_any_file(any_file, use_passwd, need_confirm)?;
                msg_decrypt(ct_msg, &key, base256mode)?;
            }
            // 纯密码模式
            (None, false, None, None, true) => {
                let pt_msg: Zeroizing<String> = msg_read_io()?;
                let passwd: Zeroizing<String> = read_passwd_interactive()?;
                let key: Zeroizing<[u8; 32]> = derive_key_from_password(passwd)?;
                msg_encrypt(pt_msg, &key, false, base256mode)?;
            }
            (Some(src_dir), false, None, None, true) => {
                let pt_msg: Zeroizing<String> = msg_read_file(src_dir)?;
                let passwd: Zeroizing<String> = read_passwd_interactive()?;
                let key: Zeroizing<[u8; 32]> = derive_key_from_password(passwd)?;
                msg_encrypt(pt_msg, &key, false, base256mode)?;
            }
            (None, true, None, None, true) => {
                let ct_msg: Zeroizing<String> = msg_read_dec()?;
                let passwd: Zeroizing<String> = read_passwd_interactive_once()?;
                let key: Zeroizing<[u8; 32]> = derive_key_from_password(passwd)?;
                msg_decrypt(ct_msg, &key, base256mode)?;
            }

            _ => {
                print_help();
            }
        }
    } else {
        return Err(anyhow!("不应该出现的错误, 输入模式不是Msg"));
    }
    Ok(())
}