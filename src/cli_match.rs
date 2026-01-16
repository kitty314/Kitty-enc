use anyhow::{Context, Result, anyhow};
use std::path::PathBuf;
use zeroize::Zeroizing;
use libsodium_rs::utils::{mlock, munlock};

use crate::*;

pub fn cli_match_main(cli: &Cli, exe_path: &PathBuf,run_dir: &PathBuf) -> Result<()> {   
    let depth = match &cli.depth {
        Some(0) => None,
        Some(depth) => Some(*depth),
        _ => Some(1)
    };
    // Determine operation mode
    match (&cli.mode, &cli.src_dir, &cli.dec_dir, &cli.fix_dir, &cli.key_file, &cli.any_file, &cli.passwd) {
        // No subcommand, no -s/-d: auto encrypt current dir, generate key if none
        (None, None, None, None, key_opt, None, false) => {
            let (key_path,passphrase_opt) = get_or_create_key_path(&run_dir, key_opt, "current")?;
            let mut key: Zeroizing<[u8; MASTER_KEY_LENGTH]> = load_key(&key_path,passphrase_opt)?;
            mlock(key.as_mut()).context("锁定主密钥失败")?;
            process_encrypt_dir(&run_dir, &key, Some(&key_path), &exe_path, depth)?;
            munlock(key.as_mut()).context("解锁主密钥失败")?;
            my_println!("Encryption completed for {}", run_dir.display());
            Ok(())
        }

        // Explicit encrypt: -s dir (key optional -> generate in cwd if missing)
        (Some(Mode::Encrypt { src_dir: Some(src_dir), key_file: key_opt }), None, None, None, None, None,false) 
        | (None, Some(src_dir), None, None, key_opt, None, false) => {
            let (key_path,passphrase_opt) = get_or_create_key_path(src_dir, key_opt, "source")?;
            let mut key: Zeroizing<[u8; MASTER_KEY_LENGTH]> = load_key(&key_path,passphrase_opt)?;
            mlock(key.as_mut()).context("锁定主密钥失败")?;
            process_encrypt_dir(src_dir, &key, Some(&key_path), &exe_path, depth)?;
            munlock(key.as_mut()).context("解锁主密钥失败")?;
            my_println!("Encryption completed for {}", src_dir.display());
            Ok(())
        }

        // Explicit decrypt: -d dir (key optional -> search in decryption directory)
        (Some(Mode::Decrypt { dec_dir: Some(dec_dir), key_file: key_opt }), None, None, None, None, None,false) 
        | (None, None, Some(dec_dir), None, key_opt, None, false) => {
            let (key_path,passphrase_opt) = get_or_create_key_path(dec_dir, key_opt, "decryption")?;
            let mut key: Zeroizing<[u8; MASTER_KEY_LENGTH]> = load_key(&key_path,passphrase_opt)?;
            mlock(key.as_mut()).context("锁定主密钥失败")?;
            process_decrypt_dir(dec_dir, &key, &exe_path, Some(&key_path), depth)?;
            munlock(key.as_mut()).context("解锁主密钥失败")?;
            my_println!("Decryption completed for {}", dec_dir.display());
            Ok(())
        }

        // Fix mode: -f dir (key optional -> search in fix directory)
        (None, None, None, Some(fix_dir), key_opt, None, false) => {
            let (key_path,passphrase_opt) = get_or_create_key_path(fix_dir, key_opt, "fix")?;
            let mut key: Zeroizing<[u8; MASTER_KEY_LENGTH]> = load_key(&key_path,passphrase_opt)?;
            mlock(key.as_mut()).context("锁定主密钥失败")?;
            process_fix_dir(fix_dir, &key, &exe_path, Some(&key_path), depth)?;
            munlock(key.as_mut()).context("解锁主密钥失败")?;
            my_println!("Fix completed for {}", fix_dir.display());
            Ok(())
        }

        // 任意文件模式：加密当前目录
        (None, None, None, None, None, Some(any_file), &use_passwd) => {
            let need_confirm = use_passwd; // 加密时需要确认密码
            let mut key: Zeroizing<[u8; MASTER_KEY_LENGTH]> = derive_key_from_any_file(any_file, use_passwd, need_confirm)?;
            mlock(key.as_mut()).context("锁定主密钥失败")?;
            process_encrypt_dir(&run_dir, &key, Some(any_file), &exe_path, depth)?;
            munlock(key.as_mut()).context("解锁主密钥失败")?;
            let mode_str = if use_passwd { "any-file mode with password" } else { "any-file mode, no password" };
            my_println!("Encryption completed for {} ({})", run_dir.display(), mode_str);
            Ok(())
        }

        // 任意文件模式：加密指定目录
        (None, Some(src_dir), None, None, None, Some(any_file), &use_passwd) => {
            let need_confirm = use_passwd; // 加密时需要确认密码
            let mut key: Zeroizing<[u8; MASTER_KEY_LENGTH]> = derive_key_from_any_file(any_file, use_passwd, need_confirm)?;
            mlock(key.as_mut()).context("锁定主密钥失败")?;
            process_encrypt_dir(src_dir, &key, Some(any_file), &exe_path, depth)?;
            munlock(key.as_mut()).context("解锁主密钥失败")?;
            let mode_str = if use_passwd { "any-file mode with password" } else { "any-file mode, no password" };
            my_println!("Encryption completed for {} ({})", src_dir.display(), mode_str);
            Ok(())
        }

        // 任意文件模式：解密指定目录
        (None, None, Some(dec_dir), None, None, Some(any_file), &use_passwd) => {
            let need_confirm = false; // 解密时不需要确认密码
            let mut key: Zeroizing<[u8; MASTER_KEY_LENGTH]> = derive_key_from_any_file(any_file, use_passwd, need_confirm)?;
            mlock(key.as_mut()).context("锁定主密钥失败")?;
            process_decrypt_dir(dec_dir, &key, &exe_path, Some(any_file), depth)?;
            munlock(key.as_mut()).context("解锁主密钥失败")?;
            let mode_str = if use_passwd { "any-file mode with password" } else { "any-file mode, no password" };
            my_println!("Decryption completed for {} ({})", dec_dir.display(), mode_str);
            Ok(())
        }

        // 任意文件模式：修复指定目录
        (None, None, None, Some(fix_dir), None, Some(any_file), &use_passwd) => {
            let need_confirm = false; // 修复时不需要确认密码
            let mut key: Zeroizing<[u8; MASTER_KEY_LENGTH]> = derive_key_from_any_file(any_file, use_passwd, need_confirm)?;
            mlock(key.as_mut()).context("锁定主密钥失败")?;
            process_fix_dir(fix_dir, &key, &exe_path, Some(any_file), depth)?;
            munlock(key.as_mut()).context("解锁主密钥失败")?;
            let mode_str = if use_passwd { "any-file mode with password" } else { "any-file mode, no password" };
            my_println!("Fix completed for {} ({})", fix_dir.display(), mode_str);
            Ok(())
        }

        // 纯密码模式：加密当前目录
        (None, None, None, None, None, None, true) => {
            let passwd: Zeroizing<String> = read_passwd_interactive()?;
            let mut key: Zeroizing<[u8; MASTER_KEY_LENGTH]> = derive_key_from_password(passwd)?;
            mlock(key.as_mut()).context("锁定主密钥失败")?;
            process_encrypt_dir(&run_dir, &key, None, &exe_path, depth)?;
            munlock(key.as_mut()).context("解锁主密钥失败")?;
            my_println!("Encryption completed for {} (password-only mode)", run_dir.display());
            Ok(())
        }

        // 纯密码模式：加密指定目录
        (None, Some(src_dir), None, None, None, None, true) => {
            let passwd: Zeroizing<String> = read_passwd_interactive()?;
            let mut key: Zeroizing<[u8; MASTER_KEY_LENGTH]> = derive_key_from_password(passwd)?;
            mlock(key.as_mut()).context("锁定主密钥失败")?;
            process_encrypt_dir(src_dir, &key, None, &exe_path, depth)?;
            munlock(key.as_mut()).context("解锁主密钥失败")?;
            my_println!("Encryption completed for {} (password-only mode)", src_dir.display());
            Ok(())
        }

        // 纯密码模式：解密指定目录
        (None, None, Some(dec_dir), None, None, None, true) => {
            let passwd: Zeroizing<String> = read_passwd_interactive_once()?;
            let mut key: Zeroizing<[u8; MASTER_KEY_LENGTH]> = derive_key_from_password(passwd)?;
            mlock(key.as_mut()).context("锁定主密钥失败")?;
            process_decrypt_dir(dec_dir, &key, &exe_path, None, depth)?;
            munlock(key.as_mut()).context("解锁主密钥失败")?;
            my_println!("Decryption completed for {} (password-only mode)", dec_dir.display());
            Ok(())
        }

        // 纯密码模式：修复指定目录
        (None, None, None, Some(fix_dir), None, None, true) => {
            let passwd: Zeroizing<String> = read_passwd_interactive_once()?;
            let mut key: Zeroizing<[u8; MASTER_KEY_LENGTH]> = derive_key_from_password(passwd)?;
            mlock(key.as_mut()).context("锁定主密钥失败")?;
            process_fix_dir(fix_dir, &key, &exe_path, None, depth)?;
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
    if let Some(Mode::Msg { src_file, dec, key_file, any_file, passwd, base256mode_code, editor}) = &cli.mode{
        my_println!("您正在使用消息加密模式，该模式不适合用于高度安全的加密传输消息，除非拥有极度安全的通道用于密钥传输，否则消息的安全性几乎等于密钥传输的安全性");
        my_println!("如果对于点对点加密传输有极高的安全性需求，你应该寻找支持非对称加密，密钥交换，随机数交换等功能的软件");
        let base256mode_code = *base256mode_code;
        match (src_file, dec, key_file, any_file, passwd, editor) {
            // 随机密钥模式
            (None, false, None, None, false, false) => {
                let pt_msg: Zeroizing<String> = msg_read_io()?;
                let key: Zeroizing<[u8; MASTER_KEY_LENGTH]> = msg_generate_random_key()?;
                msg_encrypt(pt_msg, &key, true, base256mode_code)?;
            }
            // 随机密钥模式: -s FILE
            (Some(src_file), false, None, None, false, false) => {
                let pt_msg: Zeroizing<String> = msg_read_file(src_file)?;
                let key: Zeroizing<[u8; MASTER_KEY_LENGTH]> = msg_generate_random_key()?;
                msg_encrypt(pt_msg, &key, true, base256mode_code)?;
            }
            // 随机密钥模式: -d [-e]
            (None, true, None, None, false, &use_editor) => {
                let ct_msg: Zeroizing<String> = msg_read_dec(use_editor)?;
                let key: Zeroizing<[u8; MASTER_KEY_LENGTH]> = msg_load_key(base256mode_code)?;
                msg_decrypt(ct_msg, &key, base256mode_code)?;
            }

            // 指定密钥模式
            (None, false, Some(key_file), None, false, false) => {
                let pt_msg: Zeroizing<String> = msg_read_io()?;
                let key: Zeroizing<[u8; MASTER_KEY_LENGTH]> = load_key(key_file,None)?;
                msg_encrypt(pt_msg, &key, false, base256mode_code)?;
            }
            (Some(src_file), false, Some(key_file), None, false, false) => {
                let pt_msg: Zeroizing<String> = msg_read_file(src_file)?;
                let key: Zeroizing<[u8; MASTER_KEY_LENGTH]> = load_key(key_file,None)?;
                msg_encrypt(pt_msg, &key, false, base256mode_code)?;
            }
            (None, true, Some(key_file), None, false, &use_editor) => {
                let ct_msg: Zeroizing<String> = msg_read_dec(use_editor)?;
                let key: Zeroizing<[u8; MASTER_KEY_LENGTH]> = load_key(key_file,None)?;
                msg_decrypt(ct_msg, &key, base256mode_code)?;
            }

            // 任意密钥模式
            (None, false, None, Some(any_file), &use_passwd, false) => {
                let pt_msg: Zeroizing<String> = msg_read_io()?;
                let need_confirm = use_passwd; // 加密时需要确认密码
                let key: Zeroizing<[u8; MASTER_KEY_LENGTH]> = derive_key_from_any_file(any_file, use_passwd, need_confirm)?;
                msg_encrypt(pt_msg, &key, false, base256mode_code)?;
            }
            (Some(src_file), false, None, Some(any_file), &use_passwd, false) => {
                let pt_msg: Zeroizing<String> = msg_read_file(src_file)?;
                let need_confirm = use_passwd; // 加密时需要确认密码
                let key: Zeroizing<[u8; MASTER_KEY_LENGTH]> = derive_key_from_any_file(any_file, use_passwd, need_confirm)?;
                msg_encrypt(pt_msg, &key, false, base256mode_code)?;
            }
            (None, true, None, Some(any_file), &use_passwd, &use_editor) => {
                let ct_msg: Zeroizing<String> = msg_read_dec(use_editor)?;
                let need_confirm = false;
                let key: Zeroizing<[u8; MASTER_KEY_LENGTH]> = derive_key_from_any_file(any_file, use_passwd, need_confirm)?;
                msg_decrypt(ct_msg, &key, base256mode_code)?;
            }

            // 纯密码模式
            (None, false, None, None, true, false) => {
                let pt_msg: Zeroizing<String> = msg_read_io()?;
                let passwd: Zeroizing<String> = read_passwd_interactive()?;
                let key: Zeroizing<[u8; MASTER_KEY_LENGTH]> = derive_key_from_password(passwd)?;
                msg_encrypt(pt_msg, &key, false, base256mode_code)?;
            }
            (Some(src_file), false, None, None, true, false) => {
                let pt_msg: Zeroizing<String> = msg_read_file(src_file)?;
                let passwd: Zeroizing<String> = read_passwd_interactive()?;
                let key: Zeroizing<[u8; MASTER_KEY_LENGTH]> = derive_key_from_password(passwd)?;
                msg_encrypt(pt_msg, &key, false, base256mode_code)?;
            }
            (None, true, None, None, true, &use_editor) => {
                let ct_msg: Zeroizing<String> = msg_read_dec(use_editor)?;
                let passwd: Zeroizing<String> = read_passwd_interactive_once()?;
                let key: Zeroizing<[u8; MASTER_KEY_LENGTH]> = derive_key_from_password(passwd)?;
                msg_decrypt(ct_msg, &key, base256mode_code)?;
            }

            _ => {
                print_sub_help("msg");
            }
        }
    } else {
        return Err(anyhow!("不应该出现的错误, 输入模式不是Msg"));
    }
    Ok(())
}

pub fn cli_match_base(cli: &Cli) -> Result<()> {
    if let Some(Mode::Base { io_encode, io_decode, editor, src_file, dec_file, base256mode_code }) = &cli.mode{
        my_println!("您正在使用编码模式，该模式不是加密，不提供任何安全性，不应用于任何隐私内容");
        let base256mode_code = *base256mode_code;
        match (io_encode, io_decode, editor, src_file, dec_file) {
            // -i [-e]
            (true, false, &use_editor, None, None) => {
                base_encode_io(base256mode_code, use_editor)?;
            }
            // -o [-e]
            (false, true, &use_editor, None, None) => {
                base_decode_io(base256mode_code, use_editor)?;
            }
            // -s FILE
            (false, false, false, Some(src_file), None) => {
                base_encode(src_file, base256mode_code)?;
            }
            // -d FILE
            (false, false, false, None, Some(dec_file)) => {
                base_decode(dec_file, base256mode_code)?;
            }

            _ => {
                print_sub_help("base");
            }
        }
    } else {
        return Err(anyhow!("不应该出现的错误, 输入模式不是Base"));
    }
    Ok(())
}
