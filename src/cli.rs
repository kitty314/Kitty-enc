use anyhow::{Context, Result, anyhow};
use clap::{CommandFactory, Parser, Subcommand};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use zeroize::Zeroizing;
use libsodium_rs::utils::{mlock, munlock};

use crate::*;

pub const AFTER_HELP: &str = "
使用示例:
  kitty_enc                    # 无参数：在当前目录生成密钥并加密当前目录（默认使用密码短语）
  kitty_enc -s DIR            # 加密指定目录（优先在 DIR 中查找密钥，没有则生成，默认使用密码短语）
  kitty_enc -k key.kitty_key -s DIR   # 使用指定密钥加密指定目录（默认使用密码短语）
  kitty_enc encrypt -s DIR    # 显式加密指定目录（优先在 DIR 中查找密钥，没有则生成，默认使用密码短语）
  kitty_enc -d DIR            # 解密指定目录（在 DIR 中查找密钥文件，默认使用密码短语）
  kitty_enc -k key.kitty_key -d DIR   # 使用指定密钥解密指定目录（默认使用密码短语）
  kitty_enc decrypt -d DIR    # 显式解密指定目录（在 DIR 中查找密钥文件，默认使用密码短语）
  kitty_enc -p                # 纯密码模式：使用密码加密当前目录（不生成密钥文件）
  kitty_enc -p -s DIR         # 纯密码模式：使用密码加密指定目录（不生成密钥文件）
  kitty_enc -p -d DIR         # 纯密码模式：使用密码解密指定目录（不生成密钥文件）
  kitty_enc -a FILE -s DIR    # 任意文件模式：使用指定文件派生密钥加密目录
  kitty_enc -a FILE -d DIR    # 任意文件模式：使用指定文件派生密钥解密目录
  kitty_enc -a FILE -p -s DIR # 任意文件模式+密码：使用文件内容和密码派生密钥加密目录
  kitty_enc -a FILE -p -d DIR # 任意文件模式+密码：使用文件内容和密码派生密钥解密目录

注意事项:
  - 跳过空文件（大小为 0 的文件）
  - 跳过以 . 开头的目录和文件（如 .git）
  - 跳过 .kitignore 中规定的文件
  - 跳过软链接(符号链接)，除非明确指定，指定软链接不会删除实际文件
  - 跳过自身可执行文件、密钥文件 (*.kitty_key 和 -k 指定的密钥)、已加密文件 (*.kitty_enc)
  - 加密后缀：.kitty_enc
  - 默认密钥文件：目录名-时间.kitty_key（生成于源目录中）
  - 密钥文件可以修改为任何后缀使用，但不使用默认后缀的密钥无法自动识别
  - 密钥文件支持软链接，你需要确保链接有效，软链接无法自动识别
  - 加密时：
      * 如果指定了 -k 参数，则使用指定的密钥文件
      * 如果没有指定 -k 参数，则优先在源目录（-s 指定的目录）中查找现有的密钥文件
      * 如果找不到现有密钥文件，则创建新的密钥文件（生成在源目录中）
  - 解密时：
      * 如果指定了 -k 参数，则使用指定的密钥文件
      * 如果没有指定 -k 参数，则在解密目录（-d 指定的目录）中查找密钥文件
  - 密钥查找只搜索一层目录，不递归搜索子文件夹
  - 加密后删除原始文件，解密后删除加密文件
  - 所有 .kitty_key 文件都不会被加密，无论是否是指定的密钥文件
  - 密码短语：
      * 程序会提示交互式输入密码短语，不会显示在屏幕上，也不会被终端历史记录
      * 使用密码短语时，密钥文件将存储加密的密钥
      * 不使用密码短语时，密钥文件存储原始密钥
      * 使用密码短语时，必须提供正确的密码短语才能解密密钥文件
      * 密码短语用于增强安全性，即使密钥文件泄露，没有密码短语也无法解密
  - 纯密码模式 (-p)：
      * 使用密码直接派生密钥，不生成密钥文件
      * 加密和解密都需要输入相同的密码
      * 适用于不需要密钥文件管理的场景
      * 密码强度直接影响安全性
  - 任意文件模式 (-a):
      * 使用任意文件的内容派生密钥
      * 文件必须至少32字节大小
      * 程序会读取文件前1MB内容用于密钥派生
      * 可以结合密码使用
      * 适用于需要基于特定文件生成密钥的场景
  - 修复模式 (-f):
      * 希望永远不要用到它
      * 使用时注意需要正确的解密参数，否则无法判断加密文件完整性

安全提示:
  - 请妥善保管密钥文件，丢失密钥将无法解密文件
  - 建议定期备份密钥文件
  - 不要在公共网络传输未加密的密钥文件
  - 使用强密码短语以增强安全性
  - 密码短语和密钥文件应分开保管
  - 纯密码模式下，请使用强密码并确保密码安全
  - 任意文件模式下，确保使用的文件内容稳定不变，否则无法解密

关于内存清理: 
  - 绝大多数涉及隐私信息的内存在程序正常结束时都会被清理
  - 对于运行敏感应用程序的系统，应完全禁用休眠功能
  - 在 Unix 系统中，当在开发环境之外运行加密代码时，也应该禁用核心转储
  - 由于许多系统对进程可锁定的内存量有限制, 本程序预计会取消对内存锁定的支持, 用户有责任保护内存不被交换到磁盘
  - 如果冷启动攻击或静态数据保护是您的威胁模型中严重的问题，那么最有效的防御措施是加密整个磁盘卷并加密交换分区（或完全禁用交换分区）

关于正常使用:
  - 程序在处理时会尝试请求文件锁，但取决于实际情况，可能会报错、无效、被绕过、被忽略，程序无法保证锁定有效
  - 用户应当保证需要处理的文件没有被其它进程使用，否则可能造成文件损坏及其他未知后果
  - 本程序使用的后缀`kitty_enc`及`kitty_key`，不应擅自改动或使用
  - 如果有使用相同后缀的其他程序，应当自行区分文件来源
  - 不要对同一文件启动多个加密进程
  - 不要在相同目录下创建或修改与加密文件或源文件同名的文件
  - 不推荐处理软链接，因为取决于操作系统，可能产生无法预测的结果
  - 不要忽视程序的报错，谨慎使用修复模式，优先进行手动修复";

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    name = "kitty_enc",
    about = "我不是病毒",
    long_about = "我不是病毒",
    after_help = AFTER_HELP
)]
#[command(propagate_version = true)]
pub struct Cli {
    /// 密钥文件路径（可选）
    #[arg(short = 'k', long = "key", value_name = "KEY_FILE", help = "密钥文件路径（可选）。如果指定，则使用该密钥文件；如果不指定，程序会自动查找或生成密钥文件")]
    pub key_file: Option<PathBuf>,

    /// 任意文件作为密钥源（可选）
    #[arg(short = 'a', long = "any-file", value_name = "FILE", help = "任意文件作为密钥源（可选）。使用指定文件的内容派生密钥，与-p同时使用表示使用密码")]
    pub any_file: Option<PathBuf>,

    /// 要加密的目录路径
    #[arg(short = 's', long = "src", value_name = "DIR", help = "要加密的目录路径。加密时会优先在该目录中查找密钥文件")]
    pub src_dir: Option<PathBuf>,

    /// 要解密的目录路径
    #[arg(short = 'd', long = "dec", value_name = "DIR", help = "要解密的目录路径。解密时会优先在该目录中查找密钥文件")]
    pub dec_dir: Option<PathBuf>,

    /// 纯密码模式
    #[arg(short = 'p', long = "passwd", help = "使用纯密码模式，不生成密钥文件，与-a同时使用表示使用密码")]
    pub passwd: bool,

    /// 要修复的目录路径
    #[arg(short = 'f', long = "fix", value_name = "DIR", help = "要修复的目录路径。修复时会收集该目录下的所有文件进行比对")]
    pub fix_dir: Option<PathBuf>,

    /// 操作模式子命令
    #[command(subcommand, help = "操作模式子命令")]
    pub mode: Option<Mode>,
}

#[derive(Subcommand, Debug)]
pub enum Mode {
    /// 加密模式
    #[command(about = "加密模式", long_about = "加密指定目录或当前目录。加密时会优先在源目录中查找密钥文件，没有则生成新的密钥文件")]
    Encrypt {
        /// 要加密的目录路径
        #[arg(short = 's', long = "src", value_name = "DIR", help = "要加密的目录路径。加密时会优先在该目录中查找密钥文件")]
        src_dir: Option<PathBuf>,
        /// 密钥文件路径（可选）
        #[arg(short = 'k', long = "key", value_name = "KEY_FILE", help = "密钥文件路径（可选）。如果指定，则使用该密钥文件；如果不指定，程序会自动查找或生成密钥文件")]
        key_file: Option<PathBuf>,
    },
    /// 解密模式
    #[command(about = "解密模式", long_about = "解密指定目录（需要 -d 参数指定目录）。解密时会优先在解密目录中查找密钥文件")]
    Decrypt {
        /// 要解密的目录路径
        #[arg(short = 'd', long = "dec", value_name = "DIR", help = "要解密的目录路径。解密时会优先在该目录中查找密钥文件")]
        dec_dir: Option<PathBuf>,
        #[arg(short = 'k', long = "key", value_name = "KEY_FILE", help = "密钥文件路径（可选）。如果指定，则使用该密钥文件；如果不指定，程序会自动查找或生成密钥文件")]
        key_file: Option<PathBuf>,
    },
}

/// 全局中断标志
static INTERRUPTED: AtomicBool = AtomicBool::new(false);

/// 检查是否被中断
pub fn is_interrupted() -> bool {
    INTERRUPTED.load(Ordering::SeqCst)
}

/// 设置 Ctrl+C 信号处理器
fn set_ctrlc_handler() -> Result<()>{
    ctrlc::set_handler(move || {
        INTERRUPTED.store(true, Ordering::SeqCst);
        my_println!("\n\nInterrupt signal received. Gracefully stopping after current operations...");
        my_println!("If you are entering your password, just press Enter to finish.")
    }).context("Failed to set Ctrl+C handler")?;
    Ok(())
}
/// 处理命令行参数并执行相应的操作
pub fn handle_cli(mut cli: Cli) -> Result<()> {
    // 设置 Ctrl+C 信号处理器
    set_ctrlc_handler()?;
    // Paths
    let exe_path = std::env::current_exe().context("Cannot get current executable path")?;
    let run_dir = std::env::current_dir().context("Cannot get current working directory")?;

    // 将相对路径转换为绝对路径并规范化
    normalize_cli_paths(&mut cli, &run_dir)?;

    // Determine operation mode
    let result = match (&cli.mode, &cli.src_dir, &cli.dec_dir, &cli.fix_dir, &cli.key_file, &cli.any_file, &cli.passwd) {
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
        (None, None, None, None, None, Some(any_file), &passwd_only) => {
            let need_confirm = passwd_only; // 加密时需要确认密码
            let mut key: Zeroizing<[u8; 32]> = derive_key_from_any_file(any_file, passwd_only, need_confirm)?;
            mlock(key.as_mut()).context("锁定主密钥失败")?;
            process_encrypt_dir(&run_dir, &key, Some(any_file), &exe_path)?;
            munlock(key.as_mut()).context("解锁主密钥失败")?;
            let mode_str = if passwd_only { "any-file mode with password" } else { "any-file mode, no password" };
            my_println!("Encryption completed for {} ({})", run_dir.display(), mode_str);
            Ok(())
        }

        // 任意文件模式：加密指定目录
        (None, Some(src_dir), None, None, None, Some(any_file), &passwd_only) => {
            let need_confirm = passwd_only; // 加密时需要确认密码
            let mut key: Zeroizing<[u8; 32]> = derive_key_from_any_file(any_file, passwd_only, need_confirm)?;
            mlock(key.as_mut()).context("锁定主密钥失败")?;
            process_encrypt_dir(src_dir, &key, Some(any_file), &exe_path)?;
            munlock(key.as_mut()).context("解锁主密钥失败")?;
            let mode_str = if passwd_only { "any-file mode with password" } else { "any-file mode, no password" };
            my_println!("Encryption completed for {} ({})", src_dir.display(), mode_str);
            Ok(())
        }

        // 任意文件模式：解密指定目录
        (None, None, Some(dec_dir), None, None, Some(any_file), &passwd_only) => {
            let need_confirm = false; // 解密时不需要确认密码
            let mut key: Zeroizing<[u8; 32]> = derive_key_from_any_file(any_file, passwd_only, need_confirm)?;
            mlock(key.as_mut()).context("锁定主密钥失败")?;
            process_decrypt_dir(dec_dir, &key, &exe_path, Some(any_file))?;
            munlock(key.as_mut()).context("解锁主密钥失败")?;
            let mode_str = if passwd_only { "any-file mode with password" } else { "any-file mode, no password" };
            my_println!("Decryption completed for {} ({})", dec_dir.display(), mode_str);
            Ok(())
        }

        // 任意文件模式：修复指定目录
        (None, None, None, Some(fix_dir), None, Some(any_file), &passwd_only) => {
            let need_confirm = false; // 修复时不需要确认密码
            let mut key: Zeroizing<[u8; 32]> = derive_key_from_any_file(any_file, passwd_only, need_confirm)?;
            mlock(key.as_mut()).context("锁定主密钥失败")?;
            process_fix_dir(fix_dir, &key, &exe_path, Some(any_file))?;
            munlock(key.as_mut()).context("解锁主密钥失败")?;
            let mode_str = if passwd_only { "any-file mode with password" } else { "any-file mode, no password" };
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
    };
    result
}

/// 辅助函数：规范化可选路径
fn normalize_optional_path(path: &mut Option<PathBuf>, run_dir: &PathBuf) -> Result<()> {
    if let Some(path) = path {
        if path.is_relative() {
            *path = run_dir.join(&path);
        }
        // 规范化路径（移除 . 和 ..）
        *path = normalize_path(&path, run_dir);
        if !path.try_exists()? {
            return Err(anyhow!("Path does not exist: {}", path.display()));
        }
    }
    Ok(())
}

/// 规范化 CLI 中的所有路径
fn normalize_cli_paths(cli: &mut Cli, run_dir: &PathBuf) ->Result<()>{
    // 规范化顶级参数
    normalize_optional_path(&mut cli.src_dir, run_dir)?;
    normalize_optional_path(&mut cli.dec_dir, run_dir)?;
    normalize_optional_path(&mut cli.key_file, run_dir)?;
    normalize_optional_path(&mut cli.any_file, run_dir)?;
    normalize_optional_path(&mut cli.fix_dir, run_dir)?;

    // 规范化子命令参数
    match &mut cli.mode {
        Some(Mode::Encrypt { src_dir, key_file }) => {
            normalize_optional_path(src_dir, run_dir)?;
            normalize_optional_path(key_file, run_dir)?;
        }
        Some(Mode::Decrypt { dec_dir, key_file }) => {
            normalize_optional_path(dec_dir, run_dir)?;
            normalize_optional_path(key_file, run_dir)?;
        }
        None => {}
    }
    Ok(())
}

/// 打印帮助信息
pub fn print_help() {
    // 打印 clap 的默认帮助信息
    let mut cmd = Cli::command();
    if let Err(e) = cmd.print_help() {
        my_eprintln!("Failed to print help: {}", e);
    }
    my_eprintln!();
}