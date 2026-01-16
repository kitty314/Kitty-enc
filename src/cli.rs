use anyhow::{Context, Result, anyhow};
use clap::{CommandFactory, Parser, Subcommand};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::*;

#[derive(Parser, Debug)]
#[command(
    name = "kitty_enc",
    author = "Kitty314",
    version,
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
    #[arg(short = 's', long = "src", value_name = "DIR", help = "要加密的目录路径。加密时会优先在该目录中查找密钥文件，默认为当前目录",
        num_args = 0..=1, default_missing_value = ".")]
    pub src_dir: Option<PathBuf>,

    /// 要解密的目录路径
    #[arg(short = 'd', long = "dec", value_name = "DIR", help = "要解密的目录路径。解密时会优先在该目录中查找密钥文件，默认为当前目录",
        num_args = 0..=1, default_missing_value = ".")]
    pub dec_dir: Option<PathBuf>,

    /// 纯密码模式
    #[arg(short = 'p', long = "passwd", help = "使用纯密码模式，不生成密钥文件，与-a同时使用表示使用密码")]
    pub passwd: bool,

    /// 要修复的目录路径
    #[arg(short = 'f', long = "fix", value_name = "DIR", help = "要修复的目录路径。修复时会收集该目录下的所有文件进行比对，默认为当前目录",
        num_args = 0..=1, default_missing_value = ".")]
    pub fix_dir: Option<PathBuf>,

    /// 递归深度
    #[arg(short = 'r', short_alias = 'R', long = "recursive", value_name = "DEPTH", help = "是否递归文件夹, 可指定递归深度, 0或默认为无限递归",
        num_args = 0..=1, default_missing_value = "0")]
    pub depth: Option<usize>,

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
    /// 消息模式
    #[command(aliases = ["m","message"], about = "消息模式", long_about = "消息加密子模式, 默认交互式输入, 默认随机生成密钥, -s 可指定消息文件，-d 指定解密模式", after_help = MSG_AFTER_HELP)]
    Msg {
        /// 要加密的消息文件
        #[arg(short = 's', long = "src", value_name = "FILE", help = "要加密的消息文件")]
        src_file: Option<PathBuf>,
        /// 要解密的消息字符
        #[arg(short = 'd', long = "dec", help = "解密模式，交互式输入要解密的消息")]
        dec: bool,
        /// 密钥文件路径（可选）
        #[arg(short = 'k', long = "key", value_name = "KEY_FILE", help = "密钥文件路径（可选）。如果指定，则使用该密钥文件")]
        key_file: Option<PathBuf>,
        /// 任意文件作为密钥源（可选）
        #[arg(short = 'a', long = "any-file", value_name = "FILE", help = "任意文件作为密钥源（可选）。使用指定文件的内容派生密钥，与-p同时使用表示使用密码")]
        any_file: Option<PathBuf>,
        /// 纯密码模式
        #[arg(short = 'p', long = "passwd", help = "使用纯密码模式，不生成密钥文件，与-a同时使用表示使用密码")]
        passwd: bool,
        /// 编码字典
        #[arg(short = 'm', long = "mode", value_name = "U32", help = "编码字典, 可选0, 1, 2, 3, 4, 5, 6", default_value_t = 0)]
        base256mode_code: u32,
        /// 是否使用编辑器
        #[arg(short = 'e', long = "editor", help = "使用编辑器, 仅在解密时可用")]
        editor: bool,
    },
    /// 编码模式
    #[command(aliases = ["b","base64","base256"], about = "编码模式", long_about = "编码子模式，不是加密，不提供任何安全性", after_help = BASE_AFTER_HELP)]
    Base {
        /// 交互式编码模式
        #[arg(short = 'i', long = "io-encode", help = "交互式编码模式", aliases = ["ie"])]
        io_encode: bool,
        /// 交互式解码模式
        #[arg(short = 'o', long = "io-decode", help = "交互式解码模式", aliases = ["id","od"])]
        io_decode: bool,
        /// 是否使用编辑器
        #[arg(short = 'e', long = "editor", help = "使用编辑器, 仅交互式可用")]
        editor: bool,
        /// 要编码的文件
        #[arg(short = 's', long = "src", value_name = "FILE", help = "要编码的文件")]
        src_file: Option<PathBuf>,
        /// 要解码的文件
        #[arg(short = 'd', long = "dec", value_name = "FILE", help = "要解码的文件")]
        dec_file: Option<PathBuf>,
        /// 编码字典
        #[arg(short = 'm', long = "mode", value_name = "U32", help = "编码字典, 可选0, 1, 2, 3, 4, 5, 6", default_value_t = 0)]
        base256mode_code: u32,
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
    let result = match &cli.mode {
        Some(Mode::Msg{..}) => {cli_match_msg(&cli)}
        Some(Mode::Base{..}) => {cli_match_base(&cli)}
        _ => {cli_match_main(&cli, &exe_path, &run_dir)}
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
        Some(Mode::Msg { src_file,  key_file, any_file, ..}) => {
            normalize_optional_path(src_file, run_dir)?;
            normalize_optional_path(key_file, run_dir)?;
            normalize_optional_path(any_file, run_dir)?;
        }
        Some(Mode::Base { src_file, dec_file, ..}) => {
            normalize_optional_path(src_file, run_dir)?;
            normalize_optional_path(dec_file, run_dir)?;
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

/// 打印子命令帮助信息
pub fn print_sub_help(name: &str) {
    let mut cmd = Cli::command();
    if let Some(sub) = cmd.find_subcommand_mut(name) {
        if let Err(e) = sub.print_help() {
            my_eprintln!("Failed to print help: {}", e);
        }
    } else {
        if let Err(e) = cmd.print_help() {
            my_eprintln!("Failed to print help: {}", e);
        }
    }
    my_eprintln!();
}