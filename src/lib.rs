// 声明模块
pub mod cli;
pub mod cli_match;
pub mod decrypt;
pub mod encrypt;
pub mod fix;
pub mod key_management;
pub mod utils;
pub mod hash;
pub mod stdout_lock;
pub mod read_io;
pub mod key_derive;
pub mod my_enc_dec;
pub mod msg;

// 重新导出常用的类型和函数，方便外部使用
pub use cli::*;
pub use cli_match::*;
pub use decrypt::*;
pub use encrypt::*;
pub use fix::*;
pub use key_management::*;
pub use utils::*;
pub use hash::*;
pub use stdout_lock::*;
pub use read_io::*;
pub use key_derive::*;
pub use my_enc_dec::*;
pub use msg::*;

// 如果需要，可以在这里定义一些公共的类型别名或常量
pub const STREAMING_THRESHOLD: u64 = 10 * 1024 * 1024; // 10MB，超过这个大小使用流式加密
pub const STREAMING_CHUNK_SIZE: usize = 1024 * 1024; // 1MB 流式分块大小
pub const ANY_FILE_MAX_READ_SIZE: usize = 1024 * 1024; // 任意文件加密时读取文件至多前1MB内容作为输入数据
pub const ENC_SUFFIX: &str = "kitty_enc";
pub const DEFAULT_KEY_SUFFIX: &str = "kitty_key";
pub const SALT_LENGTH: usize = 16;    // 不可更改
pub const MY_ARGON2_MEMLIMIT_16: usize = 1024*1024*8;
pub const MY_ARGON2_OPSLIMIT_16: u64 = 2;
pub const MY_ARGON2_MEMLIMIT_32: usize = 1024*1024*16;
pub const MY_ARGON2_OPSLIMIT_32: u64 = 4;
pub const MY_ADDITIONAL_DATA: Option<&[u8]> = Some(b"kitty_enc");
pub const MSG_FILE_MAX_SIZE: u64 = 1024 * 50;