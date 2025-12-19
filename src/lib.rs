// 声明模块
pub mod cli;
pub mod decrypt;
pub mod encrypt;
pub mod fix;
pub mod key_management;
pub mod utils;

// 重新导出常用的类型和函数，方便外部使用
pub use cli::*;
pub use decrypt::*;
pub use encrypt::*;
pub use fix::*;
pub use key_management::*;
pub use utils::*;

// 如果需要，可以在这里定义一些公共的类型别名或常量
pub const STREAMING_THRESHOLD: u64 = 10 * 1024 * 1024; // 10MB，超过这个大小使用流式加密
pub const STREAMING_CHUNK_SIZE: usize = 1024 * 1024; // 1MB 流式分块大小
pub const ANY_FILE_MAX_READ_SIZE: usize = 1024 * 1024; // 任意文件加密时读取文件至多前1MB内容作为输入数据
pub const ENC_SUFFIX: &str = "kitty_enc";
pub const SALT_LENGTH: usize = 16;
pub const ARGON2_M_COST: u32 = 16384; // 16MB - 减小内存消耗
pub const ARGON2_T_COST: u32 = 5;      // 增加时间成本提高安全性
pub const ARGON2_P_COST: u32 = 2;      // 并行度