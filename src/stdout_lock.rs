// 输出锁
use std::sync::Mutex;
use lazy_static::lazy_static;
lazy_static! {
    pub static ref OUTPUT_LOCK: Mutex<()> = Mutex::new(());
}

/// 线程安全的 println! 宏包装
#[macro_export]
macro_rules! my_println {
    ($($arg:tt)*) => {{
        use $crate::stdout_lock::OUTPUT_LOCK;
        {
            let _guard = match OUTPUT_LOCK.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            println!($($arg)*);
        } // _guard 在这里被释放，锁被释放
    }};
}

/// 线程安全的 eprintln! 宏包装
#[macro_export]
macro_rules! my_eprintln {
    ($($arg:tt)*) => {{
        use $crate::stdout_lock::OUTPUT_LOCK;
        {
            let _guard = match OUTPUT_LOCK.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            eprintln!($($arg)*);
        } // _guard 在这里被释放，锁被释放
    }};
}