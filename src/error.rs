use thiserror::Error;
use windows_sys::Win32::Foundation::WIN32_ERROR;

#[derive(Error, Debug)]
pub enum InjectorError {
    #[error("Win32 Error")]
    Win32Error(WIN32_ERROR),

    #[error("Bincode Error")]
    BincodeError(bincode::Error),

    #[error("Bincode Error")]
    ArchMismatch(&'static str, &'static str),

    #[error("Encoding Error")]
    EncodingError,

    #[error("ModuleUnloaded Error")]
    ModuleUnloaded,

    #[error("Other Error")]
    Other(String),
}

impl InjectorError {
    pub fn code(&self) -> Option<WIN32_ERROR> {
        match self {
            InjectorError::Win32Error(err) => Some(*err),
            _ => None,
        }
    }
}

pub type InjectorResult<T> = Result<T, InjectorError>;

#[macro_export]
macro_rules! err {
    ($($t:tt)+) => {
        $crate::error::InjectorError::Other(format!($($t)+))
    };
}

#[macro_export]
macro_rules! last_err {
    () => {
        $crate::error::InjectorError::Win32Error(unsafe {
            windows_sys::Win32::Foundation::GetLastError()
        })
    };
}
