use widestring::U16Str;
use windows_sys::Win32::{Foundation::HMODULE, System::ProcessStatus::GetModuleBaseNameW};

use crate::{
    error::{InjectorError, InjectorResult},
    last_err,
    process::ProcessHandle,
};

pub struct ProcessModule<'p>(&'p ProcessHandle, HMODULE);

impl<'p> ProcessModule<'p> {
    pub(crate) fn new(process: &'p ProcessHandle, module: HMODULE) -> Self {
        Self(process, module)
    }

    pub fn base_name(&self) -> InjectorResult<String> {
        let mut module_name = [0u16; 4096];
        let n = unsafe {
            GetModuleBaseNameW(
                self.0 .0,
                self.1,
                module_name.as_mut_ptr(),
                module_name.len() as _,
            )
        };
        if n == 0 {
            Err(last_err!())
        } else {
            let module_name = U16Str::from_slice(&module_name[..n as usize]);
            Ok(module_name
                .to_string()
                .map_err(|_| InjectorError::EncodingError)?)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::process::ProcessHandle;

    #[test]
    fn test_enum_modules() {
        let process = ProcessHandle::current();
        let modules = process.list_process_modules().unwrap();
        let found_ntdll = modules
            .iter()
            .any(|m| m.base_name().unwrap().to_lowercase() == "ntdll.dll");
        assert!(found_ntdll);
    }
}
