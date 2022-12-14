use std::{
    ffi::c_void,
    mem::{size_of_val, transmute, MaybeUninit},
    ptr,
    slice::from_raw_parts,
};

use log::info;
use windows_sys::Win32::{
    Foundation::HANDLE,
    System::{
        Diagnostics::Debug::{WriteProcessMemory, PROCESSOR_ARCHITECTURE_INTEL},
        Memory::{VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE},
        SystemInformation::{GetNativeSystemInfo, SYSTEM_INFO},
        Threading::{GetCurrentProcess, IsWow64Process},
    },
};

use crate::{
    err,
    error::{InjectorError, InjectorResult},
    last_err,
    library::Library,
    options::{InjectOptions, INJECT_OPTIONS_WRAPPER},
    thread::RemoteThrad,
};

pub struct ProcessHandle(pub(crate) HANDLE);

impl ProcessHandle {
    pub fn currrent() -> Self {
        Self(unsafe { GetCurrentProcess() })
    }

    pub fn from_handle(handle: HANDLE) -> Self {
        Self(handle)
    }

    pub fn inject_to_process(
        &self,
        opts: &Option<InjectOptions>,
        library_name: &str,
    ) -> InjectorResult<()> {
        self.check_arch()?;

        let target_lib = Library::from_filename(library_name)?;

        let full_path = target_lib.full_path()?;
        let library_name_addr = self.write_process_memory(unsafe {
            from_raw_parts(
                full_path.as_ptr() as _,
                full_path.len() * size_of_val(&full_path.as_slice()[0]),
            )
        })?;
        let kernel32 = Library::from_filename("kernel32.dll")?;
        let load_library = kernel32.find_procedure("LoadLibraryW")?;
        let load_thread = RemoteThrad::new(self, load_library.address(), unsafe {
            transmute(library_name_addr)
        })?;
        load_thread.wait()?;
        let remote_target_lib_base = load_thread.exit_code()?;
        if remote_target_lib_base == 0 {
            return Err(err!("Remote LoadLibraryW failed"));
        }

        let enable_hook_params = if let Some(opts) = opts {
            let opts_bytes = bincode::serialize(opts).map_err(InjectorError::BincodeError)?;
            let opts_ptr = self.write_process_memory(opts_bytes.as_slice())?;
            info!("Write options to address {:?}", opts_ptr);
            let opts_wrapper = INJECT_OPTIONS_WRAPPER {
                len: opts_bytes.len(),
                ptr: opts_ptr as u64,
            };
            let opts_wrapper_bytes = bincode::serialize(&opts_wrapper)
                .map_err(|e| err!("Failed to serialize options: {:?}", e))?;
            let opts_wrapper_ptr = self.write_process_memory(opts_wrapper_bytes.as_slice())?;
            info!("Write options wrapper to address {:?}", opts_wrapper_ptr);
            opts_wrapper_ptr
        } else {
            ptr::null()
        };
        let enable_hook = target_lib.find_procedure("enable_hook")?;
        let hook_thread = RemoteThrad::new(
            self,
            enable_hook.offset() + remote_target_lib_base as usize,
            unsafe { transmute(enable_hook_params) },
        )?;
        hook_thread.wait()?;

        Ok(())
    }

    pub fn check_arch(&self) -> InjectorResult<()> {
        let is_target_x86 = self.is_process_x86()?;
        let is_self_x86 = Self::currrent().is_process_x86()?;
        if is_target_x86 != is_self_x86 {
            return Err(InjectorError::ArchMismatch(
                if is_target_x86 {
                    "Expect x86"
                } else {
                    "Expect x64"
                },
                if is_self_x86 { "Got x86" } else { "Got x64" },
            ));
        }
        Ok(())
    }

    pub fn is_process_x86(&self) -> InjectorResult<bool> {
        let sys_info = unsafe {
            let mut sys_info = MaybeUninit::<SYSTEM_INFO>::uninit();
            GetNativeSystemInfo(sys_info.as_mut_ptr());
            sys_info.assume_init()
        };
        let processor_arch = unsafe { sys_info.Anonymous.Anonymous.wProcessorArchitecture };
        Ok(processor_arch == PROCESSOR_ARCHITECTURE_INTEL || self.is_wow64_process()?)
    }

    pub fn is_wow64_process(&self) -> InjectorResult<bool> {
        let mut is_wow64 = 0;
        if unsafe { IsWow64Process(self.0, &mut is_wow64) } == 0 {
            return Err(last_err!());
        }
        Ok(is_wow64 != 0)
    }

    pub fn write_process_memory(&self, content: &[u8]) -> InjectorResult<*mut c_void> {
        let target_address = unsafe {
            VirtualAllocEx(
                self.0,
                ptr::null(),
                content.len(),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
        };
        if target_address.is_null() {
            return Err(last_err!());
        }
        let success = unsafe {
            WriteProcessMemory(
                self.0,
                target_address,
                content.as_ptr() as *const c_void,
                content.len(),
                ptr::null_mut(),
            )
        };
        if success == 0 {
            return Err(last_err!());
        }
        Ok(target_address)
    }
}
