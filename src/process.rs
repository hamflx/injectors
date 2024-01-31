use std::{
    ffi::c_void,
    mem::{size_of_val, MaybeUninit},
    ptr::{self, null_mut},
    slice::from_raw_parts,
};

use log::info;
use windows_sys::Win32::{
    Foundation::{HANDLE, HMODULE},
    System::{
        Diagnostics::Debug::{WriteProcessMemory, PROCESSOR_ARCHITECTURE_INTEL},
        Memory::{VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE},
        ProcessStatus::EnumProcessModules,
        SystemInformation::{GetNativeSystemInfo, SYSTEM_INFO},
        Threading::{GetCurrentProcess, IsWow64Process},
    },
};

use crate::{
    err,
    error::{InjectorError, InjectorResult},
    last_err,
    library::Library,
    module::ProcessModule,
    options::{InjectOptions, INJECT_OPTIONS_WRAPPER},
    thread::RemoteThread,
};

pub struct ProcessHandle(pub(crate) HANDLE);

impl ProcessHandle {
    pub fn current() -> Self {
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
        let load_thread = RemoteThread::new(self, load_library.address(), unsafe {
            &*(library_name_addr as *const ())
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
        let hook_thread = RemoteThread::new(
            self,
            enable_hook.offset() + remote_target_lib_base as usize,
            unsafe { &*(enable_hook_params as *const ()) },
        )?;
        hook_thread.wait()?;

        Ok(())
    }

    pub fn check_arch(&self) -> InjectorResult<()> {
        let is_target_x86 = self.is_process_x86()?;
        let is_self_x86 = Self::current().is_process_x86()?;
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

    pub fn list_process_modules(&self) -> InjectorResult<Vec<ProcessModule>> {
        let mut needed = 0;
        let ret = unsafe { EnumProcessModules(self.0, null_mut(), 0, &mut needed) };
        if ret == 0 {
            return Err(last_err!());
        }
        let mut buf = vec![0u8; needed as usize];
        let ret = unsafe { EnumProcessModules(self.0, buf.as_mut_ptr() as _, needed, &mut needed) };
        if ret == 0 {
            return Err(last_err!());
        }
        const MODULE_HANDLE_SIZE: usize = std::mem::size_of::<HMODULE>();
        let modules = buf
            .chunks(MODULE_HANDLE_SIZE)
            .filter_map(|buf| {
                let mut handle = [0u8; MODULE_HANDLE_SIZE];
                if buf.len() == MODULE_HANDLE_SIZE {
                    handle.copy_from_slice(buf);
                    Some(ProcessModule::new(self, HMODULE::from_le_bytes(handle)))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        Ok(modules)
    }
}
