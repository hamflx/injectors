use std::{
    ffi::CString,
    mem::{size_of_val, transmute, MaybeUninit},
    os::raw::c_void,
    ptr,
};

use error::{InjectorError, InjectorResult};
use log::info;
use serde::{Deserialize, Serialize};
use widestring::WideCString;
use windows_sys::Win32::{
    Foundation::{GetLastError, HANDLE},
    System::{
        Diagnostics::Debug::{WriteProcessMemory, PROCESSOR_ARCHITECTURE_INTEL},
        LibraryLoader::{GetModuleFileNameW, GetProcAddress, LoadLibraryW},
        Memory::{VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE},
        SystemInformation::{GetNativeSystemInfo, SYSTEM_INFO},
        Threading::{
            CreateRemoteThread, GetCurrentProcess, GetExitCodeThread, GetThreadId, IsWow64Process,
            WaitForSingleObject,
        },
    },
};

pub mod error;

pub unsafe fn inject_to_process(
    process_handle: HANDLE,
    opts: &Option<InjectOptions>,
    library_name: &str,
) -> InjectorResult<()> {
    let is_target_x86 = is_process_x86(process_handle)?;
    let is_self_x86 = is_process_x86(GetCurrentProcess())?;
    if is_target_x86 != is_self_x86 {
        return Err(InjectorError::ArchMismatch(
            if is_self_x86 { "x86" } else { "x64" },
            if is_target_x86 { "x86" } else { "x64" },
        ));
    }

    let mut lib_full_path = std::env::current_exe()
        .map_err(|e| err!("No path content: {:?}", e))?
        .parent()
        .ok_or_else(|| err!("No path content"))?
        .to_path_buf();
    lib_full_path.push(library_name);
    let lib_full_path = lib_full_path
        .to_str()
        .ok_or_else(|| err!("No path content"))?;
    info!("Get enable_hook address from {}", lib_full_path);
    let fp_enable_hook = get_proc_address("enable_hook", lib_full_path)?;

    let library_name_with_null =
        WideCString::from_str(library_name).map_err(|e| err!("Invalid library_name: {:?}", e))?;
    let core_module_handle = LoadLibraryW(library_name_with_null.as_ptr() as _);
    let mut core_full_name_buffer = [0; 4096];
    if core_module_handle == 0
        || GetModuleFileNameW(
            core_module_handle,
            core_full_name_buffer.as_mut_ptr(),
            core_full_name_buffer.len() as u32,
        ) == 0
    {
        return Err(InjectorError::Win32Error(GetLastError()));
    }
    let library_name_addr = write_process_memory(
        process_handle,
        std::slice::from_raw_parts(
            core_full_name_buffer.as_ptr() as _,
            size_of_val(&core_full_name_buffer),
        ),
    )?;
    let fp_load_library = get_proc_address("LoadLibraryW", "kernel32.dll")?;
    let load_library_thread = CreateRemoteThread(
        process_handle,
        ptr::null(),
        0,
        Some(transmute(fp_load_library)),
        library_name_addr,
        0,
        ptr::null_mut(),
    );
    if load_library_thread == 0 {
        return Err(InjectorError::Win32Error(GetLastError()));
    }
    info!(
        "Created LoadLibraryW thread with id: {}",
        GetThreadId(load_library_thread)
    );
    let wait_result = WaitForSingleObject(load_library_thread, 0xFFFFFFFF);
    if wait_result != 0 {
        return Err(InjectorError::Win32Error(GetLastError()));
    }
    let mut module_handle: u32 = 0;
    if GetExitCodeThread(load_library_thread, &mut module_handle as *mut u32) != 0
        && module_handle == 0
    {
        return Err(err!("Remote LoadLibraryW failed"));
    }

    let enable_hook_params = if let Some(opts) = opts {
        let opts_bytes = bincode::serialize(opts).map_err(InjectorError::BincodeError)?;
        let opts_ptr = write_process_memory(process_handle, opts_bytes.as_slice())?;
        info!("Write options to address {:?}", opts_ptr);
        let opts_wrapper = INJECT_OPTIONS_WRAPPER {
            len: opts_bytes.len(),
            ptr: opts_ptr as u64,
        };
        let opts_wrapper_bytes = bincode::serialize(&opts_wrapper)
            .map_err(|e| err!("Failed to serialize options: {:?}", e))?;
        let opts_wrapper_ptr = write_process_memory(process_handle, opts_wrapper_bytes.as_slice())?;
        info!("Write options wrapper to address {:?}", opts_wrapper_ptr);
        opts_wrapper_ptr
    } else {
        ptr::null()
    };
    let thread_handle = CreateRemoteThread(
        process_handle,
        ptr::null(),
        0,
        Some(transmute(fp_enable_hook)),
        enable_hook_params,
        0,
        ptr::null_mut(),
    );
    if thread_handle == 0 {
        return Err(InjectorError::Win32Error(GetLastError()));
    }
    info!(
        "Created enable_hook thread with id: {}",
        GetThreadId(thread_handle)
    );
    let wait_result = WaitForSingleObject(thread_handle, 0xFFFFFFFF);
    if wait_result != 0 {
        return Err(InjectorError::Win32Error(GetLastError()));
    }

    Ok(())
}

pub unsafe fn get_proc_address(
    proc_name: &str,
    module_name: &str,
) -> InjectorResult<unsafe extern "system" fn() -> isize> {
    let module_name_cstr =
        WideCString::from_str(module_name).map_err(|e| err!("Invalid module_name: {:?}", e))?;
    let h_inst = LoadLibraryW(module_name_cstr.as_ptr());
    if h_inst == 0 {
        return Err(InjectorError::Win32Error(GetLastError()));
    }

    let proc_name_cstr = CString::new(proc_name).map_err(|e| err!("Invalid String: {:?}", e))?;
    GetProcAddress(h_inst, proc_name_cstr.as_ptr() as _)
        .ok_or_else(|| InjectorError::Win32Error(GetLastError()))
}

pub fn is_process_x86(process_handle: HANDLE) -> InjectorResult<bool> {
    let sys_info = unsafe {
        let mut sys_info = MaybeUninit::<SYSTEM_INFO>::uninit();
        GetNativeSystemInfo(sys_info.as_mut_ptr());
        sys_info.assume_init()
    };
    let processor_arch = unsafe { sys_info.Anonymous.Anonymous.wProcessorArchitecture };
    Ok(processor_arch == PROCESSOR_ARCHITECTURE_INTEL || is_wow64_process(process_handle)?)
}

pub fn is_wow64_process(process_handle: HANDLE) -> InjectorResult<bool> {
    let mut is_wow64 = 0;
    unsafe {
        if IsWow64Process(process_handle, &mut is_wow64) == 0 {
            return Err(InjectorError::Win32Error(GetLastError()));
        }
    }
    Ok(is_wow64 != 0)
}

pub unsafe fn write_process_memory(
    process_handle: HANDLE,
    content: &[u8],
) -> InjectorResult<*mut c_void> {
    let target_address = VirtualAllocEx(
        process_handle,
        ptr::null(),
        content.len(),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    );
    if target_address.is_null() {
        return Err(InjectorError::Win32Error(GetLastError()));
    }
    let success = WriteProcessMemory(
        process_handle,
        target_address,
        content.as_ptr() as *const c_void,
        content.len(),
        ptr::null_mut(),
    );
    if success == 0 {
        return Err(InjectorError::Win32Error(GetLastError()));
    }
    Ok(target_address)
}

#[derive(Serialize, Deserialize, Clone)]
pub struct InjectOptions {
    pub server_address: Option<String>,
    pub inject_sub_process: bool,
    pub includes_system_process: bool,
}

#[repr(C)]
#[derive(Serialize, Deserialize)]
pub struct INJECT_OPTIONS_WRAPPER {
    pub len: usize,
    pub ptr: u64,
}
