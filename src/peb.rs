use std::{arch::asm, ffi::CStr};

use windows_sys::Win32::Foundation::UNICODE_STRING;
use windows_sys::Win32::System::Kernel::LIST_ENTRY;
use windows_sys::Win32::System::{
    Diagnostics::Debug::{IMAGE_NT_HEADERS32, IMAGE_NT_HEADERS64, IMAGE_NT_OPTIONAL_HDR32_MAGIC},
    SystemServices::{
        IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_EXPORT_DIRECTORY, IMAGE_NT_SIGNATURE,
    },
    Threading::PEB,
    WindowsProgramming::LDR_DATA_TABLE_ENTRY,
};

use crate::string::convert_unicode_string;
use crate::{err, error::InjectorResult};

#[derive(Debug)]
pub struct ModuleInfo {
    _full_dll_name: String,
    _base_dll_name: String,
    _dll_base: usize,
}

pub fn get_module_list() -> Vec<ModuleInfo> {
    let mut addr_of_peb = 0usize;
    unsafe { asm!("mov {peb}, gs:0x60", peb = inout(reg) addr_of_peb) };

    let peb = unsafe { &*(addr_of_peb as *const PEB) };
    let ldr = unsafe { &*peb.Ldr };
    let first = unsafe { &*(&ldr.InMemoryOrderModuleList as *const LIST_ENTRY).offset(-1) };
    let mut node = unsafe { &*first.Flink };

    let mut dll_list = Vec::new();
    while node as *const _ != first as *const _ {
        let table_entry = unsafe { &*(node as *const _ as *const LDR_DATA_TABLE_ENTRY) };
        let uni_name = &table_entry.FullDllName;

        let base_dll_name_ptr =
            unsafe { &*(&table_entry.FullDllName as *const UNICODE_STRING).offset(1) };
        if let Ok(full_dll_name) = convert_unicode_string(uni_name) {
            if let Ok(base_dll_name) = convert_unicode_string(base_dll_name_ptr) {
                dll_list.push(ModuleInfo {
                    _full_dll_name: full_dll_name,
                    _base_dll_name: base_dll_name,
                    _dll_base: table_entry.DllBase as _,
                });
            }
        }

        node = unsafe { &*node.Flink };
    }

    dll_list
}

pub fn find_proc_address(dll_base: usize, func_name: &str) -> InjectorResult<Option<usize>> {
    let dos = unsafe { &*(dll_base as *const IMAGE_DOS_HEADER) };
    if dos.e_magic != IMAGE_DOS_SIGNATURE {
        return Err(err!("Invalid dos signature"));
    }

    let nt_hdr32 = unsafe { &*((dll_base + dos.e_lfanew as usize) as *const IMAGE_NT_HEADERS32) };
    let nt_hdr64 = unsafe { &*((dll_base + dos.e_lfanew as usize) as *const IMAGE_NT_HEADERS64) };
    if nt_hdr32.Signature != IMAGE_NT_SIGNATURE as _ {
        return Err(err!("Invalid nt signature"));
    }

    let is_x86 = nt_hdr32.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC;
    let export_dir = unsafe {
        &*((dll_base
            + if is_x86 {
                nt_hdr32.OptionalHeader.DataDirectory[0].VirtualAddress as usize
            } else {
                nt_hdr64.OptionalHeader.DataDirectory[0].VirtualAddress as usize
            }) as *const IMAGE_EXPORT_DIRECTORY)
    };

    let ent = (dll_base + export_dir.AddressOfNames as usize) as *const u32;
    let eot = (dll_base + export_dir.AddressOfNameOrdinals as usize) as *const u16;
    let eat = (dll_base + export_dir.AddressOfFunctions as usize) as *const u32;

    let func_name = func_name.to_lowercase();
    for i in 0..export_dir.NumberOfNames {
        let name_ptr = unsafe { *ent.offset(i as _) };
        let name = unsafe { CStr::from_ptr((name_ptr as usize + dll_base) as *const i8) }
            .to_str()
            .unwrap()
            .to_string();
        if name.to_lowercase() == func_name {
            let ord = unsafe { *eot.offset(i as _) };
            let fn_ptr = unsafe { *eat.offset(ord as _) } as usize + dll_base;
            return Ok(Some(fn_ptr));
        }
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use crate::{
        library::Library,
        peb::{find_proc_address, get_module_list},
    };

    #[test]
    pub fn test_peb() {
        let module_list = get_module_list();
        let kernel32_name = "kernel32.dll".to_string();
        let kernel32 = module_list
            .iter()
            .find(|m| m._base_dll_name.to_lowercase().contains(&kernel32_name))
            .unwrap();

        let fn_ptr = find_proc_address(kernel32._dll_base, "LoadLibraryW")
            .unwrap()
            .unwrap();

        let addr = Library::from_filename("kernel32.dll")
            .unwrap()
            .find_procedure("LoadLibraryW")
            .unwrap()
            .address();

        assert_eq!(fn_ptr, addr);
    }
}
