use std::ffi::CString;

use widestring::{WideCStr, WideCString};
use windows_sys::Win32::{
    Foundation::HINSTANCE,
    System::LibraryLoader::{FreeLibrary, GetModuleFileNameW, GetProcAddress, LoadLibraryW},
};

use crate::{
    err,
    error::{InjectorError, InjectorResult},
    last_err,
};

pub struct Library(HINSTANCE);

impl Library {
    pub fn from_filename(filename: &str) -> InjectorResult<Self> {
        let module_name_cstr =
            WideCString::from_str(filename).map_err(|e| err!("Invalid module_name: {:?}", e))?;
        let h_inst = unsafe { LoadLibraryW(module_name_cstr.as_ptr()) };
        if h_inst == 0 {
            return Err(last_err!());
        }
        Ok(Self(h_inst))
    }

    pub fn find_procedure(&self, proc_name: &str) -> InjectorResult<LibraryProcedure> {
        let proc_name_cstr =
            CString::new(proc_name).map_err(|e| err!("Invalid String: {:?}", e))?;
        let addr = unsafe { GetProcAddress(self.0, proc_name_cstr.as_ptr() as _) }
            .ok_or_else(|| last_err!())?;
        Ok(LibraryProcedure(self, addr as _))
    }

    pub fn full_path(&self) -> InjectorResult<WideCString> {
        let mut full_path_buf = [0; 4096];
        if unsafe {
            GetModuleFileNameW(
                self.0,
                full_path_buf.as_mut_ptr(),
                full_path_buf.len() as u32,
            )
        } == 0
        {
            return Err(last_err!());
        }
        Ok(WideCStr::from_slice_truncate(&full_path_buf)
            .map_err(|e| err!("Invalid string: {:?}", e))?
            .to_owned())
    }

    pub fn module_base(&self) -> usize {
        self.0 as _
    }
}

impl Drop for Library {
    fn drop(&mut self) {
        unsafe { FreeLibrary(self.0) };
    }
}

pub struct LibraryProcedure<'lib>(&'lib Library, usize);

impl<'lib> LibraryProcedure<'lib> {
    pub fn offset(&self) -> usize {
        self.1 - self.0.module_base()
    }

    pub fn address(&self) -> usize {
        self.1
    }
}
