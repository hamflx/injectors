use std::{ffi::c_void, mem::transmute, ptr};

use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE},
    System::Threading::{CreateRemoteThread, GetExitCodeThread, WaitForSingleObject},
};

use crate::{error::InjectorResult, last_err, process::ProcessHandle};

pub struct RemoteThread<'process>(&'process ProcessHandle, HANDLE);

impl<'process> RemoteThread<'process> {
    pub fn new(process: &'process ProcessHandle, addr: usize, param: &()) -> InjectorResult<Self> {
        let thread_handle = unsafe {
            CreateRemoteThread(
                process.0,
                ptr::null(),
                0,
                Some(transmute(addr)),
                param as *const () as *const c_void,
                0,
                ptr::null_mut(),
            )
        };
        if thread_handle == 0 {
            return Err(last_err!());
        }
        Ok(Self(process, thread_handle))
    }

    pub fn wait(&self) -> InjectorResult<()> {
        let wait_result = unsafe { WaitForSingleObject(self.1, 0xFFFFFFFF) };
        if wait_result != 0 {
            return Err(last_err!());
        };
        Ok(())
    }

    pub fn exit_code(&self) -> InjectorResult<u32> {
        let mut code: u32 = 0;
        if unsafe { GetExitCodeThread(self.1, &mut code as *mut u32) } == 0 {
            return Err(last_err!());
        }
        Ok(code)
    }
}

impl<'process> Drop for RemoteThread<'process> {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.1) };
    }
}
