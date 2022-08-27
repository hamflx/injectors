use widestring::WideCStr;
use windows_sys::Win32::Foundation::UNICODE_STRING;

use crate::{err, error::InjectorResult};

pub fn convert_unicode_string(uni_string: &UNICODE_STRING) -> InjectorResult<String> {
    if uni_string.Buffer.is_null() {
        return Err(err!("Null Pointer"));
    }

    Ok(
        unsafe { WideCStr::from_ptr(uni_string.Buffer, uni_string.Length as usize / 2) }
            .unwrap()
            .to_string()
            .unwrap(),
    )
}
