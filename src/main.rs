use winapi::um::handleapi::{INVALID_HANDLE_VALUE, CloseHandle};
use ntapi::ntexapi::{NtQuerySystemInformation, SystemHandleInformation};
use std::ptr;
use std::ffi::CString;
use std::mem;

#[repr(C)]
#[derive(Debug, Clone)]
pub struct SystemHandleInformation {
    pub process_id: u32,
    pub object_type: u32,
    pub handle: u32,
    pub object: *mut std::ffi::c_void,
    pub access_mask: u32,
}

unsafe fn query_system_handles() -> Vec<SystemHandleInformation> {
    let mut handle_info: Vec<SystemHandleInformation> = Vec::new();
    let mut len = 0u32;

    // 初回の呼び出し、サイズを取得するためにバッファサイズを 0 に設定
    let mut status = NtQuerySystemInformation(
        16, // SystemHandleInformationに関するコード（バージョンによって異なる場合あり）
        ptr::null_mut(),
        0,
        &mut len,
    );
    while status != 0 {
        println!("Error calling NtQuerySystemInformation, status: {}", status);
        println!("len: {}", len);

        let mut buffer = vec![0u8; len as usize];
        
        // 必要なサイズを使って再度呼び出し
        status = NtQuerySystemInformation(
            16, // SystemHandleInformationに関するコード（バージョンによって異なる場合あり）
            buffer.as_mut_ptr() as *mut winapi::ctypes::c_void,
            len,
            &mut len,
        );

        if status == 0 {
            let count = len / mem::size_of::<SystemHandleInformation>() as u32;
            for i in 0..count {
                let info = &*(buffer.as_ptr().offset(i as isize * mem::size_of::<SystemHandleInformation>() as isize) as *const SystemHandleInformation);
                handle_info.push(info.clone());
            }
            break;
        } else {
            println!("Error querying system handles again, status: {}", status);
        }
    }

    handle_info
}

fn main() {
    let file_path = r"C:\Users\ytani\Desktop\winfuser_test\test.xlsx";
    let system_handles = unsafe { query_system_handles() };

    // ハンドル情報を調べてファイルが開かれているかを確認
    for handle_info in system_handles {
        // ハンドル情報がファイルに関連しているかを判定する
        println!("{:?}", handle_info);
    }
}
