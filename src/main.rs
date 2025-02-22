use winapi::um::handleapi::{INVALID_HANDLE_VALUE, CloseHandle};
use ntapi::ntexapi::{NtQuerySystemInformation};
use ntapi::ntobapi::{OBJECT_BASIC_INFORMATION, NtQueryObject};
use std::ptr;
use std::ffi::CString;
use std::mem;

#[repr(C)]
#[derive(Debug, Clone)]
pub struct SystemHandleInformation {
    pub process_id: u32,
    pub object_type: u32,  // object_typeでオブジェクトタイプを識別
    pub handle: u32,
    pub object: *mut std::ffi::c_void,
    pub access_mask: u32,
}

// OBJECT_TYPE_INFORMATION の定義（例として）
#[repr(C)]
pub struct OBJECT_TYPE_INFORMATION {
    pub Name: [u16; 256],  // 名前（最大256文字）
    pub TotalNumberOfObjects: u32,
    pub TotalNumberOfHandles: u32,
    pub TotalNumberOfReferences: u32,
    pub TypeIndex: u32,
}

unsafe fn query_system_handles() -> Vec<SystemHandleInformation> {
    let mut handle_info: Vec<SystemHandleInformation> = Vec::new();
    let mut len = 0u32;

    // 初回の呼び出し、サイズを取得するためにバッファサイズを 0 に設定
    let status = NtQuerySystemInformation(
        16, // SystemHandleInformationに関するコード（バージョンによって異なる場合あり）
        ptr::null_mut(),
        0,
        &mut len,
    );
    let mut buffer = vec![0u8; len as usize];
    while status != 0 {
        println!("Error calling NtQuerySystemInformation, status: {}", status);
        println!("allocating buffer of size: {}", len);
        buffer = vec![0u8; len as usize];

        // 必要なサイズを使って再度呼び出し
        let status = NtQuerySystemInformation(
            16, // SystemHandleInformationに関するコード（バージョンによって異なる場合あり）
            buffer.as_mut_ptr() as *mut winapi::ctypes::c_void,
            len,
            &mut len,
        );

        if status == 0 {
            println!("Successfully called NtQuerySystemInformation, status: {} len: {} / {}", status, len, mem::size_of::<SystemHandleInformation>() as u32);

            let count = len / mem::size_of::<SystemHandleInformation>() as u32;
            println!("Found {} handles", count);
            for i in 0..count {
                let info = &*(buffer.as_ptr().offset(i as isize * mem::size_of::<SystemHandleInformation>() as isize) as *const SystemHandleInformation);
                handle_info.push(info.clone());
            }

            break;
        }
    }

    handle_info
}

// オブジェクトタイプがファイルかどうかを判定する関数
fn is_file_object(object_type: u32) -> bool {
    // object_type に対応するファイルタイプIDを確認
    const FILE_OBJECT_TYPE: u32 = 0x4;  // Windows 内部でのファイルオブジェクトタイプID（仮に 0x17 とする）

    object_type == FILE_OBJECT_TYPE
}

fn main() {
    let system_handles = unsafe { query_system_handles() };

    // ハンドル情報を調べてファイルが開かれているかを確認
    for handle_info in system_handles {
        println!("Handle: {:?}, Process ID: {:?}, Object Type: {:?}", handle_info, handle_info.process_id, handle_info.object_type);
        // ハンドルのオブジェクトタイプがファイルかどうかを確認
        if is_file_object(handle_info.object_type) {
            println!("File is opened by process {} with handle {}", handle_info.process_id, handle_info.handle);
        } else {
            // /println!("Handle {} is not associated with a file object.", handle_info.handle);
        }
    }
}
