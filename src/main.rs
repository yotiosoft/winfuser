extern crate winapi;
extern crate ntapi;

use winapi::um::fileapi::{CreateFileW, OPEN_EXISTING};
use winapi::um::winnt::{FILE_SHARE_READ, FILE_SHARE_WRITE, HANDLE};
use ntapi::ntioapi::IO_STATUS_BLOCK;
use winapi::um::handleapi::CloseHandle;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
use ntapi::ntioapi::{NtQueryInformationFile, FileBasicInformation};
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

// NtQueryInformationFileを呼び出してファイル情報を取得する関数
fn query_file_info(handle: HANDLE) -> Result<(), String> {
    // IO_STATUS_BLOCKを準備
    let mut io_status_block: IO_STATUS_BLOCK = unsafe { mem::zeroed() };

    // FileInformationのバッファ
    let mut file_info: [u8; 1024] = [0; 1024];  // バッファのサイズを適切に設定

    // NtQueryInformationFileの呼び出し
    let status = unsafe {
        NtQueryInformationFile(
            handle,
            &mut io_status_block,
            file_info.as_mut_ptr() as *mut _,
            file_info.len() as u32,
            FileBasicInformation, // 必要なFileInformationClassを指定
        )
    };

    if status < 0 {
        return Err(format!("Error querying file information: {:?}", status));
    }

    // 必要に応じてfile_infoの解析を行う（ここでは省略）

    Ok(())
}

// ファイルハンドルを取得し、ファイル情報を確認する関数
fn check_file_locks(file_path: &str) -> Result<(), String> {
    let wide_file_path: Vec<u16> = file_path.encode_utf16().collect();
    let file_handle = unsafe {
        CreateFileW(
            wide_file_path.as_ptr(),
            0, // 読み取り/書き込みモード（適切なアクセスモードに変更）
            FILE_SHARE_READ | FILE_SHARE_WRITE, // 読み取り・書き込み共有
            ptr::null_mut(),
            OPEN_EXISTING,
            0,
            ptr::null_mut(),
        )
    };

    if file_handle == INVALID_HANDLE_VALUE {
        return Err(format!("Failed to open file: {}", unsafe { GetLastError() }));
    }

    // ファイル情報のクエリ
    match query_file_info(file_handle) {
        Ok(_) => {
            println!("File information successfully queried.");
        }
        Err(e) => {
            return Err(e);
        }
    }

    unsafe {
        CloseHandle(file_handle);
    }

    Ok(())
}

fn main() {
    //let file_path = "C:\\path\\to\\file.txt";  // ここにチェックしたいファイルパスを指定
    let file_path = "C:\\Users\\ytani\\Desktop\\test\\0519\\0defd59e40a79b8f11e3a5b11a52fb0d-1024x795.jpeg";
    match check_file_locks(file_path) {
        Ok(_) => println!("File is not locked by any process."),
        Err(e) => println!("Error: {}", e),
    }
}
