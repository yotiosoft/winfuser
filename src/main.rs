extern crate winapi;
extern crate ntapi;

use winapi::um::fileapi::{CreateFileW, OPEN_EXISTING};
use winapi::um::winnt::{FILE_SHARE_READ, FILE_SHARE_WRITE, HANDLE};
use ntapi::ntioapi::{IO_STATUS_BLOCK, NtQueryInformationFile, FILE_BASIC_INFORMATION};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::errhandlingapi::GetLastError;
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

    // FILE_BASIC_INFORMATION構造体を準備
    let mut file_info: FILE_BASIC_INFORMATION = unsafe { mem::zeroed() };

    // NtQueryInformationFileの呼び出し
    let status = unsafe {
        NtQueryInformationFile(
            handle,
            &mut io_status_block,
            &mut file_info as *mut _ as *mut _,
            std::mem::size_of::<FILE_BASIC_INFORMATION>() as u32,
            4, // FileInformationClass::FileBasicInformationを整数値で指定
        )
    };

    if status < 0 {
        return Err(format!("Error querying file information: {:?}", status));
    }

    // FILE_BASIC_INFORMATIONの内容を手動で表示
    println!("File Basic Information:");
    
    unsafe {
        // 各時間情報をi64として表示
        println!("  CreationTime: {}", file_info.CreationTime.QuadPart());
        println!("  LastAccessTime: {}", file_info.LastAccessTime.QuadPart());
        println!("  LastWriteTime: {}", file_info.LastWriteTime.QuadPart());
        println!("  ChangeTime: {}", file_info.ChangeTime.QuadPart());
    }
    
    // FileAttributesはそのまま表示
    println!("  FileAttributes: {}", file_info.FileAttributes);

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
