use winapi::um::handleapi::{INVALID_HANDLE_VALUE, CloseHandle};
use ntapi::ntexapi::{NtQuerySystemInformation};
use std::ptr;
use std::mem;
use ntapi::ntexapi::{SYSTEM_HANDLE_INFORMATION, SYSTEM_HANDLE_TABLE_ENTRY_INFO};
use ntapi::ntobapi::{OBJECT_BASIC_INFORMATION, NtQueryObject, ObjectBasicInformation, ObjectTypesInformation, OBJECT_TYPE_INFORMATION};
use winapi::um::memoryapi::*;
use winapi::um::processthreadsapi::*;
use winapi::um::winnt::{ MEM_COMMIT, MEM_RELEASE, PAGE_READWRITE };
use winapi::shared::ntdef::{NT_SUCCESS, UNICODE_STRING, HANDLE};
use winapi::shared::ntstatus::{STATUS_BUFFER_TOO_SMALL, STATUS_INFO_LENGTH_MISMATCH};

const SYSTEM_HANDLE_TABLE_ENTRY_INFO_SIZE: isize = 24;
const SYSTEM_HANDLE_TABLE_ENTRY_INFO_START_INDEX: isize = 8;

// ファイルオブジェクトの ObjectTypeIndex を取得
unsafe fn get_file_object_type_index(handle: HANDLE) -> Option<String> {
    let mut buffer_size: u32 = 32;

    let mut status;
    let mut buffer;
    loop {
        buffer = VirtualAlloc(ptr::null_mut(), buffer_size as usize, MEM_COMMIT, PAGE_READWRITE) as *mut winapi::ctypes::c_void;
        let before_size = buffer_size;
        status = NtQueryObject(
            handle,
            ObjectTypesInformation,
            buffer,
            buffer_size as u32,
            &mut buffer_size,
        );
        println!("size: {}, status: {}", buffer_size, status);

        if NT_SUCCESS(status) {
            break;
        }

        if status == STATUS_BUFFER_TOO_SMALL || status == STATUS_INFO_LENGTH_MISMATCH {
            VirtualFree(buffer, before_size as usize, MEM_RELEASE);
        } else {
            println!("Error calling NtQueryObject, status: {}", status);
            return None;
        }
    }

    let buffer_vec = vec![0u8; buffer_size as usize];
    ReadProcessMemory(GetCurrentProcess(), buffer, buffer_vec.as_ptr() as *mut winapi::ctypes::c_void, buffer_size as usize, ptr::null_mut());
    println!("buffer: {:?}", buffer_vec);
    
    // ループして "File" に一致するオブジェクトタイプを探す
    for i in 0..50 {  // 最大50個のオブジェクトタイプをチェック（適宜変更）
        let object_type_info = buffer.offset(i as isize * mem::size_of::<OBJECT_TYPE_INFORMATION>() as isize) as *const OBJECT_TYPE_INFORMATION;
        let object_type_info = &*object_type_info;

/*
pub struct OBJECT_TYPE_INFORMATION {

    pub TypeName: UNICODE_STRING,
    pub TotalNumberOfObjects: ULONG,
    pub TotalNumberOfHandles: ULONG,
    pub TotalPagedPoolUsage: ULONG,
    pub TotalNonPagedPoolUsage: ULONG,
    pub TotalNamePoolUsage: ULONG,
    pub TotalHandleTableUsage: ULONG,
    pub HighWaterNumberOfObjects: ULONG,
    pub HighWaterNumberOfHandles: ULONG,
    pub HighWaterPagedPoolUsage: ULONG,
    pub HighWaterNonPagedPoolUsage: ULONG,
    pub HighWaterNamePoolUsage: ULONG,
    pub HighWaterHandleTableUsage: ULONG,
    pub InvalidAttributes: ULONG,
    pub GenericMapping: GENERIC_MAPPING,
    pub ValidAccessMask: ULONG,
    pub SecurityRequired: BOOLEAN,
    pub MaintainHandleCount: BOOLEAN,
    pub TypeIndex: UCHAR,
    pub ReservedByte: CHAR,
    pub PoolType: ULONG,
    pub DefaultPagedPoolCharge: ULONG,
    pub DefaultNonPagedPoolCharge: ULONG,
}
     */

        println!("TotalNumberOfObjects: {} TotalNumberOfHandles: {} TotalPagedPoolUsage: {} TotalNonPagedPoolUsage: {} TotalNamePoolUsage: {} TotalHandleTableUsage: {} HighWaterNumberOfObjects: {} HighWaterNumberOfHandles: {}",
            object_type_info.TotalNumberOfObjects, object_type_info.TotalNumberOfHandles, object_type_info.TotalPagedPoolUsage, object_type_info.TotalNonPagedPoolUsage, object_type_info.TotalNamePoolUsage, object_type_info.TotalHandleTableUsage, object_type_info.HighWaterNumberOfObjects, object_type_info.HighWaterNumberOfHandles);

        // オブジェクトタイプ名を取得
        let object_type_name = object_type_info.TypeName;
        println!("buffer: {:?} length: {} MaximumLength: {}", object_type_name.Buffer, object_type_name.Length, object_type_name.MaximumLength);
        let str_object_type_name = String::from_utf16_lossy(std::slice::from_raw_parts(object_type_name.Buffer, object_type_name.Length as usize / 2));

        // "File" に一致するオブジェクトタイプを見つけたら ObjectTypeIndex を返す
        if str_object_type_name == "File" {
            let object_type_index = object_type_info.TypeIndex;
            return Some(object_type_index.to_string());
        }

        println!("Object type name: {}", str_object_type_name);
    }

    None
}



// NtQuerySystemInformationを呼び出してハンドル情報を取得
unsafe fn query_system_handles() -> Vec<SYSTEM_HANDLE_TABLE_ENTRY_INFO> {
    let mut handle_info: Vec<SYSTEM_HANDLE_TABLE_ENTRY_INFO> = Vec::new();
    let mut len = 0u32;

    // 初回の呼び出し、サイズを取得するためにバッファサイズを 0 に設定
    let status = NtQuerySystemInformation(
        16, // SYSTEM_HANDLE_INFORMATIONに関するコード（バージョンによって異なる場合あり）
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
            16, // SYSTEM_HANDLE_INFORMATIONに関するコード（バージョンによって異なる場合あり）
            buffer.as_mut_ptr() as *mut winapi::ctypes::c_void,
            len,
            &mut len,
        );

        if status == 0 {
            println!("Successfully called NtQuerySystemInformation, status: {} len: {} / {}", status, len, mem::size_of::<SYSTEM_HANDLE_INFORMATION>() as u32);

            // ハンドル数を取得
            let mut buf = vec![0u8; SYSTEM_HANDLE_TABLE_ENTRY_INFO_START_INDEX as usize];
            ReadProcessMemory(GetCurrentProcess(), buffer.as_ptr() as *const winapi::ctypes::c_void, buf.as_mut_ptr() as *mut winapi::ctypes::c_void, SYSTEM_HANDLE_TABLE_ENTRY_INFO_START_INDEX as usize, ptr::null_mut());
            let count = *(buf.as_ptr() as *const u32);

            println!("Found {} {} handles", count, len / mem::size_of::<SYSTEM_HANDLE_TABLE_ENTRY_INFO>() as u32);
            for i in 0..count {
                //let info = &*(buffer.as_ptr().offset(i as isize * mem::size_of::<SYSTEM_HANDLE_TABLE_ENTRY_INFO>() as isize) as *const SYSTEM_HANDLE_TABLE_ENTRY_INFO);
                //handle_info.push(info.clone());
                let mut buf = vec![0u8; SYSTEM_HANDLE_TABLE_ENTRY_INFO_SIZE as usize];
                ReadProcessMemory(GetCurrentProcess(), buffer.as_ptr().offset(SYSTEM_HANDLE_TABLE_ENTRY_INFO_START_INDEX + i as isize * SYSTEM_HANDLE_TABLE_ENTRY_INFO_SIZE) as *const winapi::ctypes::c_void, buf.as_mut_ptr() as *mut winapi::ctypes::c_void, SYSTEM_HANDLE_TABLE_ENTRY_INFO_SIZE as usize, ptr::null_mut());
                //println!("index: {} {} {}, vec: {:?}", i, SYSTEM_HANDLE_TABLE_ENTRY_INFO_START_INDEX + i as isize * SYSTEM_HANDLE_TABLE_ENTRY_INFO_SIZE as isize, SYSTEM_HANDLE_TABLE_ENTRY_INFO_SIZE, buf);
                let info = &*(buf.as_ptr() as *const SYSTEM_HANDLE_TABLE_ENTRY_INFO);
                handle_info.push(info.clone());
            }

            break;
        }
    }

    handle_info
}

// OBJECT_BASIC_INFORMATIONを使ってオブジェクトがファイルかどうかを確認
fn is_file_object(handle_info: &SYSTEM_HANDLE_TABLE_ENTRY_INFO) -> bool {
    let file_type_index = unsafe { get_file_object_type_index(handle_info.Object) };
    if file_type_index.is_none() {
        return false;
    }

    const FILE_OBJECT_TYPE_INDEX: u8 = 36 as u8;

    // ObjectTypeIndex がファイルオブジェクトに対応していれば true を返す
    handle_info.ObjectTypeIndex == FILE_OBJECT_TYPE_INDEX
}

fn main() {
    let system_handles = unsafe { query_system_handles() };

    // ハンドル情報を調べてファイルオブジェクトが開かれているかを確認
    for handle_info in system_handles {
        // ハンドルがファイルオブジェクトに関連しているかを確認
        //println!("HendleObject: {:?}", handle_info.Object);
        /*
        pub struct SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    pub UniqueProcessId: USHORT,
    pub CreatorBackTraceIndex: USHORT,
    pub ObjectTypeIndex: UCHAR,
    pub HandleAttributes: UCHAR,
    pub HandleValue: USHORT,
    pub Object: PVOID,
    pub GrantedAccess: ULONG,
}
         */

        println!("UniqueProcessId: {} HandleValue: {} ObjectTypeIndex: {} HandleAttributes: {} GrantedAccess: {}", handle_info.UniqueProcessId, handle_info.HandleValue, handle_info.ObjectTypeIndex, handle_info.HandleAttributes, handle_info.GrantedAccess);
        let result = is_file_object(&handle_info);
        if result {
            println!("File is opened by process {} with handle {}", handle_info.UniqueProcessId, handle_info.HandleValue);
        } else {
            //println!("Handle {} is not associated with a file object.", handle_info.HandleValue);
        }
    }
}
