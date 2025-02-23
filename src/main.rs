extern crate winapi;
extern crate ntapi;

use winapi::um::handleapi::{INVALID_HANDLE_VALUE, CloseHandle};
use ntapi::ntexapi::{NtQuerySystemInformation, SystemObjectInformation, SYSTEM_HANDLE_INFORMATION_EX, SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX};
use std::ptr;
use std::mem;
use ntapi::ntexapi::{SYSTEM_HANDLE_INFORMATION, SYSTEM_HANDLE_TABLE_ENTRY_INFO, SystemExtendedHandleInformation};
use ntapi::ntobapi::{OBJECT_BASIC_INFORMATION, NtQueryObject, ObjectBasicInformation, ObjectTypesInformation, OBJECT_TYPE_INFORMATION, ObjectNameInformation, OBJECT_NAME_INFORMATION};
use winapi::um::memoryapi::*;
use winapi::um::processthreadsapi::*;
use winapi::um::winnt::{ MEM_COMMIT, MEM_RELEASE, PAGE_READWRITE };
use winapi::shared::ntdef::{NT_SUCCESS, UNICODE_STRING, HANDLE};
use winapi::shared::ntstatus::{STATUS_BUFFER_TOO_SMALL, STATUS_INFO_LENGTH_MISMATCH};
use winapi::um::memoryapi::{VirtualAlloc, VirtualFree};
use std::ffi::CString;
use winapi::um::winnt::{FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_ATTRIBUTE_NORMAL, GENERIC_READ, GENERIC_WRITE};
use winapi::um::fileapi::{OPEN_EXISTING, CreateFileA, BY_HANDLE_FILE_INFORMATION, FILE_ID_BOTH_DIR_INFO, GetFileInformationByHandle};
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::psapi::{EnumProcesses, EnumProcessModulesEx, GetModuleBaseNameA};

const SYSTEM_HANDLE_INFORMATION_CLASS: u32 = 16;

fn valloc(size: usize) -> *mut winapi::ctypes::c_void {
    unsafe {
        VirtualAlloc(std::ptr::null_mut(), size, MEM_COMMIT, PAGE_READWRITE)
    }
}

fn get_process_name(process_id: u32) -> Option<String> {
    let handle = unsafe { OpenProcess(0x0410, 0, process_id) };
    if handle.is_null() {
        return None;
    }

    let mut buffer = vec![0u8; 1024];
    let ret = unsafe {
        GetModuleBaseNameA(
            handle,
            ptr::null_mut(),
            buffer.as_mut_ptr() as *mut i8,
            buffer.len() as u32,
        )
    };

    unsafe { CloseHandle(handle) };

    if ret > 0 {
        Some(String::from_utf8_lossy(&buffer[..ret as usize]).to_string())
    } else {
        None
    }
}

fn get_handle_info(handle: HANDLE) -> Option<String> {
    let mut return_length: u32 = 0;

    // 初期バッファサイズを設定
    let initial_size = 1024;
    let mut buffer = valloc(initial_size);

    let status = loop {
        let status = unsafe {
            NtQueryObject(
                handle,
                ObjectNameInformation,
                buffer,
                initial_size as u32,
                &mut return_length,
            )
        };

        if status == STATUS_BUFFER_TOO_SMALL || status == STATUS_INFO_LENGTH_MISMATCH {
            unsafe { VirtualFree(buffer, 0, MEM_RELEASE) };
            buffer = valloc(return_length as usize);
            continue;
        }

        break status;
    };

    if !NT_SUCCESS(status) {
        eprintln!("Failed to query system information: {}", status);
        return None;
    }

    // OBJECT_NAME_INFORMATION 構造体を取得
    let name_info = unsafe { &*(buffer as *const OBJECT_NAME_INFORMATION) };
    
    if name_info.Name.Length == 0 {
        return None;
    }

    let name_slice = unsafe {
        std::slice::from_raw_parts(
            name_info.Name.Buffer,
            (name_info.Name.Length / 2) as usize,
        )
    };
    
    Some(String::from_utf16_lossy(name_slice))
}

fn main() {
    let file_path = CString::new("C:\\Users\\ytani\\git\\blog\\_posts\\2025-02-14-yapps.md").unwrap();
    let file_handle: HANDLE = unsafe {
        CreateFileA(
            file_path.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            ptr::null_mut(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            ptr::null_mut(),
        )
    };

    if file_handle == INVALID_HANDLE_VALUE {
        eprintln!("Failed to open file.");
        return;
    }

    let mut buffer = valloc(32);
    let mut size_returned = 32;

    let status = loop {
        println!("before size: {}", size_returned);
        let status = unsafe {
            NtQuerySystemInformation(
                SystemExtendedHandleInformation,
                buffer,
                size_returned,
                &mut size_returned,
            )
        };

        println!("status: {}", status);
        if status == STATUS_BUFFER_TOO_SMALL || status == STATUS_INFO_LENGTH_MISMATCH {
            unsafe { VirtualFree(buffer, 0, MEM_RELEASE) };
            buffer = valloc(size_returned as usize);
            println!("new size: {}", size_returned);
        }
        else {
            break status;
        }
    };
    if !NT_SUCCESS(status) {
        eprintln!("Failed to query system information.");
        return;
    }

    let handle_info = unsafe { &*(buffer as *const SYSTEM_HANDLE_INFORMATION_EX) };
    let mut target_handle: HANDLE = ptr::null_mut();
    let mut before_pid = 0;
    for i in 0..handle_info.NumberOfHandles {
        let entry = unsafe { &*(handle_info.Handles.as_ptr().add(i as usize) as *const SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX) };

        if entry.UniqueProcessId as u32 == std::process::id() {
            continue;
        }

        if entry.ObjectTypeIndex != 42 {
            continue;
        }

        if before_pid != entry.UniqueProcessId {
            if !target_handle.is_null() {
                unsafe { CloseHandle(target_handle) };
            }
            target_handle = unsafe {
                OpenProcess(0x0410, 0, entry.UniqueProcessId as u32)
            };
        }
        before_pid = entry.UniqueProcessId;

        if !target_handle.is_null() {
            println!("pid: {}", entry.UniqueProcessId);
            if let Some(handle_info) = get_handle_info(entry.HandleValue as HANDLE) {
                println!("pid: {} filepath: {}", entry.UniqueProcessId, handle_info);
                if handle_info == file_path.to_str().unwrap() {
                    if let Some(process_name) = get_process_name(entry.UniqueProcessId as u32) {
                        println!("Process ID: {} is holding the file. Process Name: {}", entry.UniqueProcessId, process_name);
                    }
                }
            }
        }
    }

    unsafe { CloseHandle(file_handle) };
}
