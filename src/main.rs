extern crate winapi;
extern crate ntapi;

use winapi::um::handleapi::{INVALID_HANDLE_VALUE, CloseHandle};
use ntapi::ntexapi::{NtQuerySystemInformation, SystemObjectInformation};
use std::ptr;
use std::mem;
use ntapi::ntexapi::{SYSTEM_HANDLE_INFORMATION, SYSTEM_HANDLE_TABLE_ENTRY_INFO};
use ntapi::ntobapi::{OBJECT_BASIC_INFORMATION, NtQueryObject, ObjectBasicInformation, ObjectTypesInformation, OBJECT_TYPE_INFORMATION};
use winapi::um::memoryapi::*;
use winapi::um::processthreadsapi::*;
use winapi::um::winnt::{ MEM_COMMIT, MEM_RELEASE, PAGE_READWRITE };
use winapi::shared::ntdef::{NT_SUCCESS, UNICODE_STRING, HANDLE};
use winapi::shared::ntstatus::{STATUS_BUFFER_TOO_SMALL, STATUS_INFO_LENGTH_MISMATCH};
use winapi::um::memoryapi::{VirtualAlloc, VirtualFree};
use std::ffi::CString;
use winapi::um::winnt::{FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_ATTRIBUTE_NORMAL, GENERIC_READ, GENERIC_WRITE};
use winapi::um::fileapi::{OPEN_EXISTING, CreateFileA};
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::psapi::{EnumProcesses, EnumProcessModulesEx, GetModuleBaseNameA};

const SYSTEM_HANDLE_INFORMATION_CLASS: u32 = 16;

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

    unsafe { winapi::um::handleapi::CloseHandle(handle) };

    if ret > 0 {
        Some(String::from_utf8_lossy(&buffer[..ret as usize]).to_string())
    } else {
        None
    }
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

    let mut buffer = vec![0u8; 32];
    let mut size_returned = 0;

    let status = unsafe {
        NtQuerySystemInformation(
            SYSTEM_HANDLE_INFORMATION_CLASS,
            buffer.as_mut_ptr() as *mut _,
            buffer.len() as u32,
            &mut size_returned,
        )
    };

    if (!NT_SUCCESS(status) && status != STATUS_INFO_LENGTH_MISMATCH) || size_returned == 0 {
        eprintln!("Failed to query system information.");
        return;
    }

    let mut buffer = vec![0u8; size_returned as usize];
    let status = unsafe {
        NtQuerySystemInformation(
            SYSTEM_HANDLE_INFORMATION_CLASS,
            buffer.as_mut_ptr() as *mut _,
            buffer.len() as u32,
            &mut size_returned,
        )
    };

    if !NT_SUCCESS(status) {
        eprintln!("Failed to query system information.");
        return;
    }

    let handle_info = unsafe { &*(buffer.as_ptr() as *const SYSTEM_HANDLE_INFORMATION) };
    for i in 0..handle_info.NumberOfHandles {
        let entry = unsafe { &*(handle_info.Handles.as_ptr().add(i as usize) as *const SYSTEM_HANDLE_TABLE_ENTRY_INFO) };
        if entry.HandleValue == 0 {
            continue;
        }
        println!("Handle: {}, Process ID: {}, Object: {:p}", entry.HandleValue, entry.UniqueProcessId, entry.Object);
        println!("File Handle: {:p}", file_handle);
        if entry.Object == file_handle {
            if let Some(process_name) = get_process_name(entry.UniqueProcessId as u32) {
                println!("Process ID: {} is holding the file. Process Name: {}", entry.UniqueProcessId, process_name);
            }
        }
    }

    unsafe { winapi::um::handleapi::CloseHandle(file_handle) };
}
