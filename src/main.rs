extern crate winapi;
extern crate ntapi;

use winapi::um::handleapi::{INVALID_HANDLE_VALUE, CloseHandle};
use ntapi::ntexapi::{NtQuerySystemInformation, SystemObjectInformation, SYSTEM_HANDLE_INFORMATION_EX, SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX};
use std::ptr;
use std::mem;
use ntapi::ntexapi::{SYSTEM_HANDLE_INFORMATION, SYSTEM_HANDLE_TABLE_ENTRY_INFO, SystemExtendedHandleInformation};
use ntapi::ntobapi::{OBJECT_BASIC_INFORMATION, NtQueryObject, ObjectBasicInformation, ObjectTypeInformation, OBJECT_TYPE_INFORMATION, ObjectNameInformation, OBJECT_NAME_INFORMATION};
use winapi::um::memoryapi::*;
use winapi::um::processthreadsapi::*;
use winapi::um::winnt::{ MEM_COMMIT, MEM_RELEASE, PAGE_READWRITE, GENERIC_READ, GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_ATTRIBUTE_NORMAL };
use winapi::um::memoryapi::{ FILE_MAP_WRITE };
use winapi::shared::ntdef::{NT_SUCCESS, UNICODE_STRING, HANDLE};
use winapi::shared::ntstatus::{STATUS_BUFFER_TOO_SMALL, STATUS_INFO_LENGTH_MISMATCH};
use winapi::um::memoryapi::{VirtualAlloc, VirtualFree};
use std::ffi::CString;
use std::fs::File;
use winapi::um::fileapi::{OPEN_EXISTING, CreateFileA, BY_HANDLE_FILE_INFORMATION, FILE_ID_BOTH_DIR_INFO, GetFileInformationByHandle, QueryDosDeviceW};
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::psapi::{EnumProcesses, EnumProcessModulesEx, GetModuleBaseNameA};
use winapi::shared::minwindef::MAX_PATH;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

const SYSTEM_HANDLE_INFORMATION_CLASS: u32 = 16;

fn valloc(size: usize) -> *mut winapi::ctypes::c_void {
    unsafe { VirtualAlloc(ptr::null_mut(), size, MEM_COMMIT, PAGE_READWRITE) }
}

fn vfree(buffer: *mut winapi::ctypes::c_void) -> i32 {
    unsafe { VirtualFree(buffer, 0, MEM_RELEASE) }
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

fn query_dos_device_path(drive_letter: char) -> Option<String> {
    let drive_path = format!("{}:", drive_letter);
    let mut buffer: Vec<u16> = vec![0; MAX_PATH];
    let device_name_u16 = OsStr::new(drive_path.as_str()).encode_wide().chain(Some(0).into_iter()).collect::<Vec<_>>();
    let device_name_u16 = device_name_u16.as_ptr();

    let result = unsafe {
        QueryDosDeviceW(
            device_name_u16,
            buffer.as_mut_ptr(),
            buffer.len() as u32,
        )
    };

    if result == 0 {
        return None;
    }

    let mut path = String::from_utf16_lossy(&buffer[..result as usize]);

    // 末尾のヌル文字（0）を取り除く
    if let Some(null_pos) = path.find('\0') {
        path.truncate(null_pos);
    }

    Some(path)
}

fn get_dos_device_path(device_path: &str) -> String {
    for drive_letter in 'A'..='Z' {
        if let Some(dos_path) = query_dos_device_path(drive_letter) {
            let dos_path_trimmed = dos_path.trim();
            let device_path_trimmed = device_path.trim();
            if device_path_trimmed.trim().starts_with(dos_path_trimmed) {
                return device_path.replace(&dos_path, &format!("{}:", drive_letter));
            }
        }
    }
    device_path.to_string()
}

fn get_handle_type(handle: HANDLE) -> Option<String> {
    let initial_size = 1024;
    let mut return_length: u32 = initial_size;
    let mut buffer = valloc(return_length as usize);

    let status = loop {
        let status = unsafe {
            NtQueryObject(
                handle,
                ObjectTypeInformation,
                buffer,
                return_length,
                &mut return_length,
            )
        };

        if status == STATUS_BUFFER_TOO_SMALL || status == STATUS_INFO_LENGTH_MISMATCH {
            vfree(buffer);
            buffer = valloc(return_length as usize);
            continue;
        }

        break status;
    };

    if !NT_SUCCESS(status) {
        //eprintln!("Failed to query system information: {}", status);
        return None;
    }

    let type_info = unsafe { &*(buffer as *const OBJECT_TYPE_INFORMATION) };
    let type_info_vec = vec![0u8; return_length as usize];
    unsafe {
        ReadProcessMemory(
            GetCurrentProcess(),
            type_info as *const OBJECT_TYPE_INFORMATION as *const winapi::ctypes::c_void,
            type_info_vec.as_ptr() as *mut winapi::ctypes::c_void,
            return_length as usize,
            ptr::null_mut(),
        );
    }
    if type_info.TypeName.Length == 0 {
        vfree(buffer);
        return None;
    }

    let name_buf = vec![0u16; type_info.TypeName.Length as usize];
    unsafe {
        ReadProcessMemory(
            GetCurrentProcess(),
            type_info.TypeName.Buffer as *const winapi::ctypes::c_void,
            name_buf.as_ptr() as *mut winapi::ctypes::c_void,
            type_info.TypeName.Length as usize,
            ptr::null_mut(),
        );
    }

    let type_name = String::from_utf16_lossy(&name_buf);
    vfree(buffer);

    Some(type_name)
}

fn get_handle_info(handle: HANDLE) -> Option<String> {
    let mut return_length: u32 = 0;
    let initial_size = 1024;
    let mut buffer = valloc(initial_size);

    println!("handle = {:?}", handle);

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
            vfree(buffer);
            buffer = valloc(return_length as usize);
            continue;
        }

        break status;
    };

    if !NT_SUCCESS(status) {
        //eprintln!("Failed to query system information: {}", status);
        return None;
    }

    let name_info = unsafe { &*(buffer as *const OBJECT_NAME_INFORMATION) };
    if name_info.Name.Length == 0 {
        vfree(buffer);
        return None;
    }

    let name_slice = unsafe {
        std::slice::from_raw_parts(
            name_info.Name.Buffer,
            (name_info.Name.Length / 2) as usize,
        )
    };

    let device_path = String::from_utf16_lossy(name_slice);
    vfree(buffer);
    Some(get_dos_device_path(&device_path))
}

fn main() {
    let file_path = CString::new("C:\\Users\\ytani\\git\\blog\\_posts\\2025-01-13-new-site.md").unwrap();
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
            vfree(buffer);
            buffer = valloc(size_returned as usize);
            println!("new size: {}", size_returned);
        } else {
            break status;
        }
    };
    if !NT_SUCCESS(status) {
        eprintln!("Failed to query system information.");
        vfree(buffer);
        return;
    }

    let handle_info = unsafe { &*(buffer as *const SYSTEM_HANDLE_INFORMATION_EX) };
    let mut target_handle: HANDLE = ptr::null_mut();
    let mut before_pid = 0;
    println!("handle_info.NumberOfHandles = {}", handle_info.NumberOfHandles);
    for i in 0..handle_info.NumberOfHandles {
        let entry = unsafe { &*(handle_info.Handles.as_ptr().add(i as usize) as *const SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX) };

        if entry.UniqueProcessId as u32 == std::process::id() {
            continue;
        }

        // get handle type
        let handle_type = get_handle_type(entry.HandleValue as HANDLE);
        if let Some(handle_type) = handle_type {
            if !handle_type.starts_with("File") {
                continue;
            }
        }
        else {
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
    if !target_handle.is_null() {
        unsafe { CloseHandle(target_handle) };
    }

    unsafe { CloseHandle(file_handle) };

    vfree(buffer);
}
