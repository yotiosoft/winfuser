extern crate winapi;
extern crate ntapi;

use winapi::um::handleapi::{INVALID_HANDLE_VALUE, CloseHandle, DuplicateHandle};
use ntapi::ntexapi::{NtQuerySystemInformation, SystemObjectInformation, SYSTEM_HANDLE_INFORMATION_EX, SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX};
use std::ptr;
use std::mem;
use ntapi::ntexapi::{SYSTEM_HANDLE_INFORMATION, SYSTEM_HANDLE_TABLE_ENTRY_INFO, SystemExtendedHandleInformation};
use ntapi::ntobapi::{OBJECT_BASIC_INFORMATION, NtQueryObject, ObjectBasicInformation, ObjectTypeInformation, OBJECT_TYPE_INFORMATION, ObjectNameInformation, OBJECT_NAME_INFORMATION};
use winapi::um::memoryapi::*;
use winapi::um::processthreadsapi::*;
use winapi::um::winnt::{ MEM_COMMIT, MEM_RELEASE, PAGE_READWRITE, GENERIC_READ, GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_ATTRIBUTE_NORMAL, DUPLICATE_SAME_ACCESS, PROCESS_DUP_HANDLE };
use winapi::um::memoryapi::{ FILE_MAP_WRITE };
use winapi::shared::ntdef::{NT_SUCCESS, UNICODE_STRING, HANDLE};
use winapi::shared::ntstatus::{STATUS_BUFFER_TOO_SMALL, STATUS_INFO_LENGTH_MISMATCH};
use winapi::um::memoryapi::{VirtualAlloc, VirtualFree};
use std::ffi::CString;
use std::fs::File;
use winapi::um::fileapi::{OPEN_EXISTING, CreateFileA, CreateDirectoryA, BY_HANDLE_FILE_INFORMATION, FILE_ID_BOTH_DIR_INFO, GetFileInformationByHandle, QueryDosDeviceW};
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::psapi::{EnumProcesses, EnumProcessModulesEx, GetModuleBaseNameA};
use winapi::shared::minwindef::{MAX_PATH, FALSE};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

const SYSTEM_HANDLE_INFORMATION_CLASS: u32 = 16;
type STATUS = i32;

struct Buffer {
    buffer: *mut winapi::ctypes::c_void,
    size: usize,
}

fn query_system_information(system_information_class: u32) -> Result<Buffer, STATUS> {
    let mut buffer = valloc(32);
    let mut size_returned = 32;

    let status = loop {
        let before_length = size_returned;
        let status = unsafe {
            NtQuerySystemInformation(
                system_information_class,
                buffer,
                size_returned,
                &mut size_returned,
            )
        };

        if status == STATUS_BUFFER_TOO_SMALL || status == STATUS_INFO_LENGTH_MISMATCH {
            vfree(buffer, before_length as usize);
            buffer = valloc(size_returned as usize);
        } else {
            break status;
        }
    };

    if !NT_SUCCESS(status) {
        eprintln!("Failed to query system information.");
        vfree(buffer, size_returned as usize);
        return Err(status);
    }

    Ok(Buffer { buffer, size: size_returned as usize })
}

fn nt_query_object(handle: HANDLE, object_information_class: u32) -> Result<Buffer, STATUS> {
    let mut size_returned = 1024;
    let mut buffer = valloc(size_returned as usize);

    let status = loop {
        let before_length = size_returned;
        let status = unsafe {
            NtQueryObject(
                handle,
                object_information_class,
                buffer,
                size_returned,
                &mut size_returned,
            )
        };

        if status == STATUS_BUFFER_TOO_SMALL || status == STATUS_INFO_LENGTH_MISMATCH {
            vfree(buffer, before_length as usize);
            buffer = valloc(size_returned as usize);
        } else {
            break status;
        }
    };

    if !NT_SUCCESS(status) {
        vfree(buffer, size_returned as usize);
        return Err(status);
    }

    Ok(Buffer { buffer, size: size_returned as usize })
}

fn valloc(size: usize) -> *mut winapi::ctypes::c_void {
    unsafe { VirtualAlloc(ptr::null_mut(), size, MEM_COMMIT, PAGE_READWRITE) }
}

fn vfree(buffer: *mut winapi::ctypes::c_void, size: usize) {
    unsafe { VirtualFree(buffer, size, MEM_RELEASE); }
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

fn get_handle_type(handle: HANDLE) -> Result<Option<String>, STATUS> {
    let mut buffer = nt_query_object(handle, ObjectTypeInformation)?;
    let mut return_length: u32 = buffer.size as u32;
    let buffer = buffer.buffer;

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
        vfree(buffer, return_length as usize);
        return Ok(None);
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
    vfree(buffer, return_length as usize);

    Ok(Some(type_name))
}

fn get_handle_info(handle: HANDLE) -> Result<Option<String>, STATUS> {
    let buffer = nt_query_object(handle, ObjectNameInformation)?;
    let return_length = buffer.size;
    let buffer = buffer.buffer;

    let name_info = unsafe { &*(buffer as *const OBJECT_NAME_INFORMATION) };
    if name_info.Name.Length == 0 {
        eprintln!("name length is 0");
        vfree(buffer, return_length as usize);
        return Ok(None);
    }

    let name_slice = unsafe {
        std::slice::from_raw_parts(
            name_info.Name.Buffer,
            (name_info.Name.Length / 2) as usize,
        )
    };

    let device_path = String::from_utf16_lossy(name_slice);

    vfree(buffer, return_length as usize);
    Ok(Some(get_dos_device_path(&device_path)))
}

fn main() {
    // target filepath
    let file_path = "C:\\Users\\ytani\\git\\blog\\_posts";
    println!("Target file path: {}", file_path);
    let file_path = CString::new(file_path).unwrap();

    let buffer = query_system_information(SystemExtendedHandleInformation).map_err(|e| eprintln!("Failed to query system information: {}", e)).unwrap();
    let size_returned = buffer.size;
    let buffer = buffer.buffer;

    let handle_info = unsafe { &*(buffer as *const SYSTEM_HANDLE_INFORMATION_EX) };
    for i in 0..handle_info.NumberOfHandles {
        let entry = unsafe { &*(handle_info.Handles.as_ptr().add(i as usize) as *const SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX) };

        if entry.UniqueProcessId as u32 == std::process::id() {
            continue;
        }

        if entry.ObjectTypeIndex != 42 {
            continue;
        }

        // get handle type
        let handle_type = get_handle_type(entry.HandleValue as HANDLE);
        if let Ok(Some(handle_type)) = handle_type {
            if !handle_type.starts_with("File") {
                continue;
            }
        }
        else {
            continue;
        }

        let target_process_handle = unsafe {
            OpenProcess(PROCESS_DUP_HANDLE, 0, entry.UniqueProcessId as u32)
        };
        
        let mut duplicated_handle: HANDLE = ptr::null_mut();
        let duplicate_status = unsafe {
            DuplicateHandle(
                target_process_handle,
                entry.HandleValue as HANDLE,
                GetCurrentProcess(),
                &mut duplicated_handle,
                0,
                FALSE,
                DUPLICATE_SAME_ACCESS,
            )
        };

        unsafe { CloseHandle(target_process_handle) };

        if duplicate_status == FALSE {
            //println!("Failed to duplicate handle");
            continue;
        }
        
        if let Ok(Some(handle_info)) = get_handle_info(duplicated_handle) {
            println!("pid: {} filepath: {}", entry.UniqueProcessId, handle_info);
            if handle_info == file_path.to_str().unwrap() {
                if let Some(process_name) = get_process_name(entry.UniqueProcessId as u32) {
                    println!("Process ID: {} is holding the file. Process Name: {}", entry.UniqueProcessId, process_name);
                }
            }
        }

        unsafe { CloseHandle(duplicated_handle) };
    }

    vfree(buffer, size_returned as usize);
}
