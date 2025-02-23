use winapi::um::handleapi::{ CloseHandle, DuplicateHandle };
use ntapi::ntexapi::NtQuerySystemInformation;
use std::ptr;
use ntapi::ntobapi::NtQueryObject;
use winapi::um::memoryapi::*;
use winapi::um::processthreadsapi::*;
use winapi::um::winnt::{ MEM_COMMIT, MEM_RELEASE, PAGE_READWRITE, DUPLICATE_SAME_ACCESS };
use winapi::shared::ntdef::{ NT_SUCCESS, HANDLE };
use winapi::shared::ntstatus::{ STATUS_BUFFER_TOO_SMALL, STATUS_INFO_LENGTH_MISMATCH };
use winapi::um::memoryapi::{ VirtualAlloc, VirtualFree };
use winapi::um::fileapi::QueryDosDeviceW;
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::psapi::GetModuleBaseNameA;
use winapi::shared::minwindef::{MAX_PATH, FALSE};
pub type STATUS = i32;

pub struct Buffer {
    pub buffer: *mut winapi::ctypes::c_void,
    pub size: usize,
}

pub fn query_system_information(system_information_class: u32) -> Result<Buffer, STATUS> {
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

pub fn query_dos_device(device_name_u16: *const u16) -> Option<String> {
    let mut buffer: Vec<u16> = vec![0; MAX_PATH];
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

    let path = String::from_utf16_lossy(&buffer[..result as usize]);

    Some(path)
}

pub fn nt_query_object(handle: HANDLE, object_information_class: u32) -> Result<Buffer, STATUS> {
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

pub fn get_module_base_name(handle: HANDLE) -> Option<String> {
    let mut buffer = vec![0u8; 1024];
    let ret = unsafe {
        GetModuleBaseNameA(
            handle,
            ptr::null_mut(),
            buffer.as_mut_ptr() as *mut i8,
            buffer.len() as u32,
        )
    };

    if ret > 0 {
        Some(String::from_utf8_lossy(&buffer[..ret as usize]).to_string())
    } else {
        None
    }
}

pub fn read_process_memory_u16(address: *const winapi::ctypes::c_void, size: usize) -> Vec<u16> {
    let handle = unsafe { GetCurrentProcess() };
    let mut buffer = vec![0u16; size];
    unsafe {
        ReadProcessMemory(
            handle,
            address,
            buffer.as_mut_ptr() as *mut winapi::ctypes::c_void,
            size,
            ptr::null_mut(),
        );
    }
    buffer
}

pub fn duplicate_handle(handle: HANDLE, target_process_handle: HANDLE) -> Option<HANDLE> {
    let mut duplicated_handle: HANDLE = ptr::null_mut();
    let duplicate_status = unsafe {
        DuplicateHandle(
            target_process_handle,
            handle,
            GetCurrentProcess(),
            &mut duplicated_handle,
            0,
            FALSE,
            DUPLICATE_SAME_ACCESS,
        )
    };

    if duplicate_status == FALSE {
        return None;
    }

    Some(duplicated_handle)
}

pub fn open_process(process_id: u32, access: u32) -> HANDLE {
    unsafe { OpenProcess(access, 0, process_id) }
}

pub fn close_handle(handle: HANDLE) {
    unsafe { CloseHandle(handle) };
}

pub fn valloc(size: usize) -> *mut winapi::ctypes::c_void {
    unsafe { VirtualAlloc(ptr::null_mut(), size, MEM_COMMIT, PAGE_READWRITE) }
}

pub fn vfree(buffer: *mut winapi::ctypes::c_void, size: usize) {
    unsafe { VirtualFree(buffer, size, MEM_RELEASE); }
}
