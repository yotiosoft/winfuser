use ntapi::ntobapi::{ OBJECT_TYPE_INFORMATION, OBJECT_NAME_INFORMATION };
use winapi::um::handleapi::{ CloseHandle, DuplicateHandle };
use ntapi::ntexapi::{ NtQuerySystemInformation, SYSTEM_HANDLE_INFORMATION_EX, SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX };
use std::ptr;
use ntapi::ntobapi::NtQueryObject;
use winapi::um::memoryapi::*;
use winapi::um::processthreadsapi::*;
use winapi::um::winnt::{ MEM_COMMIT, MEM_RELEASE, PAGE_READWRITE, DUPLICATE_SAME_ACCESS };
use winapi::shared::ntdef::{ NT_SUCCESS, HANDLE };
use winapi::shared::ntstatus::{ STATUS_BUFFER_TOO_SMALL, STATUS_INFO_LENGTH_MISMATCH };
use winapi::um::memoryapi::{ VirtualAlloc, VirtualFree };
use winapi::um::fileapi::{ QueryDosDeviceW, GetFileType };
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::psapi::GetModuleBaseNameA;
use winapi::shared::minwindef::{MAX_PATH, FALSE};

pub type Status = i32;
pub type NotOpenedHandle = u64;

pub struct Buffer {
    pub buffer: *mut winapi::ctypes::c_void,
    pub size: usize,
}
impl Drop for Buffer {
    fn drop(&mut self) {
        vfree(self.buffer, self.size);
    }
}

pub struct Handle {
    pub handle: HANDLE,
}
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.handle); }
    }
}
impl Handle {
    pub fn new(handle: HANDLE) -> Handle {
        Handle { handle: handle}
    }
}

// SYSTEM_HANDLE_INFORMATION_EX
pub struct WfSystemHandleInformationEx {
    pub number_of_handles: usize,
    pub reserved: usize,
    pub handles: Vec<SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX>,
}

pub fn query_system_information(system_information_class: u32) -> Result<Buffer, Status> {
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

pub fn buffer_to_system_handle_information_ex(buffer: Buffer) -> WfSystemHandleInformationEx {
    let system_handle_information_ex = unsafe { &*(buffer.buffer as *const SYSTEM_HANDLE_INFORMATION_EX) };
    let number_of_handles = system_handle_information_ex.NumberOfHandles as usize;
    let reserved = system_handle_information_ex.Reserved as usize;
    let handles = unsafe {
        std::slice::from_raw_parts(
            system_handle_information_ex.Handles.as_ptr(),
            number_of_handles,
        )
    }
    .to_vec();

    WfSystemHandleInformationEx {
        number_of_handles,
        reserved,
        handles,
    }
}

pub fn buffer_to_object_type_information(buffer: Buffer) -> OBJECT_TYPE_INFORMATION {
    unsafe { *(buffer.buffer as *const OBJECT_TYPE_INFORMATION) }
}

pub fn buffer_to_name_string(buffer: Buffer) -> String {
    let name_info = unsafe { &*(buffer.buffer as *const OBJECT_NAME_INFORMATION) };
    let name_slice = unsafe {
        std::slice::from_raw_parts(
            name_info.Name.Buffer,
            (name_info.Name.Length / 2) as usize,
        )
    };
    String::from_utf16_lossy(name_slice)
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

pub fn nt_query_object(handle: &Handle, object_information_class: u32) -> Result<Buffer, Status> {
    let mut size_returned = 1024;
    let mut buffer = valloc(size_returned as usize);

    let status = loop {
        let before_length = size_returned;
        let status = unsafe {
            NtQueryObject(
                handle.handle,
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

pub fn get_module_base_name(handle: Handle) -> Option<String> {
    let mut buffer = vec![0u8; 1024];
    let ret = unsafe {
        GetModuleBaseNameA(
            handle.handle,
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

pub fn duplicate_handle(object_handle: NotOpenedHandle, target_process_handle: Handle) -> Option<Handle> {
    let mut duplicated_handle: HANDLE = ptr::null_mut();
    let object_handle = object_handle as HANDLE;
    let target_process_handle = target_process_handle.handle;
    let duplicate_status = unsafe {
        DuplicateHandle(
            target_process_handle,
            object_handle,
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
    Some(Handle::new(duplicated_handle))
}

pub fn open_process(process_id: &u32, access: u32) -> Handle {
    let raw_handle  = unsafe { OpenProcess(access, 0, *process_id) };
    Handle::new(raw_handle)
}

pub fn get_file_type(handle: &Handle) -> u32 {
    unsafe { GetFileType(handle.handle) }
}

fn valloc(size: usize) -> *mut winapi::ctypes::c_void {
    unsafe { VirtualAlloc(ptr::null_mut(), size, MEM_COMMIT, PAGE_READWRITE) }
}

fn vfree(buffer: *mut winapi::ctypes::c_void, size: usize) {
    unsafe { VirtualFree(buffer, size, MEM_RELEASE); }
}
