extern crate winapi;
extern crate ntapi;

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ffi::CString;
use api::duplicate_handle;
use winapi::shared::ntdef::HANDLE;
use ntapi::ntobapi::{ObjectTypeInformation, OBJECT_TYPE_INFORMATION, ObjectNameInformation, OBJECT_NAME_INFORMATION};
use ntapi::ntexapi::SystemExtendedHandleInformation;
use ntapi::ntexapi::{SYSTEM_HANDLE_INFORMATION_EX, SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX};
use winapi::um::winnt::PROCESS_DUP_HANDLE;
use tokio;
use tokio::time::timeout;
use tokio::sync::oneshot;
use std::time::Duration;

mod api;

fn get_process_name(process_id: u32) -> Option<String> {
    let handle = api::open_process(process_id, 0x0410);
    if handle.is_null() {
        return None;
    }
    api::get_module_base_name(handle)
}

fn query_dos_device_path(drive_letter: char) -> Option<String> {
    let drive_path = format!("{}:", drive_letter);
    let device_name_u16 = OsStr::new(drive_path.as_str()).encode_wide().chain(Some(0).into_iter()).collect::<Vec<_>>();
    let device_name_u16 = device_name_u16.as_ptr();

    let mut path = api::query_dos_device(device_name_u16)?;

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

fn get_handle_type(handle: HANDLE) -> Result<Option<String>, api::STATUS> {
    let buffer = api::nt_query_object(handle, ObjectTypeInformation)?;
    let return_length: u32 = buffer.size as u32;
    let buffer = buffer.buffer;

    let type_info = unsafe { &*(buffer as *const OBJECT_TYPE_INFORMATION) };
    if type_info.TypeName.Length == 0 {
        api::vfree(buffer, return_length as usize);
        return Ok(None);
    }

    let name_buf = api::read_process_memory_u16(type_info.TypeName.Buffer as *const winapi::ctypes::c_void, type_info.TypeName.Length as usize);

    let type_name = String::from_utf16_lossy(&name_buf);
    api::vfree(buffer, return_length as usize);

    Ok(Some(type_name))
}

fn get_handle_info(handle: HANDLE) -> Result<Option<String>, api::STATUS> {
    let buffer = api::nt_query_object(handle, ObjectNameInformation)?;
    let return_length = buffer.size;
    let buffer = buffer.buffer;

    let name_info = unsafe { &*(buffer as *const OBJECT_NAME_INFORMATION) };
    if name_info.Name.Length == 0 {
        api::vfree(buffer, return_length as usize);
        return Ok(None);
    }

    let name_slice = unsafe {
        std::slice::from_raw_parts(
            name_info.Name.Buffer,
            (name_info.Name.Length / 2) as usize,
        )
    };

    let device_path = String::from_utf16_lossy(name_slice);

    api::vfree(buffer, return_length as usize);
    Ok(Some(get_dos_device_path(&device_path)))
}

fn is_filepath_same(handle: HANDLE, file_path: &String) -> bool {
    let handle_info = get_handle_info(handle);
    if let Ok(Some(handle_info)) = handle_info {
        if handle_info == *file_path {
            return true;
        }
    }
    false
}

fn handle_check(pid: u32, handle_value: u32, file_path: String) -> Result<(), api::STATUS> {
    let duplicated_handle = {
        let target_process_handle = api::open_process(pid as u32, PROCESS_DUP_HANDLE);
        let duplicated_handle = api::duplicate_handle(handle_value as HANDLE, target_process_handle);
        api::close_handle(target_process_handle);
        duplicated_handle
    };

    if duplicated_handle.is_none() {
        return Ok(());
    }
    let duplicated_handle = duplicated_handle.unwrap();

    // get handle type
    let handle_type = get_handle_type(duplicated_handle as HANDLE);
    match handle_type {
        Ok(Some(handle_type)) => {
            if !handle_type.starts_with("File") {
                return Ok(());
            }
        },
        Ok(None) => {
            return Ok(());
        },
        Err(e) => {
            return Err(e);
        }
    }

    if is_filepath_same(duplicated_handle, &file_path) {
        println!("pid: {} filepath: {}", pid, file_path);
        if let Some(process_name) = get_process_name(pid) {
            println!("Process ID: {} is holding the file. Process Name: {}", pid, process_name);
        }
    }

    api::close_handle(duplicated_handle);

    Ok(())
}

#[tokio::main]
async fn main() {
    // target filepath
    let file_path = "C:\\Users\\ytani\\git\\winfuser";
    println!("Target file path: {}", file_path);

    let buffer = api::query_system_information(SystemExtendedHandleInformation).map_err(|e| eprintln!("Failed to query system information: {}", e)).unwrap();
    let size_returned = buffer.size;
    let buffer = buffer.buffer;

    let handle_info = unsafe { &*(buffer as *const SYSTEM_HANDLE_INFORMATION_EX) };
    for i in 0..handle_info.NumberOfHandles {
        let entry = unsafe { &*(handle_info.Handles.as_ptr().add(i as usize) as *const SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX) };

        if entry.UniqueProcessId as u32 == std::process::id() {
            continue;
        }

        let (tx, rx) = oneshot::channel();

        let pid = entry.UniqueProcessId as u32;
        let handle = entry.HandleValue as u32;

        tokio::spawn(async move {
            let result = handle_check(pid, handle, file_path.to_string());
            tx.send(result).unwrap();
        });
        //timeout(Duration::from_secs(1), rx).await.map_err(|e| eprintln!("Timeout: {:?}", e)).map_err(|e| eprintln!("Timeout: {:?}", e)).unwrap_or(Ok(())).unwrap();
        let wait_process = timeout(Duration::from_secs(1), rx).await;
        match wait_process {
            Ok(Ok(Ok(()))) => {},
            Ok(Ok(Err(e))) => eprintln!("Error: {:?}", e),
            Ok(Err(e)) => eprintln!("Timeout: {:?}", e),
            Err(e) => eprintln!("Timeout: {:?}", e),
        }
    }

    api::vfree(buffer, size_returned as usize);
}
