extern crate winapi;
extern crate ntapi;

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use ntapi::ntobapi::{ ObjectTypeInformation, ObjectNameInformation };
use ntapi::ntexapi::SystemExtendedHandleInformation;
use winapi::um::winnt::PROCESS_DUP_HANDLE;
use winapi::um::winbase::FILE_TYPE_DISK;
use std::collections::HashMap;

mod api;

const NETWORK_DEVICE_PREFIX: &str = "\\Device\\Mup";

type Pid = u32;
type FileToPidsMap = HashMap<String, Vec<Pid>>;

fn get_process_name(process_id: u32) -> Option<String> {
    let handle = api::open_process(process_id, 0x0410);
    if handle.handle.is_null() {
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

fn get_dos_device_path(device_path: &str) -> (String, bool) {
    for drive_letter in 'A'..='Z' {
        if let Some(dos_path) = query_dos_device_path(drive_letter) {
            let dos_path_trimmed = dos_path.trim();
            let device_path_trimmed = device_path.trim();
            if device_path_trimmed.trim().starts_with(dos_path_trimmed) {
                return (device_path.replace(&dos_path, &format!("{}:", drive_letter)), true);
            }
        }
    }
    (device_path.to_string(), false)
}

fn get_handle_type(handle: &api::Handle) -> Result<Option<String>, api::Status> {
    let buffer = api::nt_query_object(handle, ObjectTypeInformation)?;
    let type_info = api::buffer_to_object_type_information(buffer);
    if type_info.TypeName.Length == 0 {
        return Ok(None);
    }

    let name_buf = api::read_process_memory_u16(type_info.TypeName.Buffer as *const winapi::ctypes::c_void, type_info.TypeName.Length as usize);

    let type_name = String::from_utf16_lossy(&name_buf);

    Ok(Some(type_name))
}

fn get_handle_filepath(handle: &api::Handle) -> Result<Option<String>, api::Status> {
    let buffer = api::nt_query_object(handle, ObjectNameInformation)?;
    let device_path = api::buffer_to_name_string(buffer);
    if device_path.len() == 0 {
        return Ok(None);
    }
    let filepath = {
        let (filepath, on_disk) = get_dos_device_path(&device_path);
        if on_disk {
            filepath
        }
        else {
            if filepath.starts_with(NETWORK_DEVICE_PREFIX) {
                filepath[NETWORK_DEVICE_PREFIX.len()..].to_string()
            }
            else {
                filepath
            }
        }
    };
    Ok(Some(filepath))
}

fn entry_to_filepath(pid: u32, handle_value: api::NotOpenedHandle) -> Result<Option<api::Handle>, api::Status> {
    let duplicated_handle = {
        let target_process_handle = api::open_process(pid, PROCESS_DUP_HANDLE);
        if target_process_handle.handle.is_null() {
            None
        }
        else {
            api::duplicate_handle(handle_value, target_process_handle)
        }
    };
    if duplicated_handle.is_none() {
        return Ok(None);
    }
    let duplicated_handle = duplicated_handle.unwrap();

    // get handle type
    let handle_type = get_handle_type(&duplicated_handle);
    match handle_type {
        Ok(Some(handle_type)) => {
            if !handle_type.starts_with("File") {
                return Ok(None);
            }
        },
        Ok(None) => {
            return Ok(None);
        },
        Err(e) => {
            return Err(e);
        }
    }

    // get file type
    let file_type = api::get_file_type(&duplicated_handle);
    if file_type != FILE_TYPE_DISK {
        return Ok(None);
    }

    Ok(Some(duplicated_handle))
}

fn query_file_to_pids_map() -> FileToPidsMap {
    let buffer = api::query_system_information(SystemExtendedHandleInformation).map_err(|e| eprintln!("Failed to query system information: {}", e)).unwrap();
    let handle_info = api::buffer_to_system_handle_information_ex(buffer);

    let mut proc_opened_files: FileToPidsMap = HashMap::new();
    for entry in handle_info.handles.iter() {
        if entry.UniqueProcessId as u32 == std::process::id() {
            continue;
        }

        let pid = entry.UniqueProcessId as u32;
        let handle_value = entry.HandleValue as api::NotOpenedHandle;
        let duplicated_handle = entry_to_filepath(pid, handle_value).map_err(|e| eprintln!("Error: {:?}", e)).unwrap();
        if duplicated_handle.is_none() {
            continue;
        }
        let duplicated_handle = duplicated_handle.unwrap();

        if let Ok(Some(filepath)) = get_handle_filepath(&duplicated_handle) {
            proc_opened_files.entry(filepath).or_insert(Vec::new()).push(pid);
        }
    }

    proc_opened_files
}

fn search_filepath_in_map(file_path: &str, proc_opened_files: &FileToPidsMap) -> Option<Vec<Pid>> {
    if proc_opened_files.contains_key(file_path) {
        Some(proc_opened_files.get(file_path).unwrap().clone())
    }
    else {
        None
    }
}

fn get_files_list_by_pid(pid: Pid, proc_opened_files: &FileToPidsMap) -> Vec<String> {
    let mut files = Vec::new();
    for (elem_filepath, elem_pids) in proc_opened_files.iter() {
        if elem_pids.iter().any(|&elem_pid| elem_pid == pid) {
            files.push(elem_filepath.clone());
        }
    }
    files
}

fn main() {
    // target filepath
    let file_path = "C:\\Users\\ytani\\git";
    println!("Target file path: {}", file_path);

    let proc_opened_files = query_file_to_pids_map();
    let pids = search_filepath_in_map(file_path, &proc_opened_files);
    
    if let Some(pids) = pids {
        for pid in pids.iter() {
            if let Some(process_name) = get_process_name(*pid) {
                println!("Process ID: {} is holding the file. Process Name: {}", pid, process_name);
            }
        }
    }
    else {
        println!("No process is holding the file.");
    }

    let query_pid = 15368;
    let files = get_files_list_by_pid(query_pid, &proc_opened_files);
    if files.len() > 0 {
        println!("Files opened by process ID: {}", query_pid);
        for file in files.iter() {
            println!("{}", file);
        }
    }
    else {
        println!("No file is opened by this process.");
    }
}
