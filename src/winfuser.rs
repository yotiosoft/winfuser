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

pub type Pid = u32;
pub type FileToPidsMap = HashMap<String, Vec<Pid>>;
pub struct WinFuserStruct {
    pub hashmap: FileToPidsMap,
}

impl WinFuserStruct {
    pub fn get() -> Result<Self, api::Status> {
        let mut hashmap = FileToPidsMap::new();
        let buffer = api::query_system_information(SystemExtendedHandleInformation)?;
        let handle_info = api::buffer_to_system_handle_information_ex(buffer);

        for entry in handle_info.handles.iter() {
            if entry.UniqueProcessId as u32 == std::process::id() {
                continue;
            }

            let pid = entry.UniqueProcessId as u32;
            let handle_value = entry.HandleValue as api::NotOpenedHandle;
            let duplicated_handle = entry_to_filepath(pid, handle_value)?;
            if duplicated_handle.is_none() {
                continue;
            }
            let duplicated_handle = duplicated_handle.unwrap();

            let filepath = get_handle_filepath(&duplicated_handle);
            match filepath {
                Ok(Some(filepath)) => {
                    hashmap.entry(filepath).or_insert(Vec::new()).push(pid);
                },
                Ok(None) => {
                    continue;
                },
                Err(e) => {
                    return Err(e);
                }
            }
        }

        Ok(Self { hashmap })
    }

    pub fn search_filepath_in_map(&self, file_path: &str) -> Option<Vec<Pid>> {
        if self.hashmap.contains_key(file_path) {
            Some(self.hashmap.get(file_path).unwrap().clone())
        }
        else {
            None
        }
    }

    pub fn get_files_list_by_pid(&self, pid: Pid) -> Vec<String> {
        let mut files = Vec::new();
        for (elem_filepath, elem_pids) in self.hashmap.iter() {
            if elem_pids.iter().any(|&elem_pid| elem_pid == pid) {
                files.push(elem_filepath.clone());
            }
        }
        files
    }
}

pub fn get_process_name(process_id: u32) -> Option<String> {
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
