use ntapi::ntexapi::SystemExtendedHandleInformation;

use super::api;
use super::*;

pub fn query_files_by_pid(pid: u32) -> Result<Vec<String>, WinFuserError> {
    let buffer = api::query_system_information(SystemExtendedHandleInformation)?;
    let handle_info = api::buffer_to_system_handle_information_ex(buffer);

    let mut files = Vec::new();
    for entry in handle_info.handles.iter() {
        let entry_pid = entry.UniqueProcessId as u32;
        if entry_pid != pid {
            continue;
        }

        let handle_value = entry.HandleValue as api::NotOpenedHandle;
        let duplicated_handle = entry_to_filepath(pid, handle_value)?;
        if duplicated_handle.is_none() {
            continue;
        }
        let duplicated_handle = duplicated_handle.unwrap();

        let filepath = get_handle_filepath(&duplicated_handle);
        match filepath {
            Ok(Some(filepath)) => {
                files.push(filepath);
            },
            Ok(None) => {
                continue;
            },
            Err(e) => {
                return Err(WinFuserError::from(e));
            }
        }
    }

    Ok(files)
}

pub fn query_pids_by_file(file_path: &str) -> Result<Vec<u32>, WinFuserError> {
    let buffer = api::query_system_information(SystemExtendedHandleInformation)?;
    let handle_info = api::buffer_to_system_handle_information_ex(buffer);

    let mut pids = Vec::new();
    for entry in handle_info.handles.iter() {
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
                if filepath == file_path {
                    pids.push(pid);
                }
            },
            Ok(None) => {
                continue;
            },
            Err(e) => {
                return Err(WinFuserError::from(e));
            }
        }
    }

    Ok(pids)
}
