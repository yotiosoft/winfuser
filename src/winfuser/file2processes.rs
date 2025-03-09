use ntapi::ntexapi::SystemExtendedHandleInformation;
use std::collections::HashMap;

use super::api;
use super::*;

pub type FileToPidsMap = HashMap<String, Vec<Pid>>;
pub struct FileToProcesses {
    pub hashmap: FileToPidsMap,
}
impl WinFuserTrait for FileToProcesses {
    fn get() -> Result<Self, api::Status> {
        let mut hashmap = FileToPidsMap::new();
        let buffer = api::query_system_information(SystemExtendedHandleInformation)?;
        let handle_info = api::buffer_to_system_handle_information_ex(buffer);

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
}

impl FileToProcesses {
    pub fn find_pids_by_filepath(&self, file_path: &str) -> Vec<Pid> {
        self.hashmap.get(file_path).map(|pids| pids.iter().map(|pid| *pid).collect()).unwrap_or_default()
    }
}
