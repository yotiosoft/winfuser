use ntapi::ntexapi::SystemExtendedHandleInformation;
use std::collections::HashMap;

use super::api;
use super::*;

pub type PidToFilesMap = HashMap<Pid, Vec<String>>;
pub struct ProcessToFiles {
    pub hashmap: PidToFilesMap,
}
impl WinFuserTrait for ProcessToFiles {
    fn get() -> Result<Self, api::Status> {
        let mut hashmap = PidToFilesMap::new();
        let buffer = api::query_system_information(SystemExtendedHandleInformation)?;
        let handle_info = api::buffer_to_system_handle_information_ex(buffer);

        for entry in handle_info.handles.iter() {
            let pid = Pid::from(entry.UniqueProcessId);
            let handle_value = entry.HandleValue as api::NotOpenedHandle;
            let duplicated_handle = entry_to_filepath(pid, handle_value)?;
            if duplicated_handle.is_none() {
                continue;
            }
            let duplicated_handle = duplicated_handle.unwrap();

            let filepath = get_handle_filepath(&duplicated_handle);
            match filepath {
                Ok(Some(filepath)) => {
                    hashmap.entry(pid).or_insert(Vec::new()).push(filepath);
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

impl ProcessToFiles {
    pub fn find_files_by_pid(&self, pid: u32) -> Vec<&str> {
        self.hashmap.get(&pid.into()).map(|files| files.iter().map(|s| s.as_str()).collect()).unwrap_or_default()
    }
}
