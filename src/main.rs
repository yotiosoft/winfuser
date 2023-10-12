use winapi::ctypes::*;
use winapi::um::memoryapi::*;
use winapi::um::processthreadsapi::*;
use winapi::um::winnt::{ MEM_COMMIT, MEM_RELEASE, PAGE_EXECUTE_READWRITE };
use ntapi::ntexapi::*;

// SystemProcessInformation を buffer に取得
fn get_system_procs_info(mut buffer_size: u32) -> *mut c_void {
    unsafe {
        let mut base_address = VirtualAlloc(std::ptr::null_mut(), buffer_size as usize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

        let tries = 0;
        let max_tries = 5;
        loop {
            // プロセス情報を取得
            // SystemProcessInformation : 各プロセスの情報（オプション定数）
            // base_address             : 格納先
            // buffer_size              : 格納先のサイズ
            // &mut buffer_size         : 実際に取得したサイズ
            let res = NtQuerySystemInformation(SystemProcessInformation, base_address, buffer_size, &mut buffer_size);
            
            if res == 0 {
                break;
            }
            if tries == max_tries {
                break;
            }

            // realloc
            VirtualFree(base_address, 0, MEM_RELEASE);
            base_address = VirtualAlloc(std::ptr::null_mut(), buffer_size as usize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        }

        base_address
    }
}

// SystemHandleInformation を buffer に取得
fn get_system_handle_info(mut buffer_size: u32) -> *mut c_void {
    unsafe {
        let mut base_address = VirtualAlloc(std::ptr::null_mut(), buffer_size as usize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

        let tries = 0;
        let max_tries = 5;
        loop {
            // プロセス情報を取得
            // SystemHandleInformation  : 各ハンドルの情報（オプション定数）
            // base_address             : 格納先
            // buffer_size              : 格納先のサイズ
            // &mut buffer_size         : 実際に取得したサイズ
            let res = NtQuerySystemInformation(SystemHandleInformation, base_address, buffer_size, &mut buffer_size);
            
            if res == 0 {
                break;
            }
            if tries == max_tries {
                break;
            }

            // realloc
            VirtualFree(base_address, 0, MEM_RELEASE);
            base_address = VirtualAlloc(std::ptr::null_mut(), buffer_size as usize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        }

        base_address
    }
}


fn get_proc_info(next_address: isize) -> SYSTEM_PROCESS_INFORMATION {
    unsafe {
        let mut system_process_info: SYSTEM_PROCESS_INFORMATION = std::mem::zeroed();

        // base_address の該当オフセット値から SYSTEM_PROCESS_INFORMATION 構造体の情報をプロセス1つ分取得
        ReadProcessMemory(
            GetCurrentProcess(), next_address as *const c_void, &mut system_process_info as *mut _ as *mut c_void, 
            std::mem::size_of::<SYSTEM_PROCESS_INFORMATION>() as usize, std::ptr::null_mut()
        );

        system_process_info
    }
}

fn get_proc_name(proc_info: SYSTEM_PROCESS_INFORMATION) -> String {
    unsafe {
        // プロセス名を取得
        let mut image_name_vec: Vec<u16> = vec![0; proc_info.ImageName.Length as usize];
        ReadProcessMemory(
            GetCurrentProcess(), proc_info.ImageName.Buffer as *const c_void, image_name_vec.as_mut_ptr() as *mut c_void, 
            proc_info.ImageName.Length as usize, std::ptr::null_mut()
        );
        // \0 を除去して return
        String::from_utf16_lossy(&image_name_vec).trim_matches(char::from(0)).to_string()
    }
}

fn get_proc_id(proc_info: SYSTEM_PROCESS_INFORMATION) -> u32 {
    proc_info.UniqueProcessId as u32
}

///
fn get_handle_info(next_address: isize) -> SYSTEM_HANDLE_INFORMATION {
    unsafe {
        let mut system_process_info: SYSTEM_HANDLE_INFORMATION = std::mem::zeroed();

        // base_address の該当オフセット値から SYSTEM_PROCESS_INFORMATION 構造体の情報をプロセス1つ分取得
        ReadProcessMemory(
            GetCurrentProcess(), next_address as *const c_void, &mut system_process_info as *mut _ as *mut c_void, 
            std::mem::size_of::<SYSTEM_HANDLE_INFORMATION>() as usize, std::ptr::null_mut()
        );

        system_process_info
    }
}

fn get_handle_entry(base_address: isize, index: &isize) -> SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    unsafe {
        let mut system_handle_table_entry: SYSTEM_HANDLE_TABLE_ENTRY_INFO = std::mem::zeroed();

        // base_address の該当オフセット値から SYSTEM_PROCESS_INFORMATION 構造体の情報をプロセス1つ分取得
        let next_address = base_address + std::mem::size_of::<SYSTEM_HANDLE_TABLE_ENTRY_INFO>() as isize * index;
        ReadProcessMemory(
            GetCurrentProcess(), next_address as *const c_void, &mut system_handle_table_entry as *mut _ as *mut c_void, 
            std::mem::size_of::<SYSTEM_HANDLE_TABLE_ENTRY_INFO>() as usize, std::ptr::null_mut()
        );

        system_handle_table_entry
    }
}

fn main() {
    unsafe {
        // プロセス情報を取得
        let base_address = get_system_handle_info(0x10000);

        // base_address に取得したプロセス情報を SYSTEM_PROCESS_INFORMATION 構造体 system_process_info に格納
        let mut system_handle_info = get_handle_info(base_address as isize);

        let mut next_address = base_address as isize;
        // すべてのプロセス情報を取得
        for i in 0..system_handle_info.NumberOfHandles as isize {
            let handle_info = get_handle_entry(base_address as isize, &i);
            println!("handle {:?} {:?} {:?} {:?}", handle_info.HandleValue, handle_info.ObjectTypeIndex, handle_info.CreatorBackTraceIndex, handle_info.UniqueProcessId);
        }
        VirtualFree(base_address, 0x0, MEM_RELEASE);
    }
}
