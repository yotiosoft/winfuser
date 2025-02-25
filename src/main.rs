mod winfuser;

fn main() {
    // target filepath
    let file_path = "C:\\Users\\ytani";
    println!("Target file path: {}", file_path);

    let proc_opened_files = winfuser::WinFuserStruct::get().map_err(|e| {
        println!("Error: {:?}", e);
    }).unwrap();
    let pids = proc_opened_files.search_filepath_in_map(file_path);
    
    if let Some(pids) = pids {
        for pid in pids.iter() {
            if let Some(process_name) = winfuser::get_process_name(*pid) {
                println!("Process ID: {} is holding the file. Process Name: {}", pid, process_name);
            }
        }
    }
    else {
        println!("No process is holding the file.");
    }

    let query_pid = 15368;
    let files = proc_opened_files.get_files_list_by_pid(query_pid);
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
