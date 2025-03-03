use winprocinfo;

mod winfuser;
use crate::winfuser::{ WinFuserStruct, WinFuserTrait };

mod parse;

fn by_filepath(file_path: &str) {
    let proc_opened_files = WinFuserStruct::get().map_err(|e| {
        println!("Error: {:?}", e);
    }).unwrap();
    let pids = proc_opened_files.search_filepath(&file_path);
    
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
}

fn by_pid(pid: u32) {
    let proc_opened_files = WinFuserStruct::get().map_err(|e| {
        println!("Error: {:?}", e);
    }).unwrap();
    let files = proc_opened_files.get_files_by_pid(pid);
    if files.len() > 0 {
        println!("Files opened by process ID: {}", pid);
        for file in files.iter() {
            println!("{}", file);
        }
    }
    else {
        println!("No file is opened by this process.");
    }
}

fn main() {
    // Parse command line arguments
    let args = parse::parse();

    // filepath mode.
    if args.file_path.is_some() {
        let file_path = args.file_path.unwrap();
        by_filepath(&file_path);
    }
    // pid mode.
    else if args.pid.is_some() {
        let pid = args.pid.unwrap();
        by_pid(pid);
    }
    // Process name mode.
    else if args.name_of_process.is_some() {
        let process_name = args.name_of_process.unwrap();

        let pids = {
            let processes = winprocinfo::get_list();
            if let Ok(processes) = processes {
                processes.get_pids_by_name(&process_name)
            }
            else {
                println!("Error: {}", processes.err().unwrap());
                None
            }
        };
        if let Some(pids) = pids {
            for pid in pids.iter() {
                println!("\nProcess name: {} Process ID: {}", process_name, pid);
                by_pid(*pid);
            }
        }
        else {
            println!("No process is found with the name.");
        }
    }
    // none
    else {
        println!("Please provide either file path with -f or process ID with -p.");
    }
}
