mod winfuser;
use crate::winfuser::{ WinFuserStruct, WinFuserTrait };

mod parse;

fn main() {
    // Parse command line arguments
    let args = parse::parse();

    // filepath mode.
    if args.file_path.is_some() {
        let file_path = args.file_path.unwrap();
        println!("Target file path: {}", file_path);

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
    // pid mode.
    else if args.pid.is_some() {
        let pid = args.pid.unwrap();
        println!("Process ID: {}", pid);

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
    // none
    else {
        println!("Please provide either file path with -f or process ID with -p.");
    }
}
