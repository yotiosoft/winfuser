use winprocinfo;

mod winfuser;
use winfuser::WinFuserTrait;

mod parse;

fn by_filepath_single(file_path: &str) -> Result<(), winfuser::WinFuserError> {
    let pids = winfuser::single::query_pids_by_file(&file_path)?;
    
    if pids.len() > 0 {
        for pid in pids.iter() {
            if let Some(process_name) = winfuser::get_process_name(pid) {
                println!("Process ID: {} is holding the file. Process Name: {}", pid, process_name);
            }
        }
    }
    else {
        println!("No process is holding the file.");
    }
    Ok(())
}

fn by_filepath(file_paths: Vec<String>) {
    let proc_opened_files = winfuser::FileToProcesses::get().map_err(|e| {
        println!("Error: {:?}", e);
    }).unwrap();

    for file_path in file_paths.iter() {
        let pids = proc_opened_files.find_pids_by_filepath(&file_path);
        
        if pids.len() > 0 {
            println!("File: {}", file_path);
            for pid in pids.iter() {
                if let Some(process_name) = winfuser::get_process_name(pid) {
                    println!("Process ID: {} is holding the file. Process Name: {}", pid, process_name);
                }
            }
        }
        else {
            println!("No process is holding the file.");
        }
        println!();
    }
}

fn by_pid_single(pid: u32) -> Result<(), winfuser::WinFuserError> {
    let process_name = winfuser::get_process_name(&pid);
    if process_name.is_none() {
        println!("No process is found with the ID: {}", pid);
        return Ok(());
    }

    let files = winfuser::single::query_files_by_pid(pid)?;
    if files.len() > 0 {
        println!("Files opened by process ID: {} (process name: {})", pid, process_name.unwrap());
        for file in files.iter() {
            println!("{}", file);
        }
    }
    else {
        println!("No file is opened by this process.");
    }
    Ok(())
}

fn by_pid(pid: Vec<u32>, process_to_files: &winfuser::ProcessToFiles) {
    for pid in pid.iter() {
        let process_name = winfuser::get_process_name(&pid);
        if process_name.is_none() {
            println!("No process is found with the ID: {}", pid);
            continue;
        }

        let files = process_to_files.find_files_by_pid(*pid);
        if files.len() > 0 {
            println!("Files opened by process ID: {}", pid);
            for file in files.iter() {
                println!("{}", file);
            }
        }
        else {
            println!("No file is opened by this process.");
        }
        println!();
    }
}

fn all_processes() {
    let proc_opened_files = winfuser::ProcessToFiles::get().map_err(|e| {
        println!("Error: {:?}", e);
    }).unwrap();

    for process in proc_opened_files.hashmap.iter() {
        let pid = *process.0;
        let process_name = winfuser::get_process_name(&pid).unwrap();
        let files = process.1;

        if files.len() > 0 {
            println!("Files opened by process ID: {} (process name: {})", pid, process_name);
            for file in files.iter() {
                println!("{}", file);
            }
        }
        else {
            println!("No file is opened by this process.");
        }
        println!();
    }
}

fn main() {
    // Parse command line arguments
    let args = parse::parse();

    // filepath mode.
    if args.file_path.is_some() {
        let file_path = args.file_path.unwrap();
        if file_path.len() == 1 {
            by_filepath_single(&file_path[0]).map_err(|e| {
                println!("Error: {:?}", e);
            }).unwrap();
        }
        else if file_path.len() > 1 {
            by_filepath(file_path);
        }
    }
    // pid mode.
    if args.pid.is_some() {
        let pid = args.pid.unwrap();

        if pid.len() == 1 {
            by_pid_single(pid[0]).map_err(|e| {
                println!("Error: {:?}", e);
            }).unwrap();
        }
        else if pid.len() > 1 {
            // Get all processes and their opened files.
            let proc_opened_files = winfuser::ProcessToFiles::get().map_err(|e| {
                println!("Error: {:?}", e);
            }).unwrap();
            by_pid(pid, &proc_opened_files);
        }
    }
    // Process name mode.
    if args.name_of_process.is_some() {
        let process_names = args.name_of_process.unwrap();

        // Get all processes and their opened files.
        let proc_opened_files = winfuser::ProcessToFiles::get().map_err(|e| {
            println!("Error: {:?}", e);
        }).unwrap();

        for process_name in process_names.iter() {
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
                by_pid(pids, &proc_opened_files);
            }
            else {
                println!("No process is found with the name.");
            }
        }
    }
    // All processes mode.
    if args.all {
        all_processes();
    }
}
