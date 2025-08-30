use clap::Parser;

#[derive(clap::Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// File path to search for.
    #[arg(short, long)]
    pub file_path: Option<Vec<String>>,

    /// Process ID to search for.
    #[arg(short, long)]
    pub pid: Option<Vec<u32>>,

    /// Process name to search for (ex. notepad.exe).
    #[arg(short, long)]
    pub name_of_process: Option<Vec<String>>,

    /// All processes.
    #[arg(short, long)]
    pub all: bool,

    /// Show only the names of processes or files.
    #[arg(short, long)]
    pub silent: bool,

    // Show the count of processes or files.
    //#[arg(short, long)]
    //pub count: bool,
}

pub fn parse() -> Args {
    let args = Args::parse();
    // none
    if args.file_path.is_none() && args.pid.is_none() && args.name_of_process.is_none() && !args.all {
        println!("Please provide either file path with -f or process ID with -p.");
    }
    args
}
