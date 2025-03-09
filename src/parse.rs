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
}

pub fn parse() -> Args {
    Args::parse()
}
