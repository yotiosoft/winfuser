use clap::{ArgGroup, Parser, Subcommand};

#[derive(clap::Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// File path to search for.
    /// If this option is provided, the program will search for the process that is holding the file.
    #[arg(short, long)]
    pub file_path: Option<String>,

    /// Process ID to search for.
    /// If this option is provided, the program will search for the files that are opened by the process.
    #[arg(short, long)]
    pub pid: Option<u32>,
}

pub fn parse() -> Args {
    Args::parse()
}
