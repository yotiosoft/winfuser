# Winfuser

## Overview

Winfuser is a Rust binary CLI tool/library that utilizes the Windows API to obtain information about which processes are using which files. It can be used to identify file locks, monitor file usage, and manage file access in Windows environments.

Winfuser is a **Rust-based Windows-only tool** for analyzing file handles.  
It allows you to determine:

- Which processes are opening a specific file  
- Which files a given process ID or process name has opened  
- All opened files across all processes

It enumerates all process handles in Windows and efficiently maps file paths ↔ processes.

---

## Features

- Low-level Windows API–based handle enumeration (`NtQuerySystemInformation`, etc.)
- Search processes by file path
- Search opened files by process ID
- Search opened files by process name
- Display all processes and their opened files
- Usable both as a CLI tool and as a Rust library

---

## Installation

Install via Cargo:

```powershell
cargo install winfuser
```

Or add it to your Cargo.toml:

```toml
[dependencies]
winfuser = "0.x"
```

## CLI Usage

Winfuser’s CLI interface (winfuser.exe) supports the following options:

```powershell
> winfuser -h
Usage: winfuser.exe [OPTIONS]

Options:
  -f, --file-path <FILE_PATH>  File path to search for
  -p, --pid <PID>              Process ID to search for
  -n, --name <NAME>            Process name to search for (ex. notepad.exe)
  -a, --all                    All processes
  -q, --quiet                  Show only the names of processes or files
  -h, --help                   Print help
  -V, --version                Print version
```

### Examples
1. List processes that have opened a specific file
winfuser -f C:\path\to\file.txt

2. List files opened by a specific PID
winfuser -p 1234

3. List files opened by process name
winfuser -n notepad.exe

4. Show all processes and their opened files
winfuser -a
