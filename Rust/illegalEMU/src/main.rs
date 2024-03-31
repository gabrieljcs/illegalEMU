/*
    illegalEMU

    This is a debugger to emulate illegal (unknown) instructions in software.

    It is intended to run modern software in legacy CPUs which do not carry newer instructions
    (specifically SSE 4.1+ and AVX+) but are reasonably powerful.

    Thanks to: https://www.timdbg.com/posts/writing-a-debugger-from-scratch-part-1/
*/

use std::env;
use std::mem;
use std::ptr::null;
use windows_sys::Win32::{Foundation::*, System::Threading::*};

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 || &args[1] == "-h" || &args[1] == "--help" {
        println!("Usage: illegalEMU <path of process to be emulated>");
        println!("\nOptions:");
        println!("  -h, --help    Display this help message");
        return;
    }

    println!("Started");

    let mut si: STARTUPINFOEXW = unsafe { mem::zeroed() };
    si.StartupInfo.cb = mem::size_of::<STARTUPINFOEXW>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { mem::zeroed() };

    let debugged_process = &args[1];
    let mut debugged_process_u16: Vec<u16> = debugged_process.encode_utf16().collect();

    /* DEBUG_ONLY_THIS_PROCESS will not debug child processes as well */
    let ret = unsafe {
        CreateProcessW(
            null(),                             // lpApplicationName
            debugged_process_u16.as_mut_ptr(),  // lpCommandLine
            null(),                             // lpProcessAttributes
            null(),                             // lpThreadAttributes
            FALSE,                              // bInheritHandles
            DEBUG_ONLY_THIS_PROCESS,            // dwCreationFlags
            null(),                             // lpEnvironment
            null(),                             // lpCurrentDirectory
            &mut si.StartupInfo,                // lpStartupInfo
            &mut pi                             // lpProcessInformation
        )
    };

    println!("CreateProcess returned: {}", ret);

    match GetLastError() {
        740 => {
            println!("Insufficient privileges to debug the process. Restart the program as an administrator.");
            std::process::exit(740);
        },
        2 => {
            println!("The specified file was not found.");
            std::process::exit(2);
        },
        3 => {
            println!("The specified path was not found.");
            std::process::exit(3);
        },
        _ => {},
    }

    let mut debug_event: DEBUG_EVENT = unsafe { std::mem::zeroed() };

    /* Debugger loop */
    loop {
        unsafe {
            WaitForDebugEventEx(&mut debug_event, INFINITE);

            /* Pause debuggee when illegal instruction is hit */
            if debug_event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT &&
                debug_event.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION {

                    /* Address where exception happened */
                    let exception_address = debug_event.u.Exception.ExceptionRecord.ExceptionAddress;

                    println!("Illegal instruction detected");
            }
        }
    }

}