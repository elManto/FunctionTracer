#![allow(non_snake_case)]

use std::{env, path, fs, u64, i64};
use std::io::BufReader;
use std::collections::HashMap;
use nix::sys::ptrace;
use nix::unistd::{execv, Pid, fork, ForkResult};
use nix::sys::wait::{waitpid, wait};
use nix::sys::signal::Signal;
use std::ffi::CString;
extern crate linux_personality;
use linux_personality::personality;
use goblin::{error, elf};
use goblin::elf::sym::*;
use libc::*;

fn elfParser(target: &String) -> HashMap<String, u64> {
	let mut addrToSym: HashMap<String, u64> = HashMap::new();
  let path = path::Path::new(target.as_str());
  let buffer = fs::read(target).unwrap();
  let elf = elf::Elf::parse(&buffer).expect("File not parsed correctly");

  for sym in elf.syms.iter() {
  	if let Some(Ok(str)) = elf.strtab.get(sym.st_name) {
    	if sym.st_value == 0 {
      	let dyn_addr = unsafe {
        	libc::dlsym(libc::RTLD_DEFAULT, CString::new(str).unwrap().as_ptr())
      	};
      	if !dyn_addr.is_null() {
      		addrToSym.insert(str.to_owned(), dyn_addr as u64);
      	}
    	} else {
    		addrToSym.insert(str.to_owned(), sym.st_value);
    	} 
    } 
  }
  return addrToSym;
}


fn setBreakpoint(pid: Pid, addr: u64) -> i64 {
		println!("Setting break at addr -> {}" , addr);
    let value = ptrace::read(pid, addr as *mut c_void).expect("Error reading memory");
    let bp = (value & (i64::MAX ^ 0xFF)) | 0xCC;
    unsafe {
        ptrace::write(pid, addr as *mut c_void, bp as *mut c_void).unwrap();
    }
    value
}

//fn restore_breakpoint(pid: Pid, addr: u64, orig_value: i64) {
//    unsafe {
//        // Restore original bytecode
//        ptrace::write(pid, addr as *mut c_void, orig_value as *mut c_void).unwrap();
//    }
//}
//
//fn handle_sigstop(pid: Pid, saved_values: &HashMap<u64, i64>) {
//    let mut regs = ptrace::getregs(pid).unwrap();
//    println!("Hit breakpoint at 0x{:x}", regs.rip - 1);
//
//    match saved_values.get(&(regs.rip - 1)) {
//        Some(orig) => {
//            restore_breakpoint(pid, regs.rip - 1, *orig);
//
//            // rewind rip
//            regs.rip -= 1;
//            ptrace::setregs(pid, regs).expect("Error rewinding RIP");
//
//        }
//        _ => print!("Nothing saved here"),
//    }
//
//    ptrace::cont(pid, None).expect("Restoring breakpoint failed");
//
//}
//
//
//fn eventsManager() {
//	loop {
//		match wait() {
//	  	Ok(WaitStatus::Stopped(pid_t, sig_num)) => {
//	    	match sig_num {
//	      	Signal::SIGTRAP => {
//	        	handle_sigstop(pid_t, &saved_values);
//	        }
//	                    
//	        Signal::SIGSEGV => {
//	        	let regs = ptrace::getregs(pid_t).unwrap();
//	          println!("Segmentation fault at 0x{:x}", regs.rip);
//	          break
//	        }
//	        _ => {
//	        	println!("Some other signal - {}", sig_num);
//	          break
//	        }
//	      }
//	    },
//	
//	    Ok(WaitStatus::Exited(pid, exit_status)) => {
//	    	println!("Process with pid: {} exited with status {}", pid, exit_status);
//	      break;
//	    },
//	
//	    Ok(status) =>  {
//	    	println!("Received status: {:?}", status);
//	      ptrace::cont(pid, None).expect("Failed to deliver signal");
//	    },
//	
//	    Err(err) => {
//	    	println!("Some kind of error - {:?}",err);      
//	    },
//	  }
//	}
//}

fn parentProcess(pid: Pid, mainOffset: u64) -> u32 {
	waitpid(pid, None).unwrap();

	// set BPs
  let baseAddr : u64 = getMainProcBaseAddr(&getAddressSpace(pid));
	let mainBreakpoint: u64 = baseAddr; //+ mainOffset;

  wait().unwrap();
	setBreakpoint(pid, mainBreakpoint);
	
	ptrace::cont(pid, None).expect("Failed continue process");

	wait().unwrap();	
	    let mut regs = ptrace::getregs(pid).unwrap();
    println!("Hit breakpoint at 0x{:x}", regs.rip - 1);

	ptrace::cont(pid, None).expect("Failed continue process");
	// Single step
  //let mut i = 0;
  //while i < 10 {
  //  ptrace::step(pid, None);
  //  wait().unwrap();
  //  let mut regs = ptrace::getregs(pid).expect("get registers failed");
  //  println!("{}", regs.rip);
  //  i = i + 1;
  //}
  
  println!("[main] I'll be waiting for the child termination...");
  match waitpid(pid, None) {
    Ok(status) => println!("[main] Child exited with status {:?}", status),
    Err(err) => println!("[main] waitpid() failed: {}", err),
  }

  return 0;
}

fn getMainProcBaseAddr(mapping: &String) -> u64 {
  let splittedMapping: Vec<&str> = mapping.split(" ").collect();
  let offsets: Vec<&str> = splittedMapping[0].split("-").collect();
  let baseAddr = offsets[0];
  let addr = u64::from_str_radix(baseAddr, 16).unwrap();

  println!("base addr -> {}", addr);
  return addr;


}
  
fn getAddressSpace(pid: Pid) -> String {
  let pidInt: i32 = pid.as_raw();
  let mut mappingFilePath: String = String::from("");
  if pidInt == 0 {
    mappingFilePath = format!("/proc/self/maps");
  }
  else {
    mappingFilePath = format!("/proc/{}/maps", pid.as_raw().to_string());
  }
  let mapping = fs::read_to_string(mappingFilePath).expect("Unable to read");
	println!("{}", mapping);
  return mapping
}

fn main() {
  let args: Vec<String> = env::args().collect();
  if args.len() != 2 {
    println!("Wrong number of params");
    std::process::exit(0);
  }
  let target: String = args[1].clone();
  if ! path::Path::new(&target).exists() {
    println!("File does not exist");
    std::process::exit(-1);
  }
  
  let mainBinarySymbolMap: HashMap<String, u64> = elfParser(&target);
	let mainOffset = mainBinarySymbolMap.get(&String::from("main"))
		.expect("Impossible to recover the `main()` offset")
		.clone();


  match fork() {
    Ok(ForkResult::Child) => {
      let targetFile = CString::new(target).expect("Target File cannot be converted into CStr");
      let targetArguments = CString::new("./").unwrap();
      let zeroPid = Pid::from_raw(0);
      ptrace::traceme().unwrap();
      personality(linux_personality::ADDR_NO_RANDOMIZE).unwrap();
      //ptrace::setoptions(zeroPid, ptrace::Options::PTRACE_O_TRACEEXIT);
      execv(&targetFile, &[&targetArguments]);

      std::process::exit(0);
    }
    
    Ok(ForkResult::Parent {child}) => {
        parentProcess(child, mainOffset);
    }
    
    Err(err) => {
        panic!("[main] fork() failed: {}", err);
    }

  }

 
    
  return;
}
