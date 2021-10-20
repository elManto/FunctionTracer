#![allow(non_snake_case)]

use std::{env, path, fs, u64, i64};
use std::io::BufReader;
use std::collections::HashMap;
use nix::sys::ptrace;
use nix::unistd::{execv, Pid, fork, ForkResult};
use nix::sys::wait::{waitpid, wait, WaitStatus};
use nix::sys::signal::Signal;
use std::ffi::CString;
extern crate linux_personality;
use linux_personality::personality;
use goblin::{error, elf};
use goblin::elf::sym::*;
use libc::*;
use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, NasmFormatter, FlowControl, InstructionInfoFactory};

struct Area {
	filename: String,
	baseAddr: u64,
	endAddr: u64,
	symbols: HashMap<u64, String>,
}

fn elfParser(target: &String) -> HashMap<String, u64> {
	let mut addrToSym: HashMap<String, u64> = HashMap::new();
  let path = path::Path::new(target.as_str());
  let buffer = fs::read(target).unwrap();
	println!("Parsing {} target", target);
  let elf = elf::Elf::parse(&buffer).expect("File not parsed correctly");

  for sym in elf.syms.iter() {
		//println!("{}", sym.st_name);
		if let Some(Ok(str)) = elf.strtab.get(sym.st_name) {
			//println!("{}", str);
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

  for sym in elf.dynsyms.iter() {
		//println!("{}", sym.st_name);
  	if let Some(Ok(str)) = elf.dynstrtab.get(sym.st_name) {
			//println!("{}", str);
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
	
	println!("Retrieved {} symbols", addrToSym.keys().len());

  return addrToSym;
}

fn libraryParser(target: &String) -> HashMap<u64, String> {
	let mut addrToSym: HashMap<u64, String> = HashMap::new();
  let path = path::Path::new(target.as_str());
  let buffer = fs::read(target).unwrap();
	println!("Parsing {} target", target);
  let elf = elf::Elf::parse(&buffer).expect("File not parsed correctly");

  for sym in elf.syms.iter() {
		//println!("{}", sym.st_name);
		if let Some(Ok(str)) = elf.strtab.get(sym.st_name) {
			//println!("{}", str);
    	if sym.st_value == 0 {
      	let dyn_addr = unsafe {
        	libc::dlsym(libc::RTLD_DEFAULT, CString::new(str).unwrap().as_ptr())
      	};
      	if !dyn_addr.is_null() {
      		addrToSym.insert(dyn_addr as u64, str.to_owned());
      	}
    	} else {
    		addrToSym.insert(sym.st_value, str.to_owned());
    	} 
    } 
  }

  for sym in elf.dynsyms.iter() {
		//println!("{}", sym.st_name);
  	if let Some(Ok(str)) = elf.dynstrtab.get(sym.st_name) {
			//println!("{}", str);
    	if sym.st_value == 0 {
      	let dyn_addr = unsafe {
        	libc::dlsym(libc::RTLD_DEFAULT, CString::new(str).unwrap().as_ptr())
      	};
      	if !dyn_addr.is_null() {
      		addrToSym.insert(dyn_addr as u64, str.to_owned());
      	}
    	} else {
    		addrToSym.insert(sym.st_value, str.to_owned());
    	} 
    } 
  }
	
	println!("Retrieved {} symbols", addrToSym.keys().len());

  return addrToSym;
}


fn readMemory(pid: Pid, addr: u64) -> Vec<u8> {
	//reads a total of 32 bytes, assuming the machine is little endin (le)
	let mut code: Vec<u8> = Vec::new();
	for i in 0..2 {
    let value = ptrace::read(pid, addr as *mut c_void).expect("Error reading memory");
		let bytes = value.to_le_bytes();
		for b in &bytes {
			code.push(*b);
		}

	}
	return code;
}

fn setBreakpoint(pid: Pid, addr: u64) -> i64 {
    let value = ptrace::read(pid, addr as *mut c_void).expect("Error reading memory");
    let bp = (value & (i64::MAX ^ 0xFF)) | 0xCC;
    unsafe {
        ptrace::write(pid, addr as *mut c_void, bp as *mut c_void).unwrap();
    }
    value
}

fn restore_breakpoint(pid: Pid, addr: u64, orig_value: i64) {
    unsafe {
        // Restore original bytecode
        ptrace::write(pid, addr as *mut c_void, orig_value as *mut c_void).unwrap();
    }
}

fn analyseMemoryMapping(pid: Pid) -> Vec<Area> {
		let mut memoryMappings: Vec<Area> = Vec::new();
		let mut files: Vec<String> = vec![];
		let mapping: String = getAddressSpace(pid);
		let lines: Vec<_> = mapping.lines().collect();
		for line in &lines {
		  let splittedLine: Vec<&str> = line.split(" ").collect();
			let filename: String = splittedLine.last().copied().unwrap().to_string();
			if files.contains(&filename) || !path::Path::new(&filename).exists(){
				continue;
			}
			files.push(filename.clone());
			println!("Fetched name -> {}" , filename);
		  let offsets: Vec<&str> = splittedLine[0].split("-").collect();
		  let baseAddr = offsets[0];
			let endAddr = offsets[1];
				
		  let base = u64::from_str_radix(baseAddr, 16).unwrap();
		  let end = u64::from_str_radix(endAddr, 16).unwrap();
			let symbols: HashMap<_,_> = libraryParser(&filename);	
			let boxedArea: Box<Area> = Box::new(Area {filename: filename, baseAddr: base, endAddr: end, symbols: symbols}); 
			memoryMappings.push(*boxedArea);
		}
		
		return memoryMappings;
}

//fn handle_sigstop(pid: Pid, saved_values: &HashMap<u64, i64>) {
fn handle_sigstop(pid: Pid, addr: u64, val: i64) -> bool {
    let mut regs = ptrace::getregs(pid).unwrap();
		let mut isMain : bool = false;

		if (regs.rip - 1) == addr {

    	println!("Hit breakpoint at 0x{:x}", regs.rip - 1);
			restore_breakpoint(pid, regs.rip - 1, val);
			regs.rip -= 1;
			ptrace::setregs(pid, regs).expect("Error resetting RIP");
			isMain = true;
		}
    //match saved_values.get(&(regs.rip - 1)) {
    //    Some(orig) => {
    //        restore_breakpoint(pid, regs.rip - 1, *orig);

    //        // rewind rip
    //        regs.rip -= 1;
    //        ptrace::setregs(pid, regs).expect("Error rewinding RIP");

    //    }
    //    _ => print!("Nothing saved here"),
    //}

    //ptrace::cont(pid, None).expect("Restoring breakpoint failed");
		return isMain;
}


fn disassembleIP(pid: Pid) {
		//println!("Disassembling code to look for a call instruction");
    let mut regs = ptrace::getregs(pid).unwrap();
		let code: Vec<u8> = readMemory(pid, regs.rip);
    let mut decoder =
        Decoder::with_ip(64, &code, regs.rip, DecoderOptions::NONE);
		    let mut formatter = NasmFormatter::new();

    formatter.options_mut().set_digit_separator("`");
    formatter.options_mut().set_first_operand_char_index(10);

    let mut output = String::new();

    let mut instruction = Instruction::default();
		let mut info_factory = InstructionInfoFactory::new();

    while decoder.can_decode() {
        decoder.decode_out(&mut instruction);

        output.clear();
				match instruction.flow_control() {

					FlowControl::Call => {	
						let info = info_factory.info(&instruction);
						let offsets = decoder.get_constant_offsets(&instruction);
        		let start_index = (instruction.ip() - regs.rip) as usize;
        		let instr_bytes = &code[start_index..start_index + instruction.len()];
						println!("Instruction type -> {:?}", instruction.mnemonic());
        		for b in offsets.immediate_offset()..offsets.immediate_offset()+offsets.immediate_size() {
        		    print!("{:02X}", instr_bytes[b]);
        		}
						println!("");


        		formatter.format(&instruction, &mut output);

        		// Eg. "00007FFAC46ACDB2 488DAC2400FFFFFF     lea       rbp,[rsp-100h]"
        		print!("{:016X} ", instruction.ip());
        		let start_index = (instruction.ip() - regs.rip) as usize;
        		let instr_bytes = &code[start_index..start_index + instruction.len()];
						let instr_string = String::from("");
        		for b in instr_bytes.iter() {
        		    print!("{:02X}", b);
        		}

        		println!(" {}", output);
					},
					_ => {()},
				}



    }
		
}

fn eventsManager(pid: Pid, breakpointMainAddr: u64, valMainAddr: i64) {
	let mut memoryMappings: Vec<Area> = Vec::new();
	loop {
		match wait() {
	  	Ok(WaitStatus::Stopped(pid_t, sig_num)) => {
	    	match sig_num {
	      	Signal::SIGTRAP => {
	        	//handle_sigstop(pid_t, &saved_values);
	        	let isMain: bool = handle_sigstop(pid_t, breakpointMainAddr, valMainAddr);
						if isMain {
							memoryMappings = analyseMemoryMapping(pid);
						}
						disassembleIP(pid);
    				ptrace::step(pid, None);
	        }
	                    
	        Signal::SIGSEGV => {
	        	let regs = ptrace::getregs(pid_t).unwrap();
	          println!("Segmentation fault at 0x{:x}", regs.rip);
	          break
	        }
	        _ => {
	        	println!("Some other signal - {}", sig_num);
	          break
	        }
	      }
	    },
	
	    Ok(WaitStatus::Exited(pid, exit_status)) => {
	    	println!("Process with pid: {} exited with status {}", pid, exit_status);
	      break;
	    },
	
	    Ok(status) =>  {
	    	println!("Received status: {:?}", status);
	      //ptrace::cont(pid, None).expect("Failed to deliver signal");
  			ptrace::step(pid, None);
	    },
	
	    Err(err) => {
	    	println!("Some kind of error - {:?}",err);      
	    },

			_ => {
				ptrace::step(pid, None);
				// get rip and if it points to a call, extract the address, get the corresponding symbols and prints it
			}
	  }
	}
}



fn getLibraryCalls(pid: Pid) {
	getAddressSpace(pid);
	// Here we construct a global structure that contains for each loaded library the range addresses and the offsets of the symbols
}


fn parentProcess(pid: Pid, mainOffset: u64) -> u32 {
	waitpid(pid, None).unwrap();

	// set BPs
  let baseAddr : u64 = getMainProcBaseAddr(&getAddressSpace(pid));
	let mainBreakpoint: u64 = baseAddr + mainOffset;
	let mainVal : i64 = setBreakpoint(pid, mainBreakpoint);


	ptrace::cont(pid, None).expect("Failed continue process");
	eventsManager(pid, mainBreakpoint, mainVal);
  
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
