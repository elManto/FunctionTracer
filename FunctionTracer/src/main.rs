#![allow(non_snake_case)]

use std::{env, path, fs};
use std::io::BufReader;
//use std::path;
//use fork::{Fork, fork, ForkResult};
use nix::sys::ptrace;
use nix::unistd::{execv, Pid, fork, ForkResult};
use nix::sys::wait::*;
use nix::sys::signal::Signal;
use std::ffi::CString;
extern crate linux_personality;
use linux_personality::personality;


//use goblin::{error, Object};

//fn elfParser(target: String) -> u32 {
//  let path = path::Path::new(target.as_str());
//  let buffer = fs::read(target).unwrap();
//  let elf = Object::parse(&buffer);
//  return 0;
//}

fn parentProcess(pid: Pid) -> u32 {
  let baseAddr : u64 = getAddressSpace(pid);
  wait().unwrap();
  let mut i = 0;
  while i < 10 {
    ptrace::step(pid, None);

    wait().unwrap();
    let mut regs = ptrace::getregs(pid).expect("get registers failed");


    println!("{}", regs.rip);
    i = i + 1;
  }
  
  println!("[main] I'll be waiting for the child termination...");
  match waitpid(pid, None) {
    Ok(status) => println!("[main] Child exited with status {:?}", status),
    Err(err) => println!("[main] waitpid() failed: {}", err),
  }

  return 0;
}
  
fn getAddressSpace(pid: Pid) -> u64 {
  let mappingFilePath: String = format!("/proc/{}/maps", pid.as_raw().to_string());
  let mapping = fs::read_to_string(mappingFilePath).expect("Unable to read");
  //let mappingFile = fs::File::open(mappingFilePath).expect("file not found");
  //let mut buf_reader = BufReader::new(mappingFile);
  //let mut contents = String::new();
  //buf_reader.read_to_string(&mut contents)?;

  println!("{}", mapping);
  return 0;
}

fn main() {
  println!("Simple function tracer implementation");
  let args: Vec<String> = env::args().collect();
  println!("{:?}", args);
  if args.len() != 2 {
    println!("Wrong number of params");
    std::process::exit(0);
  }
  let target: String = args[1].clone();
  if ! path::Path::new(&target).exists() {
    println!("File does not exist");
    std::process::exit(-1);
  }
  
  match fork() {
    Ok(ForkResult::Child) => {
      let targetFile = CString::new(target).expect("Target File cannot be converted into CStr");
      let targetArguments = CString::new("./").unwrap();
      let zeroPid = Pid::from_raw(0);
      ptrace::traceme();
      personality(linux_personality::ADDR_NO_RANDOMIZE).unwrap();
      ptrace::setoptions(zeroPid, ptrace::Options::PTRACE_O_TRACEEXIT);
      execv(&targetFile, &[&targetArguments]);

      std::process::exit(0);
    }
    
    Ok(ForkResult::Parent {child}) => {
        parentProcess(child);
    }
    
    Err(err) => {
        panic!("[main] fork() failed: {}", err);
    }

  }

 
    
  return;
}
