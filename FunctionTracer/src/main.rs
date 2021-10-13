//#![allow(non_snake_case)]

use std::env;
use std::path;
use fork::{daemon, Fork, fork};
use std::process::Command;
use nix::unistd::execve;
use nix::sys::wait::waitpid;
use std::ffi::CString;



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

  
  let childPid = match fork() {
    Ok(Fork::Parent(child))  => {
      println!("Parent process");
      child

    }
    Ok(Fork::Child) => {
      let targetFile = CString::new(target).expect("Target File cannot be converted into CStr");
      let targetArguments = CString::new("./").unwrap();
      let targetEnv = CString::new("").unwrap();
      execve(&targetFile, &[targetArguments], &[targetEnv]);
    }
    Err(_) => {
      println!("Fork failed"); 
    }
  }
  waitpid(childPid, None);
  println!("Parent again, child has pid {}", childPid);
  
    
  return;
}
