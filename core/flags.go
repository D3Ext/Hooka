package core

/*

This package returns CLI flags with customizble options

*/

import "flag"

func ParseFlags() (string, string, string, string, string, bool, bool, int, bool, bool, bool, bool, bool, string, int) {
  var sc_url string
  var sc_file string
  var dll_file string
  var dll_url string
  var technique string
  var hook_detect bool
  var halos bool
  var unhook int
  var base64_flag bool
  var hex_flag bool
  var test_flag bool
  var amsi bool
  var etw bool
  var lsass_flag string
  var pid int
  //var elevate bool

  flag.StringVar(&sc_url, "url", "", "remote url where shellcode is stored (e.g. http://192.168.1.37/shellcode.bin)")
  flag.StringVar(&dll_url, "remote-dll", "", "remote url where DLL is stored, especify function separated by comma (i.e. http://192.168.1.37/evil.dll,xyz)")
  flag.StringVar(&sc_file, "file", "", "path to file where shellcode is stored")
  flag.StringVar(&dll_file, "dll", "", "path to DLL you want to inject with function name sepparated by comma (i.e. evil.dll,xyz)")
  flag.StringVar(&technique, "t", "", "shellcode injection technique: CreateRemoteThread, Fibers, CreateProcess, EarlyBirdApc, UuidFromString (default: random)")
  flag.BoolVar(&hook_detect, "hooks", false, "dinamically detect hooked functions by EDR")
  flag.BoolVar(&halos, "halos", false, "use Hell's Gate and Halo's Gate to resolve syscalls (not all injection techniques are covered)")
  flag.IntVar(&unhook, "unhook", 0, "overwrite syscall memory address to bypass EDR : 1=classic, 2=full, 3=Perun's Fart")
  flag.BoolVar(&base64_flag, "b64", false, "decode base64 encoded shellcode")
  flag.BoolVar(&amsi, "amsi", false, "overwrite AmsiScanBuffer memory address to patch AMSI (Anti Malware Scan Interface)")
  flag.BoolVar(&etw, "etw", false, "overwrite EtwEventWrite memory address to patch ETW (Event Tracing for Windows)")
  flag.BoolVar(&hex_flag, "hex", false, "decode hex encoded shellcode")
  flag.BoolVar(&test_flag, "test", false, "test shellcode injection capabilities by spawning a calc.exe")
  flag.StringVar(&lsass_flag, "lsass", "", "dump lsass.exe process memory into a file to extract credentials (run as admin)")
  flag.IntVar(&pid, "pid", 0, "PID to inject shellcode into (default: self)")
  //flag.BoolVar(&elevate, "e", false, "enable SeDebugPrivilege to be able to interact with system processes")
  flag.Parse()

  // Return all param values
  return sc_url, sc_file, dll_file, dll_url, technique, hook_detect, halos, unhook, base64_flag, hex_flag, test_flag, amsi, etw, lsass_flag, pid //elevate
}


