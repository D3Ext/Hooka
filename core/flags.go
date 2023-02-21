package core

/*

This package returns CLI flags with customizble options

*/

import (
  "flag"
)

func ParseFlags() (string, string, string, string, bool, bool, int, bool, bool, bool, string) {
  var sc_url string
  var sc_file string
  var dll_file string
  var technique string
  var hook_detect bool
  var hells bool
  var unhook int
  var base64_flag bool
  var hex_flag bool
  var test_flag bool
  var lsass_flag string

  flag.StringVar(&sc_url, "url", "", "remote shellcode url (e.g. http://192.168.1.37/shellcode.bin)")
  flag.StringVar(&sc_file, "file", "", "path to file where shellcode is stored")
  flag.StringVar(&dll_file, "dll", "", "path to DLL you want to inject with function name sepparated by comma (i.e. evil.dll,xyz)")
  flag.StringVar(&technique, "t", "", "shellcode injection technique: CreateRemoteThread, Fibers, OpenProcess, EarlyBirdApc (default: random)")
  flag.BoolVar(&hook_detect, "hooks", false, "dinamically detect hooked functions by EDR")
  flag.BoolVar(&hells, "hells", false, "enable Hell's Gate technique to try to evade possible EDRs")
  flag.IntVar(&unhook, "unhook", 0, "overwrite syscall memory address to bypass EDR : 1=classic, 2=full, 3=Perun's Fart")
  flag.BoolVar(&base64_flag, "b64", false, "decode base64 encoded shellcode")
  flag.BoolVar(&hex_flag, "hex", false, "decode hex encoded shellcode")
  flag.BoolVar(&test_flag, "test", false, "test shellcode injection capabilities by spawning a calc.exe")
  flag.StringVar(&lsass_flag, "lsass", "", "dump lsass.exe process memory into a file to extract credentials (run as admin)")
  flag.Parse()

  return sc_url, sc_file, dll_file, technique, hook_detect, hells, unhook, base64_flag, hex_flag, test_flag, lsass_flag // Return all param values
}


