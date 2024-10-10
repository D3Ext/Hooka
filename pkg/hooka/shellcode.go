package hooka

import (
  sc_pkg "github.com/D3Ext/Hooka/shellcode"
)

// use 0 as pid to self-inject
func CreateProcess(shellcode []byte, pid int) error {
	return sc_pkg.CreateProcess(shellcode, pid)
}

// use 0 as pid to self-inject
func CreateRemoteThread(shellcode []byte, pid int) error {
	return sc_pkg.CreateRemoteThread(shellcode, pid)
}

func NtCreateThreadEx(shellcode []byte, pid int) error {
	return sc_pkg.NtCreateThreadEx(shellcode, pid)
}

func ProcessHollowing(shellcode []byte, proc string, blockdlls bool) error {
  return sc_pkg.ProcessHollowing(shellcode, proc, blockdlls)
}

func EnumSystemLocales(shellcode []byte) error {
	return sc_pkg.EnumSystemLocales(shellcode)
}

func Fibers(shellcode []byte) error {
	return sc_pkg.Fibers(shellcode)
}

func QueueUserApc(shellcode []byte) error {
	return sc_pkg.QueueUserApc(shellcode)
}

func NtQueueApcThreadEx(shellcode []byte) error {
  return sc_pkg.NtQueueApcThreadEx(shellcode)
}

func NoRWX(shellcode []byte) error {
  return sc_pkg.NoRWX(shellcode)
}

func UuidFromString(shellcode []byte) error {
	return sc_pkg.UuidFromString(shellcode)
}

func EtwpCreateEtwThread(shellcode []byte) error {
	return sc_pkg.EtwpCreateEtwThread(shellcode)
}

func RtlCreateUserThread(shellcode []byte, pid int) error {
	return sc_pkg.RtlCreateUserThread(shellcode, pid)
}

/*

Hell's Gate + Halo's Gate functions

*/

func NtCreateThreadExHalos(shellcode []byte) error {
	return sc_pkg.NtCreateThreadExHalos(shellcode)
}

func EnumSystemLocalesHalos(shellcode []byte) error {
	return sc_pkg.EnumSystemLocalesHalos(shellcode)
}


